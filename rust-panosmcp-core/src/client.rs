//! Reusable, bounded async PAN-OS XML API client.

use crate::{
    PanosMcpError, Result,
    inventory::{DeviceConfig, LoadedTlsTrust, MutationPolicy},
    xml::{
        JobStatus, PanosResponse, XmlLimits, parse_job_status, parse_panos_response,
        validate_read_only_op_command, validate_read_xpath,
    },
};
use futures_util::StreamExt;
use reqwest::{Certificate, Client, redirect::Policy};
use rustls::{
    CertificateError, DigitallySignedStruct, Error as RustlsError, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::CryptoProvider,
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use sha2::{Digest, Sha256};
use std::{fmt, sync::Arc, time::Duration};
use tokio::{sync::Semaphore, time};
use tokio_util::sync::CancellationToken;

const API_PATH: &str = "api/";
const JOB_ID_MAX_BYTES: usize = 32;

/// Pooled PAN-OS API client for exactly one validated inventory device.
#[derive(Clone)]
pub struct PanosClient {
    config: Arc<DeviceConfig>,
    client: Client,
    api_url: reqwest::Url,
    concurrency: Arc<Semaphore>,
}

impl fmt::Debug for PanosClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PanosClient")
            .field("device", &self.config.metadata.name)
            .field("api_url", &self.api_url)
            .field("max_concurrency", &self.config.max_concurrency)
            .finish_non_exhaustive()
    }
}

impl PanosClient {
    /// Construct a reusable client from a fully validated device entry.
    pub fn new(config: Arc<DeviceConfig>) -> Result<Self> {
        let client = build_http_client(&config)?;
        let api_url = config
            .endpoint
            .join(API_PATH)
            .map_err(|error| PanosMcpError::Configuration(error.to_string()))?;
        Ok(Self {
            concurrency: Arc::new(Semaphore::new(config.max_concurrency)),
            config,
            client,
            api_url,
        })
    }

    /// Safe device name.
    #[must_use]
    pub fn device_name(&self) -> &str {
        &self.config.metadata.name
    }

    /// Explicit candidate-mutation policy, if the operator enabled writes.
    #[must_use]
    pub fn mutation_policy(&self) -> Option<&MutationPolicy> {
        self.config.mutation.as_ref()
    }

    /// Canonical management endpoint used to serialize aliases of one appliance.
    #[must_use]
    pub(crate) fn mutation_lock_key(&self) -> String {
        self.config.endpoint.origin().ascii_serialization()
    }

    /// Execute a validated PAN-OS operational XML command.
    pub async fn operational(
        &self,
        command: &str,
        cancellation: CancellationToken,
    ) -> Result<PanosResponse> {
        validate_read_only_op_command(command)?;
        self.post(
            vec![("type", "op".to_owned()), ("cmd", command.to_owned())],
            cancellation,
        )
        .await
    }

    /// Read running (`show`) or candidate (`get`) configuration at an XPath.
    pub async fn configuration(
        &self,
        candidate: bool,
        xpath: &str,
        cancellation: CancellationToken,
    ) -> Result<PanosResponse> {
        validate_read_xpath(xpath)?;
        self.post(
            vec![
                ("type", "config".to_owned()),
                ("action", if candidate { "get" } else { "show" }.to_owned()),
                ("xpath", xpath.to_owned()),
            ],
            cancellation,
        )
        .await
    }

    /// Poll a PAN-OS asynchronous job with cancellation and bounded backoff.
    pub async fn poll_job(
        &self,
        job_id: &str,
        deadline: Duration,
        cancellation: CancellationToken,
    ) -> Result<JobStatus> {
        if job_id.is_empty()
            || job_id.len() > JOB_ID_MAX_BYTES
            || !job_id.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(PanosMcpError::Policy {
                field: "job_id",
                reason: "job identifier must contain only 1-32 ASCII digits".to_owned(),
            });
        }
        let command = format!("<show><jobs><id>{job_id}</id></jobs></show>");
        let operation = async {
            let mut backoff = Duration::from_millis(200);
            loop {
                let response = self.operational(&command, cancellation.clone()).await?;
                let status = parse_job_status(&response)?;
                if status.is_finished() {
                    return Ok(status);
                }
                let jitter = fastrand::u64(0..=100);
                tokio::select! {
                    () = cancellation.cancelled() => return Err(PanosMcpError::Cancelled),
                    () = time::sleep(backoff + Duration::from_millis(jitter)) => {}
                }
                backoff = (backoff * 2).min(Duration::from_secs(3));
            }
        };
        match time::timeout(deadline, operation).await {
            Ok(result) => result,
            Err(_) => Err(PanosMcpError::Timeout {
                operation: "poll_job",
            }),
        }
    }

    /// Submit already-validated fields for guarded configuration lifecycle operations.
    pub(crate) async fn post_fields(
        &self,
        fields: Vec<(&'static str, String)>,
        cancellation: CancellationToken,
    ) -> Result<PanosResponse> {
        self.post(fields, cancellation).await
    }

    async fn post(
        &self,
        mut fields: Vec<(&'static str, String)>,
        cancellation: CancellationToken,
    ) -> Result<PanosResponse> {
        if let Some(vsys) = &self.config.metadata.vsys {
            fields.push(("vsys", vsys.clone()));
        }
        let operation = async {
            let _permit = self
                .concurrency
                .acquire()
                .await
                .map_err(|_| PanosMcpError::Cancelled)?;

            let mut api_key =
                reqwest::header::HeaderValue::from_str(self.config.api_key.expose_secret())
                    .map_err(|_| {
                        PanosMcpError::Secret(
                            "PAN-OS API key is not a valid header value".to_owned(),
                        )
                    })?;
            api_key.set_sensitive(true);
            let response = self
                .client
                .post(self.api_url.clone())
                .header("X-PAN-KEY", api_key)
                .form(&fields)
                .send()
                .await
                .map_err(|error| classify_transport(error, self.device_name()))?;

            if !response.status().is_success() {
                return Err(PanosMcpError::HttpStatus {
                    device: self.device_name().to_owned(),
                    status: response.status().as_u16(),
                });
            }
            if response
                .content_length()
                .is_some_and(|length| length > self.config.max_response_bytes as u64)
            {
                return Err(PanosMcpError::ResponseTooLarge {
                    device: self.device_name().to_owned(),
                    limit: self.config.max_response_bytes,
                });
            }

            let mut bytes = Vec::new();
            let mut stream = response.bytes_stream();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(|error| classify_transport(error, self.device_name()))?;
                if bytes.len().saturating_add(chunk.len()) > self.config.max_response_bytes {
                    return Err(PanosMcpError::ResponseTooLarge {
                        device: self.device_name().to_owned(),
                        limit: self.config.max_response_bytes,
                    });
                }
                bytes.extend_from_slice(&chunk);
            }

            parse_panos_response(
                &bytes,
                XmlLimits {
                    max_bytes: self.config.max_response_bytes,
                    max_depth: 64,
                },
            )?
            .ensure_success(self.device_name())
        };

        tokio::select! {
            () = cancellation.cancelled() => Err(PanosMcpError::Cancelled),
            result = time::timeout(self.config.request_timeout, operation) => {
                match result {
                    Ok(result) => result,
                    Err(_) => Err(PanosMcpError::Timeout { operation: "panos_api" }),
                }
            }
        }
    }
}

fn build_http_client(config: &DeviceConfig) -> Result<Client> {
    let provider = rustls::crypto::ring::default_provider();
    let _ = provider.clone().install_default();
    let provider = Arc::new(provider);
    let mut builder = Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(Policy::none())
        .connect_timeout(config.connect_timeout)
        .pool_idle_timeout(Duration::from_secs(300))
        .pool_max_idle_per_host(config.max_concurrency)
        .http1_only()
        .tls_version_min(reqwest::tls::Version::TLS_1_2);

    match &config.tls {
        LoadedTlsTrust::System => {}
        LoadedTlsTrust::CustomCa { pem, .. } => {
            let certificates =
                Certificate::from_pem_bundle(pem).map_err(|_| PanosMcpError::Tls {
                    device: config.metadata.name.clone(),
                    reason: "custom CA bundle is not valid PEM certificate data".to_owned(),
                })?;
            if certificates.is_empty() {
                return Err(PanosMcpError::Tls {
                    device: config.metadata.name.clone(),
                    reason: "custom CA bundle contains no certificates".to_owned(),
                });
            }
            builder = builder.tls_certs_only(certificates);
        }
        LoadedTlsTrust::LeafSha256(expected) => {
            let verifier = Arc::new(LeafPinVerifier {
                expected: *expected,
                provider: provider.clone(),
            });
            let mut tls = rustls::ClientConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
                .map_err(|error| PanosMcpError::Tls {
                    device: config.metadata.name.clone(),
                    reason: format!("failed to enable TLS 1.2/1.3: {error}"),
                })?
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_no_client_auth();
            tls.alpn_protocols = vec![b"http/1.1".to_vec()];
            builder = builder.tls_backend_preconfigured(tls);
        }
    }

    builder.build().map_err(|error| PanosMcpError::Tls {
        device: config.metadata.name.clone(),
        reason: sanitized_reqwest_reason(&error).to_owned(),
    })
}

#[derive(Debug)]
struct LeafPinVerifier {
    expected: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for LeafPinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, RustlsError> {
        let actual: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
        if actual == self.expected {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(RustlsError::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            signature,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            signature,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn classify_transport(error: reqwest::Error, device: &str) -> PanosMcpError {
    if error.is_timeout() {
        return PanosMcpError::Timeout {
            operation: "panos_api",
        };
    }
    PanosMcpError::Transport {
        device: device.to_owned(),
        reason: sanitized_reqwest_reason(&error).to_owned(),
    }
}

fn sanitized_reqwest_reason(error: &reqwest::Error) -> &'static str {
    if error.is_connect() {
        "connection or TLS handshake failed"
    } else if error.is_body() || error.is_decode() {
        "response body transfer failed"
    } else if error.is_builder() {
        "request construction failed"
    } else if error.is_request() {
        "request transmission failed"
    } else {
        "HTTP client failure"
    }
}
