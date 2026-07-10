//! Secure PEM loading for the Streamable HTTP listener.

use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
};
use zeroize::Zeroizing;

const MAX_CERT_BYTES: u64 = 1024 * 1024;
const MAX_KEY_BYTES: u64 = 128 * 1024;

/// Listener TLS configuration failure.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    /// File read or metadata error.
    #[error("TLS file I/O at '{}': {error}", path.display())]
    Io {
        /// Affected path.
        path: PathBuf,
        /// Underlying filesystem error.
        #[source]
        error: std::io::Error,
    },
    /// Unsafe filesystem metadata.
    #[error("unsafe TLS file '{}': {message}", path.display())]
    UnsafeFile {
        /// Affected path.
        path: PathBuf,
        /// Safe diagnostic.
        message: String,
    },
    /// PEM or certificate/key mismatch.
    #[error("invalid TLS configuration: {0}")]
    Invalid(String),
}

/// Load a certificate chain and private key into a TLS 1.2+ rustls server.
pub fn load(cert_path: &Path, key_path: &Path) -> Result<Arc<rustls::ServerConfig>, TlsError> {
    let cert_bytes = read_regular(cert_path, MAX_CERT_BYTES, false)?;
    let key_bytes = Zeroizing::new(read_regular(key_path, MAX_KEY_BYTES, true)?);
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&cert_bytes)
        .collect::<Result<_, _>>()
        .map_err(|error| TlsError::Invalid(format!("certificate PEM: {error}")))?;
    if certs.is_empty() {
        return Err(TlsError::Invalid(
            "certificate PEM contains no certificates".to_owned(),
        ));
    }
    let key = PrivateKeyDer::from_pem_slice(&key_bytes)
        .map_err(|error| TlsError::Invalid(format!("private-key PEM: {error}")))?;
    let provider = rustls::crypto::ring::default_provider();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|error| TlsError::Invalid(format!("TLS versions: {error}")))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|error| TlsError::Invalid(format!("certificate/key: {error}")))?;
    Ok(Arc::new(config))
}

fn read_regular(path: &Path, maximum: u64, private: bool) -> Result<Vec<u8>, TlsError> {
    #[cfg(unix)]
    let file = {
        let descriptor = rustix::fs::open(
            path,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        )
        .map_err(|error| io_error(path, error.into()))?;
        fs::File::from(descriptor)
    };
    #[cfg(not(unix))]
    let file = fs::File::open(path).map_err(|error| io_error(path, error))?;

    let metadata = file.metadata().map_err(|error| io_error(path, error))?;
    if !metadata.is_file() || metadata.len() > maximum {
        return Err(TlsError::UnsafeFile {
            path: path.to_path_buf(),
            message: format!("must be a regular file no larger than {maximum} bytes"),
        });
    }
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::MetadataExt;
        let mode = metadata.mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(TlsError::UnsafeFile {
                path: path.to_path_buf(),
                message: format!("private key mode {mode:04o} permits group/other access"),
            });
        }
        let owner = metadata.uid();
        let effective = rustix::process::geteuid().as_raw();
        if owner != effective && owner != 0 {
            return Err(TlsError::UnsafeFile {
                path: path.to_path_buf(),
                message: format!(
                    "private key owner uid {owner} is neither effective uid {effective} nor root"
                ),
            });
        }
    }
    let mut bytes = Vec::with_capacity((metadata.len() as usize).min(maximum as usize));
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| io_error(path, error))?;
    if bytes.len() as u64 > maximum {
        return Err(TlsError::UnsafeFile {
            path: path.to_path_buf(),
            message: format!("file exceeds {maximum} bytes"),
        });
    }
    Ok(bytes)
}

fn io_error(path: &Path, error: std::io::Error) -> TlsError {
    TlsError::Io {
        path: path.to_path_buf(),
        error,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_matching_self_signed_pair() {
        let issued =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("self signed");
        let directory = tempfile::tempdir().expect("tempdir");
        let cert = directory.path().join("cert.pem");
        let key = directory.path().join("key.pem");
        fs::write(&cert, issued.cert.pem()).expect("cert");
        fs::write(&key, issued.signing_key.serialize_pem()).expect("key");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).expect("mode");
        }
        load(&cert, &key).expect("TLS config");
    }

    #[cfg(unix)]
    #[test]
    fn refuses_world_readable_private_key() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().expect("tempdir");
        let cert = directory.path().join("cert.pem");
        let key = directory.path().join("key.pem");
        fs::write(&cert, "no certificate").expect("cert");
        fs::write(&key, "no key").expect("key");
        fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).expect("mode");
        assert!(matches!(
            load(&cert, &key),
            Err(TlsError::UnsafeFile { .. })
        ));
    }
}
