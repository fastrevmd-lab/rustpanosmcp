//! Validated device inventory and secret-provider loading.

use crate::{PanosMcpError, Result};
use rust_panosmcp_auth::SecretString;
use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs,
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use url::Url;

const INVENTORY_VERSION: u32 = 1;
const MAX_INVENTORY_BYTES: u64 = 1024 * 1024;
const MAX_SECRET_BYTES: u64 = 16 * 1024;
const MAX_CA_BUNDLE_BYTES: u64 = 1024 * 1024;
const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 10;
const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 30;
const DEFAULT_MAX_CONCURRENCY: usize = 4;
const DEFAULT_MAX_RESPONSE_BYTES: usize = 5 * 1024 * 1024;
const MAX_DEVICE_CONCURRENCY: usize = 5;
const MAX_DEVICE_NAME_BYTES: usize = 64;
const MAX_DEVICES: usize = 256;
const MAX_TAGS_PER_DEVICE: usize = 32;

/// Source used to resolve environment-backed secrets.
pub trait Environment: Send + Sync {
    /// Return the exact value of an environment variable when it exists.
    fn variable(&self, name: &str) -> Option<String>;
}

/// Production environment resolver.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProcessEnvironment;

impl Environment for ProcessEnvironment {
    fn variable(&self, name: &str) -> Option<String> {
        std::env::var(name).ok()
    }
}

/// Non-secret metadata safe to return from `list_devices`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, schemars::JsonSchema)]
pub struct DeviceMetadata {
    /// Stable inventory name used by all MCP calls.
    pub name: String,
    /// Configured HTTPS management endpoint.
    pub endpoint: String,
    /// Optional virtual-system identifier.
    pub vsys: Option<String>,
    /// Operator-provided classification tags.
    pub tags: Vec<String>,
}

/// TLS trust material loaded and validated with the inventory.
#[derive(Clone)]
pub enum LoadedTlsTrust {
    /// Use platform trust roots and normal hostname validation.
    System,
    /// Trust only the PEM certificates loaded from this inventory entry.
    CustomCa {
        /// Original operator path, used only for diagnostics.
        source: PathBuf,
        /// Validated PEM bundle bytes.
        pem: Arc<[u8]>,
    },
    /// Trust an exact SHA-256 fingerprint of the presented leaf certificate.
    LeafSha256([u8; 32]),
}

impl fmt::Debug for LoadedTlsTrust {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::System => formatter.write_str("System"),
            Self::CustomCa { source, .. } => formatter
                .debug_struct("CustomCa")
                .field("source", source)
                .field("pem", &"[CERTIFICATE DATA]")
                .finish(),
            Self::LeafSha256(_) => formatter.write_str("LeafSha256([FINGERPRINT])"),
        }
    }
}

/// Fully loaded device entry used to build a pooled API client.
#[derive(Clone)]
pub struct DeviceConfig {
    /// Safe public metadata.
    pub metadata: DeviceMetadata,
    /// Parsed base endpoint with no path/query/credentials.
    pub endpoint: Url,
    /// Resolved PAN-OS API credential.
    pub api_key: Arc<SecretString>,
    /// Strict TLS trust strategy.
    pub tls: LoadedTlsTrust,
    /// TCP/TLS connect deadline.
    pub connect_timeout: Duration,
    /// Whole request deadline, including response body.
    pub request_timeout: Duration,
    /// Maximum in-flight API calls for this device.
    pub max_concurrency: usize,
    /// Hard cap applied while streaming a PAN-OS response.
    pub max_response_bytes: usize,
}

impl fmt::Debug for DeviceConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeviceConfig")
            .field("metadata", &self.metadata)
            .field("endpoint", &self.endpoint)
            .field("api_key", &self.api_key)
            .field("tls", &self.tls)
            .field("connect_timeout", &self.connect_timeout)
            .field("request_timeout", &self.request_timeout)
            .field("max_concurrency", &self.max_concurrency)
            .field("max_response_bytes", &self.max_response_bytes)
            .finish()
    }
}

/// Immutable, name-indexed validated inventory.
#[derive(Debug, Clone)]
pub struct Inventory {
    source: PathBuf,
    devices: BTreeMap<String, Arc<DeviceConfig>>,
}

impl Inventory {
    /// Load an inventory using the process environment for environment-backed
    /// API keys.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        Self::load_with_environment(path, &ProcessEnvironment)
    }

    /// Load an inventory with an injectable environment resolver.
    pub fn load_with_environment(
        path: impl AsRef<Path>,
        environment: &dyn Environment,
    ) -> Result<Self> {
        let path = path.as_ref();
        let bytes = read_validated_file(path, FilePurpose::Inventory)?;
        let parsed: InventoryFile = serde_json::from_slice(&bytes).map_err(|error| {
            PanosMcpError::Inventory(format!("invalid JSON in '{}': {error}", path.display()))
        })?;
        if parsed.version != INVENTORY_VERSION {
            return Err(PanosMcpError::Inventory(format!(
                "unsupported inventory version {}; expected {INVENTORY_VERSION}",
                parsed.version
            )));
        }
        if parsed.devices.is_empty() {
            return Err(PanosMcpError::Inventory(
                "inventory must contain at least one device".to_owned(),
            ));
        }
        if parsed.devices.len() > MAX_DEVICES {
            return Err(PanosMcpError::Inventory(format!(
                "inventory contains more than {MAX_DEVICES} devices"
            )));
        }

        let mut devices = BTreeMap::new();
        for raw in parsed.devices {
            let loaded = Arc::new(load_device(raw, environment)?);
            if devices
                .insert(loaded.metadata.name.clone(), loaded.clone())
                .is_some()
            {
                return Err(PanosMcpError::Inventory(format!(
                    "duplicate device name '{}'",
                    loaded.metadata.name
                )));
            }
        }

        Ok(Self {
            source: path.to_path_buf(),
            devices,
        })
    }

    /// Source inventory path.
    #[must_use]
    pub fn source(&self) -> &Path {
        &self.source
    }

    /// Resolve only an exact configured device name.
    pub fn device(&self, name: &str) -> Result<Arc<DeviceConfig>> {
        self.devices
            .get(name)
            .cloned()
            .ok_or_else(|| PanosMcpError::UnknownDevice(name.to_owned()))
    }

    /// Safe metadata in stable name order.
    #[must_use]
    pub fn metadata(&self) -> Vec<DeviceMetadata> {
        self.devices
            .values()
            .map(|device| device.metadata.clone())
            .collect()
    }

    /// Iterate the validated device entries in stable name order.
    pub(crate) fn entries(&self) -> impl Iterator<Item = Arc<DeviceConfig>> + '_ {
        self.devices.values().cloned()
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InventoryFile {
    version: u32,
    devices: Vec<RawDevice>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDevice {
    name: String,
    endpoint: String,
    #[serde(default)]
    vsys: Option<String>,
    api_key: ApiKeySource,
    #[serde(default)]
    tls: TlsTrust,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default = "default_connect_timeout_secs")]
    connect_timeout_secs: u64,
    #[serde(default = "default_request_timeout_secs")]
    request_timeout_secs: u64,
    #[serde(default = "default_max_concurrency")]
    max_concurrency: usize,
    #[serde(default = "default_max_response_bytes")]
    max_response_bytes: usize,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum ApiKeySource {
    Env { name: String },
    File { path: PathBuf },
}

#[derive(Debug, Default, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum TlsTrust {
    #[default]
    System,
    CustomCa {
        path: PathBuf,
    },
    LeafSha256 {
        fingerprint: String,
    },
}

#[derive(Debug, Clone, Copy)]
enum FilePurpose {
    Inventory,
    Secret,
    CaBundle,
}

impl FilePurpose {
    const fn label(self) -> &'static str {
        match self {
            Self::Inventory => "inventory",
            Self::Secret => "secret",
            Self::CaBundle => "CA bundle",
        }
    }

    const fn max_bytes(self) -> u64 {
        match self {
            Self::Inventory => MAX_INVENTORY_BYTES,
            Self::Secret => MAX_SECRET_BYTES,
            Self::CaBundle => MAX_CA_BUNDLE_BYTES,
        }
    }
}

fn load_device(raw: RawDevice, environment: &dyn Environment) -> Result<DeviceConfig> {
    validate_identifier("device name", &raw.name, MAX_DEVICE_NAME_BYTES)?;
    if let Some(vsys) = &raw.vsys {
        validate_identifier("vsys", vsys, MAX_DEVICE_NAME_BYTES)?;
    }

    let endpoint = validate_endpoint(&raw.endpoint)?;
    let api_key = Arc::new(SecretString::new(load_api_key(&raw.api_key, environment)?));
    let tls = load_tls(raw.tls)?;

    if !(1..=MAX_DEVICE_CONCURRENCY).contains(&raw.max_concurrency) {
        return Err(PanosMcpError::Inventory(format!(
            "device '{}' max_concurrency must be between 1 and {MAX_DEVICE_CONCURRENCY}",
            raw.name
        )));
    }
    if !(1..=300).contains(&raw.connect_timeout_secs) {
        return Err(PanosMcpError::Inventory(format!(
            "device '{}' connect_timeout_secs must be between 1 and 300",
            raw.name
        )));
    }
    if !(1..=3600).contains(&raw.request_timeout_secs) {
        return Err(PanosMcpError::Inventory(format!(
            "device '{}' request_timeout_secs must be between 1 and 3600",
            raw.name
        )));
    }
    if !(1024..=DEFAULT_MAX_RESPONSE_BYTES).contains(&raw.max_response_bytes) {
        return Err(PanosMcpError::Inventory(format!(
            "device '{}' max_response_bytes must be between 1024 and {DEFAULT_MAX_RESPONSE_BYTES}",
            raw.name
        )));
    }

    let mut seen_tags = BTreeSet::new();
    if raw.tags.len() > MAX_TAGS_PER_DEVICE {
        return Err(PanosMcpError::Inventory(format!(
            "device '{}' contains more than {MAX_TAGS_PER_DEVICE} tags",
            raw.name
        )));
    }
    let mut tags = Vec::with_capacity(raw.tags.len());
    for tag in raw.tags {
        validate_identifier("tag", &tag, MAX_DEVICE_NAME_BYTES)?;
        if seen_tags.insert(tag.clone()) {
            tags.push(tag);
        }
    }

    Ok(DeviceConfig {
        metadata: DeviceMetadata {
            name: raw.name,
            endpoint: endpoint.as_str().trim_end_matches('/').to_owned(),
            vsys: raw.vsys,
            tags,
        },
        endpoint,
        api_key,
        tls,
        connect_timeout: Duration::from_secs(raw.connect_timeout_secs),
        request_timeout: Duration::from_secs(raw.request_timeout_secs),
        max_concurrency: raw.max_concurrency,
        max_response_bytes: raw.max_response_bytes,
    })
}

fn validate_endpoint(raw: &str) -> Result<Url> {
    let mut endpoint = Url::parse(raw)
        .map_err(|error| PanosMcpError::Inventory(format!("invalid endpoint URL: {error}")))?;
    if endpoint.scheme() != "https" {
        return Err(PanosMcpError::Inventory(
            "device endpoint must use https".to_owned(),
        ));
    }
    if endpoint.host_str().is_none() {
        return Err(PanosMcpError::Inventory(
            "device endpoint must include a host".to_owned(),
        ));
    }
    if !endpoint.username().is_empty() || endpoint.password().is_some() {
        return Err(PanosMcpError::Inventory(
            "device endpoint must not include credentials".to_owned(),
        ));
    }
    if endpoint.query().is_some() || endpoint.fragment().is_some() {
        return Err(PanosMcpError::Inventory(
            "device endpoint must not include a query or fragment".to_owned(),
        ));
    }
    if endpoint.path() != "/" && !endpoint.path().is_empty() {
        return Err(PanosMcpError::Inventory(
            "device endpoint must not include a path".to_owned(),
        ));
    }
    endpoint.set_path("/");
    Ok(endpoint)
}

fn load_api_key(source: &ApiKeySource, environment: &dyn Environment) -> Result<String> {
    let value = match source {
        ApiKeySource::Env { name } => {
            validate_environment_name(name)?;
            environment.variable(name).ok_or_else(|| {
                PanosMcpError::Secret(format!("environment variable '{name}' is not set"))
            })?
        }
        ApiKeySource::File { path } => {
            if !path.is_absolute() {
                return Err(PanosMcpError::Secret(
                    "API-key file path must be absolute".to_owned(),
                ));
            }
            let bytes = read_validated_file(path, FilePurpose::Secret)?;
            String::from_utf8(bytes).map_err(|_| {
                PanosMcpError::Secret("PAN-OS API-key file is not valid UTF-8".to_owned())
            })?
        }
    };

    let trimmed = value.trim_matches(|character: char| character.is_ascii_whitespace());
    if trimmed.is_empty() || trimmed.len() > MAX_SECRET_BYTES as usize {
        return Err(PanosMcpError::Secret(
            "PAN-OS API key has an invalid length".to_owned(),
        ));
    }
    if !trimmed
        .bytes()
        .all(|byte| byte.is_ascii() && !byte.is_ascii_control() && !byte.is_ascii_whitespace())
    {
        return Err(PanosMcpError::Secret(
            "PAN-OS API key contains invalid characters".to_owned(),
        ));
    }
    Ok(trimmed.to_owned())
}

fn load_tls(raw: TlsTrust) -> Result<LoadedTlsTrust> {
    match raw {
        TlsTrust::System => Ok(LoadedTlsTrust::System),
        TlsTrust::CustomCa { path } => {
            if !path.is_absolute() {
                return Err(PanosMcpError::Inventory(
                    "custom CA path must be absolute".to_owned(),
                ));
            }
            let pem = read_validated_file(&path, FilePurpose::CaBundle)?;
            Ok(LoadedTlsTrust::CustomCa {
                source: path,
                pem: pem.into(),
            })
        }
        TlsTrust::LeafSha256 { fingerprint } => {
            Ok(LoadedTlsTrust::LeafSha256(parse_sha256(&fingerprint)?))
        }
    }
}

fn validate_identifier(field: &'static str, value: &str, max_bytes: usize) -> Result<()> {
    if value.is_empty() || value.len() > max_bytes {
        return Err(PanosMcpError::Inventory(format!(
            "{field} must contain between 1 and {max_bytes} bytes"
        )));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(PanosMcpError::Inventory(format!(
            "{field} may contain only ASCII letters, digits, '.', '_' and '-'"
        )));
    }
    Ok(())
}

fn validate_environment_name(name: &str) -> Result<()> {
    let mut bytes = name.bytes();
    let Some(first) = bytes.next() else {
        return Err(PanosMcpError::Secret(
            "environment variable name is empty".to_owned(),
        ));
    };
    if !(first == b'_' || first.is_ascii_uppercase())
        || !bytes.all(|byte| byte == b'_' || byte.is_ascii_uppercase() || byte.is_ascii_digit())
    {
        return Err(PanosMcpError::Secret(
            "environment variable name must match [A-Z_][A-Z0-9_]*".to_owned(),
        ));
    }
    Ok(())
}

fn parse_sha256(raw: &str) -> Result<[u8; 32]> {
    let raw = raw.strip_prefix("sha256:").unwrap_or(raw);
    if raw.len() != 64 || !raw.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(PanosMcpError::Inventory(
            "leaf SHA-256 fingerprint must contain exactly 64 hexadecimal characters".to_owned(),
        ));
    }
    let mut digest = [0_u8; 32];
    for (index, chunk) in raw.as_bytes().chunks_exact(2).enumerate() {
        digest[index] = (hex_nibble(chunk[0]) << 4) | hex_nibble(chunk[1]);
    }
    Ok(digest)
}

const fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => 0,
    }
}

fn read_validated_file(path: &Path, purpose: FilePurpose) -> Result<Vec<u8>> {
    #[cfg(unix)]
    let file = {
        let descriptor = rustix::fs::open(
            path,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        )
        .map_err(|error| PanosMcpError::FileIo {
            purpose: purpose.label(),
            path: path.to_path_buf(),
            error: error.into(),
        })?;
        fs::File::from(descriptor)
    };
    #[cfg(not(unix))]
    let file = {
        let link_metadata = fs::symlink_metadata(path).map_err(|error| PanosMcpError::FileIo {
            purpose: purpose.label(),
            path: path.to_path_buf(),
            error,
        })?;
        if link_metadata.file_type().is_symlink() {
            return Err(PanosMcpError::FileSecurity {
                purpose: purpose.label(),
                path: path.to_path_buf(),
                reason: "symbolic links are forbidden".to_owned(),
            });
        }
        fs::File::open(path).map_err(|error| PanosMcpError::FileIo {
            purpose: purpose.label(),
            path: path.to_path_buf(),
            error,
        })?
    };
    let metadata = file.metadata().map_err(|error| PanosMcpError::FileIo {
        purpose: purpose.label(),
        path: path.to_path_buf(),
        error,
    })?;
    if !metadata.is_file() {
        return Err(PanosMcpError::FileSecurity {
            purpose: purpose.label(),
            path: path.to_path_buf(),
            reason: "must be a regular file".to_owned(),
        });
    }
    if metadata.len() > purpose.max_bytes() {
        return Err(PanosMcpError::FileSecurity {
            purpose: purpose.label(),
            path: path.to_path_buf(),
            reason: format!("exceeds the {}-byte limit", purpose.max_bytes()),
        });
    }

    #[cfg(unix)]
    validate_unix_file_security(path, &metadata, purpose)?;

    let mut bytes = Vec::with_capacity((metadata.len() as usize).min(purpose.max_bytes() as usize));
    file.take(purpose.max_bytes() + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| PanosMcpError::FileIo {
            purpose: purpose.label(),
            path: path.to_path_buf(),
            error,
        })?;
    if bytes.len() as u64 > purpose.max_bytes() {
        return Err(PanosMcpError::FileSecurity {
            purpose: purpose.label(),
            path: path.to_path_buf(),
            reason: format!("exceeds the {}-byte limit", purpose.max_bytes()),
        });
    }
    Ok(bytes)
}

#[cfg(unix)]
fn validate_unix_file_security(
    path: &Path,
    metadata: &fs::Metadata,
    purpose: FilePurpose,
) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    let mode = metadata.mode() & 0o777;
    let forbidden = match purpose {
        FilePurpose::Secret => 0o077,
        FilePurpose::Inventory | FilePurpose::CaBundle => 0o022,
    };
    if mode & forbidden != 0 {
        return Err(PanosMcpError::FileSecurity {
            purpose: purpose.label(),
            path: path.to_path_buf(),
            reason: format!("mode {mode:04o} is too permissive"),
        });
    }

    let owner = metadata.uid();
    let effective = rustix::process::geteuid().as_raw();
    if owner != effective && owner != 0 {
        return Err(PanosMcpError::FileSecurity {
            purpose: purpose.label(),
            path: path.to_path_buf(),
            reason: format!("owner uid {owner} is neither the effective uid {effective} nor root"),
        });
    }
    Ok(())
}

const fn default_connect_timeout_secs() -> u64 {
    DEFAULT_CONNECT_TIMEOUT_SECS
}

const fn default_request_timeout_secs() -> u64 {
    DEFAULT_REQUEST_TIMEOUT_SECS
}

const fn default_max_concurrency() -> usize {
    DEFAULT_MAX_CONCURRENCY
}

const fn default_max_response_bytes() -> usize {
    DEFAULT_MAX_RESPONSE_BYTES
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[derive(Default)]
    struct TestEnvironment(HashMap<String, String>);

    impl Environment for TestEnvironment {
        fn variable(&self, name: &str) -> Option<String> {
            self.0.get(name).cloned()
        }
    }

    fn write_inventory(directory: &Path, json: &str) -> PathBuf {
        let path = directory.join("devices.json");
        fs::write(&path, json).expect("write inventory");
        path
    }

    fn environment() -> TestEnvironment {
        TestEnvironment(HashMap::from([(
            "PANOS_TEST_KEY".to_owned(),
            "test-api-key-value".to_owned(),
        )]))
    }

    #[test]
    fn loads_valid_environment_backed_inventory() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = write_inventory(
            directory.path(),
            r#"{
                "version": 1,
                "devices": [{
                    "name": "lab-fw-01",
                    "endpoint": "https://fw.example.test:4443",
                    "api_key": {"type": "env", "name": "PANOS_TEST_KEY"},
                    "tags": ["lab", "lab"]
                }]
            }"#,
        );

        let inventory =
            Inventory::load_with_environment(path, &environment()).expect("valid inventory");
        let device = inventory.device("lab-fw-01").expect("known device");
        assert_eq!(device.metadata.endpoint, "https://fw.example.test:4443");
        assert_eq!(device.metadata.tags, ["lab"]);
        assert_eq!(device.max_concurrency, 4);
        assert_eq!(device.api_key.expose_secret(), "test-api-key-value");
        assert!(!format!("{device:?}").contains("test-api-key-value"));
    }

    #[test]
    fn rejects_plaintext_api_key_field() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = write_inventory(
            directory.path(),
            r#"{
                "version": 1,
                "devices": [{
                    "name": "fw",
                    "endpoint": "https://fw.example.test",
                    "api_key": {"type": "env", "name": "PANOS_TEST_KEY", "value": "secret"}
                }]
            }"#,
        );
        let error = Inventory::load_with_environment(path, &environment())
            .expect_err("unknown plaintext field must be refused");
        assert!(error.to_string().contains("unknown field"));
        assert!(!error.to_string().contains("test-api-key-value"));
    }

    #[test]
    fn rejects_non_https_and_endpoint_paths() {
        for endpoint in ["http://fw.example.test", "https://fw.example.test/api"] {
            let directory = tempfile::tempdir().expect("tempdir");
            let path = write_inventory(
                directory.path(),
                &format!(
                    r#"{{"version":1,"devices":[{{"name":"fw","endpoint":"{endpoint}","api_key":{{"type":"env","name":"PANOS_TEST_KEY"}}}}]}}"#
                ),
            );
            assert!(Inventory::load_with_environment(path, &environment()).is_err());
        }
    }

    #[test]
    fn rejects_duplicate_names_and_excessive_concurrency() {
        let directory = tempfile::tempdir().expect("tempdir");
        let duplicate = write_inventory(
            directory.path(),
            r#"{"version":1,"devices":[
                {"name":"fw","endpoint":"https://one.test","api_key":{"type":"env","name":"PANOS_TEST_KEY"}},
                {"name":"fw","endpoint":"https://two.test","api_key":{"type":"env","name":"PANOS_TEST_KEY"}}
            ]}"#,
        );
        assert!(Inventory::load_with_environment(duplicate, &environment()).is_err());

        let too_many = write_inventory(
            directory.path(),
            r#"{"version":1,"devices":[
                {"name":"fw","endpoint":"https://one.test","api_key":{"type":"env","name":"PANOS_TEST_KEY"},"max_concurrency":6}
            ]}"#,
        );
        assert!(Inventory::load_with_environment(too_many, &environment()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn secret_file_requires_private_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().expect("tempdir");
        let secret = directory.path().join("api-key");
        fs::write(&secret, "file-backed-api-key").expect("write secret");
        fs::set_permissions(&secret, fs::Permissions::from_mode(0o644)).expect("chmod");
        let path = write_inventory(
            directory.path(),
            &format!(
                r#"{{"version":1,"devices":[{{"name":"fw","endpoint":"https://one.test","api_key":{{"type":"file","path":"{}"}}}}]}}"#,
                secret.display()
            ),
        );
        let error = Inventory::load_with_environment(&path, &environment())
            .expect_err("world-readable secret must be refused");
        assert!(error.to_string().contains("too permissive"));

        fs::set_permissions(&secret, fs::Permissions::from_mode(0o600)).expect("chmod");
        let inventory =
            Inventory::load_with_environment(path, &environment()).expect("private secret");
        assert_eq!(
            inventory
                .device("fw")
                .expect("device")
                .api_key
                .expose_secret(),
            "file-backed-api-key"
        );
    }

    #[test]
    fn parses_prefixed_leaf_fingerprint() {
        let digest = parse_sha256(&format!("sha256:{}", "a5".repeat(32))).expect("fingerprint");
        assert!(digest.iter().all(|byte| *byte == 0xa5));
        assert!(parse_sha256("short").is_err());
    }
}
