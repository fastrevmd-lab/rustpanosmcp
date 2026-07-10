//! Secure, validated, atomically replaced token-store persistence.

use crate::{
    KNOWN_TOOLS,
    store::{MutationGrant, ScopeSet, TokenEntry, TokenStore},
    token::{TokenError, TokenSecret},
};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

const STORE_VERSION: u32 = 2;
const MAX_STORE_BYTES: u64 = 1024 * 1024;

/// Token-store read, validation, or persistence failure.
#[derive(Debug, thiserror::Error)]
pub enum TokenStoreFileError {
    /// Schema or semantic failure.
    #[error("token store invalid: {0}")]
    Invalid(String),
    /// Filesystem failure with the affected path.
    #[error("token store I/O at '{}': {error}", path.display())]
    Io {
        /// Affected operator path.
        path: PathBuf,
        /// Underlying error.
        #[source]
        error: std::io::Error,
    },
    /// JSON decoding or encoding failure.
    #[error("token store JSON error: {0}")]
    Json(#[from] serde_json::Error),
    /// CSPRNG or digest failure.
    #[error(transparent)]
    Token(#[from] TokenError),
}

impl From<crate::store::StoreError> for TokenStoreFileError {
    fn from(error: crate::store::StoreError) -> Self {
        Self::Invalid(error.to_string())
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OnDiskStore {
    version: u32,
    #[serde(default)]
    tokens: Vec<TokenEntry>,
}

/// Token-store filesystem operations.
pub struct TokenStoreFile;

impl TokenStoreFile {
    /// Load a complete store and validate all device/tool references.
    pub fn load(path: &Path, known_devices: &[String]) -> Result<TokenStore, TokenStoreFileError> {
        require_absolute(path)?;
        let bytes = read_private_file(path)?;
        Self::parse(&bytes, known_devices)
    }

    /// Parse and validate a bounded digest-only store without filesystem access.
    ///
    /// This is also the pure parser entry point used by the token-store fuzz
    /// target. Production callers normally use [`Self::load`] so ownership and
    /// permission checks are enforced before parsing.
    pub fn parse(
        bytes: &[u8],
        known_devices: &[String],
    ) -> Result<TokenStore, TokenStoreFileError> {
        if bytes.len() as u64 > MAX_STORE_BYTES {
            return Err(TokenStoreFileError::Invalid(format!(
                "token store exceeds {MAX_STORE_BYTES} bytes"
            )));
        }
        let on_disk: OnDiskStore = serde_json::from_slice(bytes)?;
        if !matches!(on_disk.version, 1 | STORE_VERSION) {
            return Err(TokenStoreFileError::Invalid(format!(
                "unsupported version {}; expected {STORE_VERSION}",
                on_disk.version
            )));
        }
        let store = TokenStore::new(on_disk.tokens)?;
        validate_references(&store, known_devices)?;
        Ok(store)
    }

    /// Atomically save digest-only metadata with private permissions.
    pub fn save(path: &Path, store: &TokenStore) -> Result<(), TokenStoreFileError> {
        require_absolute(path)?;
        let parent = path.parent().ok_or_else(|| {
            TokenStoreFileError::Invalid("token path has no parent directory".to_owned())
        })?;
        let metadata = existing_metadata(path)?;
        let payload = serde_json::to_vec_pretty(&OnDiskStore {
            version: STORE_VERSION,
            tokens: store.entries().to_vec(),
        })?;
        if payload.len() as u64 > MAX_STORE_BYTES {
            return Err(TokenStoreFileError::Invalid(format!(
                "serialized store exceeds {MAX_STORE_BYTES} bytes"
            )));
        }

        let mut temporary = tempfile::Builder::new()
            .prefix(".rust-panosmcp-tokens-")
            .suffix(".tmp")
            .tempfile_in(parent)
            .map_err(|error| io_error(parent, error))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            temporary
                .as_file()
                .set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|error| io_error(temporary.path(), error))?;
            if let Some(metadata) = &metadata {
                fs::set_permissions(
                    temporary.path(),
                    fs::Permissions::from_mode(metadata.mode & 0o600),
                )
                .map_err(|error| io_error(temporary.path(), error))?;
                if let Err(error) = std::os::unix::fs::chown(
                    temporary.path(),
                    Some(metadata.uid),
                    Some(metadata.gid),
                ) {
                    tracing::warn!(
                        path = %temporary.path().display(),
                        %error,
                        "could not preserve token-store ownership"
                    );
                }
            }
        }
        temporary
            .write_all(&payload)
            .map_err(|error| io_error(temporary.path(), error))?;
        temporary
            .as_file()
            .sync_all()
            .map_err(|error| io_error(temporary.path(), error))?;
        temporary
            .persist(path)
            .map_err(|error| io_error(path, error.error))?;
        sync_directory(parent)?;
        Ok(())
    }

    /// Add one scoped token and return its one-time plaintext.
    pub fn add(
        path: &Path,
        name: &str,
        devices: ScopeSet,
        tools: ScopeSet,
        known_devices: &[String],
    ) -> Result<TokenSecret, TokenStoreFileError> {
        Self::add_with_options(path, name, devices, tools, None, None, known_devices)
    }

    /// Add one token with optional v0.2 expiry and mutation authority.
    pub fn add_with_options(
        path: &Path,
        name: &str,
        devices: ScopeSet,
        tools: ScopeSet,
        expires_at_unix: Option<u64>,
        mutation: Option<MutationGrant>,
        known_devices: &[String],
    ) -> Result<TokenSecret, TokenStoreFileError> {
        let current = if path.exists() {
            Self::load(path, known_devices)?
        } else {
            TokenStore::default()
        };
        if current.entries().iter().any(|entry| entry.name == name) {
            return Err(TokenStoreFileError::Invalid(format!(
                "token '{name}' already exists"
            )));
        }
        let (secret, digest) = TokenSecret::mint()?;
        let mut entries = current.entries().to_vec();
        entries.push(TokenEntry {
            name: name.to_owned(),
            digest,
            devices,
            tools,
            created_at_unix: now_unix()?,
            expires_at_unix,
            mutation,
        });
        let updated = TokenStore::new(entries)?;
        validate_references(&updated, known_devices)?;
        Self::save(path, &updated)?;
        Ok(secret)
    }

    /// Idempotently revoke one named token.
    pub fn revoke(
        path: &Path,
        name: &str,
        known_devices: &[String],
    ) -> Result<bool, TokenStoreFileError> {
        let current = Self::load(path, known_devices)?;
        let mut entries = current.entries().to_vec();
        let before = entries.len();
        entries.retain(|entry| entry.name != name);
        let removed = before != entries.len();
        if removed {
            Self::save(path, &TokenStore::new(entries)?)?;
        }
        Ok(removed)
    }

    /// Atomically replace one token digest while preserving its scopes.
    pub fn rotate(
        path: &Path,
        name: &str,
        known_devices: &[String],
    ) -> Result<TokenSecret, TokenStoreFileError> {
        let current = Self::load(path, known_devices)?;
        if !current.entries().iter().any(|entry| entry.name == name) {
            return Err(TokenStoreFileError::Invalid(format!(
                "token '{name}' does not exist"
            )));
        }
        let (secret, digest) = TokenSecret::mint()?;
        let created_at_unix = now_unix()?;
        let entries = current
            .entries()
            .iter()
            .map(|entry| {
                if entry.name == name {
                    TokenEntry {
                        name: entry.name.clone(),
                        digest: digest.clone(),
                        devices: entry.devices.clone(),
                        tools: entry.tools.clone(),
                        created_at_unix,
                        expires_at_unix: entry.expires_at_unix,
                        mutation: entry.mutation.clone(),
                    }
                } else {
                    entry.clone()
                }
            })
            .collect();
        Self::save(path, &TokenStore::new(entries)?)?;
        Ok(secret)
    }
}

#[cfg(unix)]
struct ExistingMetadata {
    uid: u32,
    gid: u32,
    mode: u32,
}

#[cfg(unix)]
fn existing_metadata(path: &Path) -> Result<Option<ExistingMetadata>, TokenStoreFileError> {
    use std::os::unix::fs::MetadataExt;
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            validate_metadata(path, &metadata)?;
            Ok(Some(ExistingMetadata {
                uid: metadata.uid(),
                gid: metadata.gid(),
                mode: metadata.mode() & 0o777,
            }))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(io_error(path, error)),
    }
}

#[cfg(not(unix))]
fn existing_metadata(path: &Path) -> Result<Option<()>, TokenStoreFileError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            validate_metadata(path, &metadata)?;
            Ok(Some(()))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(io_error(path, error)),
    }
}

fn read_private_file(path: &Path) -> Result<Vec<u8>, TokenStoreFileError> {
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
    let file = {
        let metadata = fs::symlink_metadata(path).map_err(|error| io_error(path, error))?;
        if metadata.file_type().is_symlink() {
            return Err(TokenStoreFileError::Invalid(
                "token store may not be a symbolic link".to_owned(),
            ));
        }
        fs::File::open(path).map_err(|error| io_error(path, error))?
    };
    let metadata = file.metadata().map_err(|error| io_error(path, error))?;
    validate_metadata(path, &metadata)?;
    let mut bytes = Vec::with_capacity((metadata.len() as usize).min(MAX_STORE_BYTES as usize));
    file.take(MAX_STORE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| io_error(path, error))?;
    if bytes.len() as u64 > MAX_STORE_BYTES {
        return Err(TokenStoreFileError::Invalid(format!(
            "token store exceeds {MAX_STORE_BYTES} bytes"
        )));
    }
    Ok(bytes)
}

fn validate_metadata(path: &Path, metadata: &fs::Metadata) -> Result<(), TokenStoreFileError> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(TokenStoreFileError::Invalid(format!(
            "'{}' must be a regular non-symlink file",
            path.display()
        )));
    }
    if metadata.len() > MAX_STORE_BYTES {
        return Err(TokenStoreFileError::Invalid(format!(
            "token store exceeds {MAX_STORE_BYTES} bytes"
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let mode = metadata.mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(TokenStoreFileError::Invalid(format!(
                "token store mode {mode:04o} permits group/other access"
            )));
        }
        let owner = metadata.uid();
        let effective = rustix::process::geteuid().as_raw();
        if owner != effective && owner != 0 {
            return Err(TokenStoreFileError::Invalid(format!(
                "token store owner uid {owner} is neither effective uid {effective} nor root"
            )));
        }
    }
    Ok(())
}

fn validate_references(
    store: &TokenStore,
    known_devices: &[String],
) -> Result<(), TokenStoreFileError> {
    for entry in store.entries() {
        if let ScopeSet::Allowlist(devices) = &entry.devices {
            for device in devices {
                if !known_devices.iter().any(|known| known == device) {
                    return Err(TokenStoreFileError::Invalid(format!(
                        "token '{}' references unknown device '{device}'",
                        entry.name
                    )));
                }
            }
        }
        if let ScopeSet::Allowlist(tools) = &entry.tools {
            for tool in tools {
                if !KNOWN_TOOLS.contains(&tool.as_str()) {
                    return Err(TokenStoreFileError::Invalid(format!(
                        "token '{}' references unknown tool '{tool}'",
                        entry.name
                    )));
                }
            }
        }
    }
    Ok(())
}

fn require_absolute(path: &Path) -> Result<(), TokenStoreFileError> {
    if !path.is_absolute() {
        return Err(TokenStoreFileError::Invalid(
            "token-store path must be absolute".to_owned(),
        ));
    }
    Ok(())
}

fn now_unix() -> Result<u64, TokenStoreFileError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| TokenStoreFileError::Invalid("system clock is before Unix epoch".to_owned()))
}

fn sync_directory(path: &Path) -> Result<(), TokenStoreFileError> {
    fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| io_error(path, error))
}

fn io_error(path: &Path, error: std::io::Error) -> TokenStoreFileError {
    TokenStoreFileError::Io {
        path: path.to_path_buf(),
        error,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn known() -> Vec<String> {
        vec!["fw-1".to_owned(), "fw-2".to_owned()]
    }

    #[test]
    fn add_list_rotate_revoke_never_persists_plaintext() {
        let directory = tempfile::tempdir().expect("directory");
        let path = directory.path().join("tokens.json");
        let secret = TokenStoreFile::add(
            &path,
            "reader",
            ScopeSet::Allowlist(vec!["fw-1".to_owned()]),
            ScopeSet::Allowlist(vec!["list_devices".to_owned()]),
            &known(),
        )
        .expect("add");
        let bytes = fs::read(&path).expect("stored JSON");
        assert!(!String::from_utf8_lossy(&bytes).contains(secret.expose_secret()));
        let before = TokenStoreFile::load(&path, &known()).expect("load");
        assert!(before.authenticate(secret.expose_secret()).is_some());

        let rotated = TokenStoreFile::rotate(&path, "reader", &known()).expect("rotate");
        let after = TokenStoreFile::load(&path, &known()).expect("reload");
        assert!(after.authenticate(secret.expose_secret()).is_none());
        assert!(after.authenticate(rotated.expose_secret()).is_some());
        assert!(TokenStoreFile::revoke(&path, "reader", &known()).expect("revoke"));
        assert!(!TokenStoreFile::revoke(&path, "reader", &known()).expect("idempotent revoke"));
    }

    #[test]
    fn unknown_references_and_plaintext_fields_are_refused() {
        let directory = tempfile::tempdir().expect("directory");
        let path = directory.path().join("tokens.json");
        let digest = crate::TokenDigest::from_secret("secret");
        fs::write(
            &path,
            format!(
                r#"{{"version":1,"tokens":[{{"name":"bad","digest":"{}","devices":["missing"],"tools":["list_devices"],"created_at_unix":1,"secret":"no"}}]}}"#,
                digest.as_str()
            ),
        )
        .expect("write");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("mode");
        }
        assert!(TokenStoreFile::load(&path, &known()).is_err());
    }

    #[test]
    fn version_one_store_loads_and_is_saved_as_version_two() {
        let directory = tempfile::tempdir().expect("directory");
        let path = directory.path().join("tokens.json");
        let digest = crate::TokenDigest::from_secret("secret");
        fs::write(
            &path,
            format!(
                r#"{{"version":1,"tokens":[{{"name":"reader","digest":"{}","devices":["fw-1"],"tools":["list_devices"],"created_at_unix":1}}]}}"#,
                digest.as_str()
            ),
        )
        .expect("write");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("mode");
        }
        let store = TokenStoreFile::load(&path, &known()).expect("v1 migration read");
        assert!(store.entries()[0].mutation.is_none());
        TokenStoreFile::save(&path, &store).expect("v2 save");
        let saved: serde_json::Value =
            serde_json::from_slice(&fs::read(path).expect("saved bytes")).expect("JSON");
        assert_eq!(saved["version"], 2);
    }

    #[test]
    fn unknown_device_and_tool_references_are_refused_independently() {
        let directory = tempfile::tempdir().expect("directory");
        let path = directory.path().join("tokens.json");
        let digest = crate::TokenDigest::from_secret("secret");
        for (devices, tools) in [
            (r#"["missing"]"#, r#"["list_devices"]"#),
            (r#"["fw-1"]"#, r#"["not_a_tool"]"#),
        ] {
            fs::write(
                &path,
                format!(
                    r#"{{"version":1,"tokens":[{{"name":"bad","digest":"{}","devices":{devices},"tools":{tools},"created_at_unix":1}}]}}"#,
                    digest.as_str()
                ),
            )
            .expect("write");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("mode");
            }
            assert!(TokenStoreFile::load(&path, &known()).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn permissive_mode_and_symlink_are_refused() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let directory = tempfile::tempdir().expect("directory");
        let path = directory.path().join("tokens.json");
        fs::write(&path, r#"{"version":1,"tokens":[]}"#).expect("write");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("chmod");
        assert!(TokenStoreFile::load(&path, &known()).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");
        let link = directory.path().join("tokens-link.json");
        symlink(&path, &link).expect("symlink");
        assert!(TokenStoreFile::load(&link, &known()).is_err());
    }
}
