//! Signing key stores: in memory (tests, ephemeral deployments) and the
//! file system (the file system key store, the default for the memory store kind).

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use async_trait::async_trait;
use rustid_core::stores::{SerializedKey, SigningKeyStore, StoreError};

#[derive(Debug, Default)]
pub struct InMemorySigningKeyStore {
    keys: Mutex<Vec<SerializedKey>>,
}

#[async_trait]
impl SigningKeyStore for InMemorySigningKeyStore {
    async fn load_keys(&self) -> Result<Vec<SerializedKey>, StoreError> {
        Ok(self.keys.lock().unwrap_or_else(|p| p.into_inner()).clone())
    }

    async fn store_key(&self, key: SerializedKey) -> Result<(), StoreError> {
        let mut keys = self.keys.lock().unwrap_or_else(|p| p.into_inner());
        if keys.iter().any(|k| k.id == key.id) {
            return Err(StoreError::DuplicateKey(key.id));
        }
        keys.push(key);
        Ok(())
    }

    async fn delete_key(&self, id: &str) -> Result<(), StoreError> {
        self.keys
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .retain(|k| k.id != id);
        Ok(())
    }
}

const KEY_FILE_PREFIX: &str = "is-signing-key-";
const KEY_FILE_EXTENSION: &str = ".json";

/// One JSON file per key, `is-signing-key-{id}.json`, in a directory created
/// on first use. Unreadable files are skipped.
#[derive(Debug, Clone)]
pub struct FileSystemSigningKeyStore {
    dir: PathBuf,
}

impl FileSystemSigningKeyStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        FileSystemSigningKeyStore { dir: dir.into() }
    }

    fn path(&self, id: &str) -> Result<PathBuf, StoreError> {
        // Ids are generated hex; refuse anything that could leave the directory.
        if id.is_empty()
            || !id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(StoreError::Backend(format!(
                "invalid signing key id {id:?}"
            )));
        }
        Ok(self
            .dir
            .join(format!("{KEY_FILE_PREFIX}{id}{KEY_FILE_EXTENSION}")))
    }
}

fn io(error: std::io::Error, what: &str, path: &Path) -> StoreError {
    StoreError::Backend(format!("{what} {}: {error}", path.display()))
}

#[async_trait]
impl SigningKeyStore for FileSystemSigningKeyStore {
    async fn load_keys(&self) -> Result<Vec<SerializedKey>, StoreError> {
        tokio::fs::create_dir_all(&self.dir)
            .await
            .map_err(|e| io(e, "creating", &self.dir))?;
        let mut entries = tokio::fs::read_dir(&self.dir)
            .await
            .map_err(|e| io(e, "reading", &self.dir))?;
        let mut keys = Vec::new();
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| io(e, "reading", &self.dir))?
        {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if !(name.starts_with(KEY_FILE_PREFIX) && name.ends_with(KEY_FILE_EXTENSION)) {
                continue;
            }
            let path = entry.path();
            let parsed = tokio::fs::read_to_string(&path)
                .await
                .map_err(|e| e.to_string())
                .and_then(|json| {
                    serde_json::from_str::<SerializedKey>(json.trim_start_matches('\u{feff}'))
                        .map_err(|e| e.to_string())
                });
            match parsed {
                Ok(key) => keys.push(key),
                Err(message) => {
                    tracing::error!(path = %path.display(), %message, "skipping an unreadable signing key file");
                }
            }
        }
        keys.sort_by(|a, b| a.created.cmp(&b.created).then_with(|| a.id.cmp(&b.id)));
        Ok(keys)
    }

    async fn store_key(&self, key: SerializedKey) -> Result<(), StoreError> {
        use tokio::io::AsyncWriteExt;
        let path = self.path(&key.id)?;
        tokio::fs::create_dir_all(&self.dir)
            .await
            .map_err(|e| io(e, "creating", &self.dir))?;
        let mut options = tokio::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = match options.open(&path).await {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(StoreError::DuplicateKey(key.id));
            }
            Err(e) => return Err(io(e, "creating", &path)),
        };
        let json = serde_json::to_vec(&key).expect("serialized keys serialise");
        file.write_all(&json)
            .await
            .map_err(|e| io(e, "writing", &path))?;
        file.flush().await.map_err(|e| io(e, "writing", &path))?;
        Ok(())
    }

    async fn delete_key(&self, id: &str) -> Result<(), StoreError> {
        let path = self.path(id)?;
        match tokio::fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(io(e, "deleting", &path)),
        }
    }
}
