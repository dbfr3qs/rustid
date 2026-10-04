use rustid_core::stores::{SigningKeyStore, StoreError};
use rustid_store_memory::FileSystemSigningKeyStore;

/// A key file as the file system key store writes it (BOM included).
const KEY_FILE_WITH_BOM: &str = "\u{feff}{\"Version\":1,\"Id\":\"D4382392FF3029C063481BFCFC6958A5\",\"Created\":\"2026-09-29T05:14:02.7172539Z\",\"Algorithm\":\"RS256\",\"IsX509Certificate\":false,\"Data\":\"CfDJ8...\",\"DataProtected\":true}";

#[tokio::test]
async fn files_are_named_by_id_and_unreadable_ones_are_skipped() {
    let dir = tempfile::tempdir().unwrap();
    let store = FileSystemSigningKeyStore::new(dir.path());
    std::fs::write(
        dir.path()
            .join("is-signing-key-D4382392FF3029C063481BFCFC6958A5.json"),
        KEY_FILE_WITH_BOM,
    )
    .unwrap();
    std::fs::write(dir.path().join("is-signing-key-broken.json"), "{").unwrap();
    std::fs::write(dir.path().join("unrelated.json"), "{}").unwrap();
    let keys = store.load_keys().await.unwrap();
    assert_eq!(keys.len(), 1, "the broken and unrelated files are ignored");
    assert_eq!(keys[0].id, "D4382392FF3029C063481BFCFC6958A5");
    assert!(keys[0].data_protected);
    store
        .delete_key("D4382392FF3029C063481BFCFC6958A5")
        .await
        .unwrap();
    assert!(store.load_keys().await.unwrap().is_empty());
}

#[tokio::test]
async fn ids_cannot_escape_the_directory() {
    let dir = tempfile::tempdir().unwrap();
    let store = FileSystemSigningKeyStore::new(dir.path().join("keys"));
    for id in ["../x", "a/b", "", "a.b"] {
        assert!(
            matches!(store.delete_key(id).await, Err(StoreError::Backend(_))),
            "{id}"
        );
    }
}

#[cfg(unix)]
#[tokio::test]
async fn key_files_are_readable_by_the_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let store = FileSystemSigningKeyStore::new(dir.path());
    store
        .store_key(rustid_core::stores::SerializedKey {
            version: 1,
            id: "K".into(),
            created: chrono::Utc::now(),
            algorithm: "RS256".into(),
            is_x509_certificate: false,
            data: "secret".into(),
            data_protected: false,
        })
        .await
        .unwrap();
    let mode = std::fs::metadata(dir.path().join("is-signing-key-K.json"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
}
