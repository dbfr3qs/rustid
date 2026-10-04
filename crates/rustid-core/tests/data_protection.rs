use rustid_core::data_protection::{DataProtectionError, DataProtector, KEY_LEN, generate_key};

const A: [u8; KEY_LEN] = [1; KEY_LEN];
const B: [u8; KEY_LEN] = [2; KEY_LEN];

#[test]
fn values_round_trip_and_name_the_sealing_key() {
    let ring = DataProtector::new([("a", &A[..])]).unwrap();
    let sealed = ring.protect("p", b"secret");
    assert!(sealed.starts_with("v1.a."), "{sealed}");
    assert_eq!(ring.unprotect("p", &sealed).unwrap(), b"secret");
    assert_ne!(
        ring.protect("p", b"secret"),
        sealed,
        "fresh nonce each time"
    );
}

#[test]
fn a_rotated_ring_protects_with_the_new_key_and_still_reads_the_old() {
    let old = DataProtector::new([("a", &A[..])]).unwrap();
    let sealed_by_old = old.protect("p", b"x");
    let rotated = DataProtector::new([("b", &B[..]), ("a", &A[..])]).unwrap();
    assert!(rotated.protect("p", b"x").starts_with("v1.b."));
    assert_eq!(rotated.unprotect("p", &sealed_by_old).unwrap(), b"x");
    let without_old = DataProtector::new([("b", &B[..])]).unwrap();
    assert_eq!(
        without_old.unprotect("p", &sealed_by_old),
        Err(DataProtectionError::UnknownKey("a".into()))
    );
}

#[test]
fn purpose_and_integrity_are_checked() {
    let ring = DataProtector::new([("a", &A[..])]).unwrap();
    let sealed = ring.protect("keys", b"x");
    assert_eq!(
        ring.unprotect("cookies", &sealed),
        Err(DataProtectionError::Tampered)
    );
    // Change a ciphertext character that carries six data bits; the last
    // character may hold padding bits that base64 decoding rejects instead.
    let mut tampered = sealed.clone().into_bytes();
    let i = tampered.len() - 3;
    tampered[i] = if tampered[i] == b'A' { b'B' } else { b'A' };
    let tampered = String::from_utf8(tampered).unwrap();
    assert_eq!(
        ring.unprotect("keys", &tampered),
        Err(DataProtectionError::Tampered)
    );
    for malformed in [
        "",
        "v1.a",
        "v2.a.AAAA.AAAA",
        "v1.a.!!.AAAA",
        "v1.a.AAAA.AAAA.x",
    ] {
        assert!(ring.unprotect("keys", malformed).is_err(), "{malformed}");
    }
    // A sealed key protected under a same-id but different secret fails.
    let impostor = DataProtector::new([("a", &B[..])]).unwrap();
    assert_eq!(
        impostor.unprotect("keys", &sealed),
        Err(DataProtectionError::Tampered)
    );
}

#[test]
fn rings_are_validated() {
    assert_eq!(
        DataProtector::new(std::iter::empty()).unwrap_err(),
        DataProtectionError::NoKeys
    );
    assert_eq!(
        DataProtector::new([("a", &A[..16])]).unwrap_err(),
        DataProtectionError::KeyLength("a".into())
    );
    assert_eq!(
        DataProtector::new([("a.b", &A[..])]).unwrap_err(),
        DataProtectionError::KeyId("a.b".into())
    );
    assert_eq!(
        DataProtector::new([("a", &A[..]), ("a", &B[..])]).unwrap_err(),
        DataProtectionError::DuplicateKeyId("a".into())
    );
    assert_ne!(generate_key(), generate_key());
}
