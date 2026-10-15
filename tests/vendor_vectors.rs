use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use idrive_core::crypto::{CommandCipher, challenge_hash};

// Golden vectors produced by the official ARM64 client with synthetic inputs.
#[test]
fn vendor_string_encryption_vector() {
    let cipher = CommandCipher::derive(b"i am salt for encode", b"i am salt for encode");
    let encrypted = cipher.encrypt_bytes(b"idrive-rs-synthetic-vector");
    let mut bytes = format!("{}-", encrypted.len()).into_bytes();
    bytes.extend_from_slice(&encrypted);
    assert_eq!(
        STANDARD_NO_PAD.encode(bytes),
        "MzItHaxkoYbYyqgBsJJ0GQPSVOkdT7DOZ+BL5URsN+FOKAs"
    );
}

#[test]
fn vendor_module_wire_vector() {
    let cipher = CommandCipher::greeting();
    assert_eq!(
        cipher.encode("ibackup").unwrap(),
        "MTY6MC3g8k1OjNfi)A8r+JB7cydZ"
    );
    assert_eq!(
        cipher.decode("MTY6MC3g8k1OjNfi)A8r+JB7cydZ").unwrap(),
        "ibackup"
    );
}

#[test]
fn vendor_authentication_hash_vectors() {
    assert_eq!(
        challenge_hash(b"synthetic-password", b"synthetic-challenge").as_str(),
        "XDbotfg+aR4gMThTd6c01g"
    );
    assert_eq!(
        challenge_hash(b"synthetic-user", b"synthetic-user").as_str(),
        "fErMXTLbAACYwpquMtdZTg"
    );
}

#[test]
fn malformed_command_frames_are_rejected() {
    let c = CommandCipher::greeting();
    for input in ["!", "OTk5OTk5OTk5OjAt", "MTY6MC0=", "MTY6MS0="] {
        assert!(c.decode(input).is_err());
    }
}
