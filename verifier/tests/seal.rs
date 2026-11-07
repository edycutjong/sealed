//! Public-API tests for `verifier::seal`: wire format, determinism and round-trip via `crypto_box`.

use base64::Engine;
use blake2::{digest::consts::U24, Blake2b, Digest};
use crypto_box::{aead::Aead, PublicKey, SalsaBox, SecretKey};
use verifier::seal::{plaintext, seal};

const SALT: [u8; 32] = [7u8; 32];

fn keys() -> ([u8; 32], [u8; 32], PublicKey) {
    let proto_sk = SecretKey::from([0x11u8; 32]);
    let proto_pk = proto_sk.public_key();
    (*proto_pk.as_bytes(), [0x22u8; 32], proto_pk)
}

#[test]
fn plaintext_has_canonical_key_order_and_encodings() {
    let pt = String::from_utf8(plaintext(b"\x00\xffabc", &SALT, "al\"ice")).unwrap();
    let b64 = base64::engine::general_purpose::STANDARD.encode(b"\x00\xffabc");
    let expected = format!(
        "{{\"exploit\":\"{b64}\",\"salt\":\"{}\",\"hunter\":\"al\\\"ice\"}}",
        "07".repeat(32)
    );
    assert_eq!(pt, expected);
    let v: serde_json::Value = serde_json::from_str(&pt).unwrap();
    assert_eq!(v["hunter"], "al\"ice");
}

#[test]
fn plaintext_handles_empty_inputs() {
    let pt = String::from_utf8(plaintext(b"", &[0u8; 32], "")).unwrap();
    assert_eq!(pt, format!("{{\"exploit\":\"\",\"salt\":\"{}\",\"hunter\":\"\"}}", "00".repeat(32)));
}

#[test]
fn seal_is_deterministic_and_opens_like_sealed_box() {
    let (pk_bytes, eph_sk, _) = keys();
    let a = seal(b"payload", &SALT, "bob", &pk_bytes, &eph_sk).unwrap();
    let b = seal(b"payload", &SALT, "bob", &pk_bytes, &eph_sk).unwrap();
    assert_eq!(a, b);

    // epk prefix is X25519(eph_sk)
    let epk = SecretKey::from(eph_sk).public_key();
    assert_eq!(&a[..32], epk.as_bytes());
    // 16-byte poly1305 tag overhead
    let pt = plaintext(b"payload", &SALT, "bob");
    assert_eq!(a.len(), 32 + pt.len() + 16);

    // open as libsodium crypto_box_seal_open would
    let proto_sk = SecretKey::from([0x11u8; 32]);
    let mut h = Blake2b::<U24>::new();
    h.update(epk.as_bytes());
    h.update(pk_bytes);
    let nonce = h.finalize();
    let opened = SalsaBox::new(&epk, &proto_sk).decrypt(&nonce, &a[32..]).unwrap();
    assert_eq!(opened, pt);
}

#[test]
fn seal_differs_per_ephemeral_key_and_input() {
    let (pk_bytes, eph_sk, _) = keys();
    let base = seal(b"x", &SALT, "h", &pk_bytes, &eph_sk).unwrap();
    assert_ne!(base, seal(b"x", &SALT, "h", &pk_bytes, &[0x33u8; 32]).unwrap());
    assert_ne!(base, seal(b"y", &SALT, "h", &pk_bytes, &eph_sk).unwrap());
    assert_ne!(base, seal(b"x", &[8u8; 32], "h", &pk_bytes, &eph_sk).unwrap());
    assert_ne!(base, seal(b"x", &SALT, "other", &pk_bytes, &eph_sk).unwrap());
}
