//! Deterministic libsodium `crypto_box_seal` wire format: the ephemeral key comes from the hunter's `EPH_SK`
//! instead of an RNG, so native, wasmtime and OutLayer produce identical bytes and `crypto_box_seal_open`
//! (e.g. PyNaCl `SealedBox`) opens them.
//!
//! `epk = X25519(EPH_SK)`, `nonce = BLAKE2b-24(epk ‖ pk)`, `enc = epk ‖ crypto_box_easy(PT, nonce, pk, EPH_SK)`.

use base64::Engine;
use blake2::{digest::consts::U24, Blake2b, Digest};
use crypto_box::{aead::Aead, PublicKey, SalsaBox, SecretKey};

/// Canonical plaintext: `{"exploit":base64(exploit_bytes),"salt":hex,"hunter":str}` (keys in this order).
pub fn plaintext(exploit_bytes: &[u8], salt: &[u8; 32], hunter: &str) -> Vec<u8> {
    let b64 = base64::engine::general_purpose::STANDARD.encode(exploit_bytes);
    format!(
        "{{\"exploit\":{},\"salt\":\"{}\",\"hunter\":{}}}",
        serde_json::Value::String(b64),
        hex::encode(salt),
        serde_json::Value::String(hunter.to_string())
    )
    .into_bytes()
}

pub fn seal(
    exploit_bytes: &[u8],
    salt: &[u8; 32],
    hunter: &str,
    protocol_pk: &[u8; 32],
    eph_sk: &[u8; 32],
) -> Result<Vec<u8>, String> {
    let sk = SecretKey::from(*eph_sk);
    let epk = sk.public_key();
    let pk = PublicKey::from(*protocol_pk);
    let mut h = Blake2b::<U24>::new();
    h.update(epk.as_bytes());
    h.update(pk.as_bytes());
    let nonce = h.finalize();
    let ct = SalsaBox::new(&pk, &sk)
        .encrypt(&nonce, plaintext(exploit_bytes, salt, hunter).as_slice())
        .map_err(|_| "seal failed".to_string())?;
    let mut out = Vec::with_capacity(32 + ct.len());
    out.extend_from_slice(epk.as_bytes());
    out.extend_from_slice(&ct);
    Ok(out)
}
