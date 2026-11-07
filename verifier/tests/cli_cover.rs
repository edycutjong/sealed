//! CLI (`src/main.rs`) paths not reached by `tests/cli.rs`: sealed secrets from env, the missing-secret
//! error verdict, NEAR_MAX_* limits echoed in the verdict, and the SEALED_DEBUG_ENC stderr line.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::Value;

fn vector() -> Value {
    let p: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR")).join("../day0/fallback.json");
    serde_json::from_slice(&std::fs::read(p).expect("day-0 vector")).unwrap()
}

fn run_cli(input: &[u8], env: &[(&str, &str)]) -> (bool, Value, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_verifier"));
    for k in ["EXPLOIT", "SALT", "EPH_SK", "NEAR_MAX_INSTRUCTIONS", "NEAR_MAX_MEMORY_MB",
        "NEAR_MAX_EXECUTION_SECONDS", "SEALED_DEBUG_ENC"] {
        cmd.env_remove(k);
    }
    cmd.envs(env.iter().copied());
    cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    child.stdin.as_mut().unwrap().write_all(input).unwrap();
    let out = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    (out.status.success(), serde_json::from_str(stdout.trim()).expect("verdict line"),
        String::from_utf8_lossy(&out.stderr).into_owned())
}

/// (input without secrets, the secrets object)
fn split() -> (Vec<u8>, Value) {
    let mut v = vector();
    let s = v.as_object_mut().unwrap().remove("secrets").expect("vector carries secrets");
    (serde_json::to_vec(&v).unwrap(), s)
}

#[test]
fn secrets_from_env_give_the_same_verdict_as_embedded_secrets() {
    let (embedded, _, _) = (serde_json::to_vec(&vector()).unwrap(), 0, 0);
    let (_, want, _) = run_cli(&embedded, &[]);
    let (bare, s) = split();
    let g = |k: &str| s[k].as_str().unwrap().to_string();
    let (e, x, y) = (g("EXPLOIT"), g("SALT"), g("EPH_SK"));
    let (ok, got, err) = run_cli(&bare, &[("EXPLOIT", &e), ("SALT", &x), ("EPH_SK", &y)]);
    assert!(ok, "{err}");
    assert_eq!(got["broken"], Value::Bool(true));
    assert_eq!(got, want);
}

#[test]
fn missing_secrets_yield_an_error_verdict_naming_the_invariant() {
    let (bare, _) = split();
    let (ok, v, _) = run_cli(&bare, &[]);
    assert!(ok);
    assert_eq!(v["broken"], Value::Bool(false));
    assert!(v.to_string().contains("secret missing"), "{v}");
}

#[test]
fn partial_env_secrets_fall_back_to_embedded_then_error() {
    let (bare, _) = split();
    let (_, v, _) = run_cli(&bare, &[("EXPLOIT", "00")]);
    assert!(v.to_string().contains("secret missing"), "{v}");
}

#[test]
fn near_max_limits_are_echoed_in_the_verdict() {
    let input = serde_json::to_vec(&vector()).unwrap();
    let (ok, v, _) = run_cli(&input, &[
        ("NEAR_MAX_INSTRUCTIONS", " 1000 "),
        ("NEAR_MAX_MEMORY_MB", "64"),
        ("NEAR_MAX_EXECUTION_SECONDS", "junk"),
    ]);
    assert!(ok);
    assert_eq!(v["lim"]["i"], 1000);
    assert_eq!(v["lim"]["m"], 64);
    assert!(v["lim"]["s"].is_null(), "unparseable limit is dropped");
}

#[test]
fn no_limits_means_no_lim_field() {
    let input = serde_json::to_vec(&vector()).unwrap();
    let (_, v, _) = run_cli(&input, &[]);
    assert!(v.get("lim").is_none_or(|l| l.is_null()));
}

#[test]
fn debug_enc_prints_the_ciphertext_hex_to_stderr_only() {
    let input = serde_json::to_vec(&vector()).unwrap();
    let (ok, v, err) = run_cli(&input, &[("SEALED_DEBUG_ENC", "1")]);
    assert!(ok);
    let line = err.lines().find(|l| l.starts_with("enc=")).expect("enc= line");
    let hexs = &line[4..];
    assert!(!hexs.is_empty() && hexs.chars().all(|c| c.is_ascii_hexdigit()));
    assert!(!v.to_string().contains(hexs), "ciphertext never leaks into the verdict");
}
