//! Native CLI entrypoint (`src/main.rs`): stdin = public input JSON (the day-0 vectors carry their
//! own test secrets), stdout = one verdict JSON line. The golden tests call the library directly and
//! run the wasm under wasmtime; nothing else exercises the native `main` or the env-gated
//! `SEALED_TRACE` path (`lib::trace` / `lib::outcome`). These do.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn vector(name: &str) -> Vec<u8> {
    std::fs::read(root().join(format!("day0/{name}.json"))).expect("day-0 vector")
}

/// Run the compiled verifier binary with `input` on stdin. Returns (success, stdout, stderr).
fn run_cli(input: &[u8], trace: bool) -> (bool, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_verifier"));
    cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    if trace {
        cmd.env("SEALED_TRACE", "1");
    }
    let mut child = cmd.spawn().expect("spawn verifier binary");
    child.stdin.as_mut().unwrap().write_all(input).unwrap();
    let out = child.wait_with_output().unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn cli_prints_a_broken_verdict_for_a_real_exploit() {
    let (ok, stdout, stderr) = run_cli(&vector("fallback"), false);
    assert!(ok, "exit success; stderr: {stderr}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("one verdict JSON line");
    assert_eq!(v["broken"], serde_json::Value::Bool(true));
    assert_eq!(v["h_enc"].as_str().unwrap().len(), 64, "h_enc is a sha256 hex digest");
}

#[test]
fn cli_with_trace_emits_trace_lines_and_the_same_verdict() {
    let (ok, stdout, stderr) = run_cli(&vector("fallback"), true);
    assert!(ok, "exit success with SEALED_TRACE; stderr: {stderr}");
    assert!(stderr.contains("trace:"), "SEALED_TRACE should emit trace lines; got: {stderr}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(v["broken"], serde_json::Value::Bool(true), "tracing does not change the verdict");
}

#[test]
fn cli_treats_invalid_input_as_a_normal_not_broken_verdict() {
    let (ok, stdout, stderr) = run_cli(b"this is not json", false);
    assert!(ok, "bad input is a normal verdict, never a crash; stderr: {stderr}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(v["broken"], serde_json::Value::Bool(false));
    assert_eq!(v["err"], serde_json::Value::String("input invalid".into()));
}
