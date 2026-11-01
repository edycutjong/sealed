//! Golden verdicts. Inputs are the day-0 vectors (`day0/*.json`, test keys from `day0/vectors.json`); the expected
//! verdict line for each is in `tests/golden/<name>.json`. `UPDATE_GOLDEN=1 cargo test -p verifier` rewrites them.
//!
//! The same vectors also run through the committed `verifier.wasm` under wasmtime (skipped, loudly, if wasmtime is
//! not on PATH) and must print the same verdict bytes, `lim` aside (the worker's environment report).

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use verifier::{run, sha256, Input, Verdict, SNAPSHOTS};

const VECTORS: &[&str] = &[
    "fallback", "noop", "abuse-big", "abuse-blake2f", "abuse-callself", "abuse-cdcopy", "abuse-create", "abuse-exp",
    "abuse-extcodecopy", "abuse-input", "abuse-jumpdest", "abuse-keccak", "abuse-log", "abuse-loop", "abuse-mcopy",
    "abuse-mem", "abuse-mulmod", "abuse-over", "abuse-sstore",
];

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn input(name: &str) -> (Vec<u8>, Input) {
    let raw = std::fs::read(root().join("day0").join(format!("{name}.json"))).expect("vector");
    let input: Input = serde_json::from_slice(&raw).expect("vector parses");
    (raw, input)
}

fn verdict(name: &str) -> (Input, Verdict, Vec<u8>) {
    let (_, input) = input(name);
    let secrets = input.secrets.clone().expect("day-0 vectors carry their test secrets");
    let r = run(&input, &secrets, None).expect("run");
    (input, r.verdict, r.enc)
}

fn golden(name: &str, actual: &str) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden").join(name);
    if std::env::var("UPDATE_GOLDEN").is_ok() {
        std::fs::write(&path, format!("{actual}\n")).unwrap();
    }
    let want = std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing golden {path:?}"));
    assert_eq!(want.trim_end(), actual, "golden {name}");
}

#[test]
fn every_vector_matches_its_golden_verdict() {
    for name in VECTORS {
        let (_, v, _) = verdict(name);
        golden(&format!("{name}.json"), &serde_json::to_string(&v).unwrap());
    }
}

#[test]
fn fallback_real_exploit_breaks_the_level() {
    let (input, v, _) = verdict("fallback");
    assert!(v.broken, "Fallback exploit must make validateInstance return true");
    assert_eq!(v.err, None);
    assert_eq!(v.h_exploit, input.commit_hash, "h_exploit is the commit hash the hunter committed");
    assert_eq!(v.h_snapshot, hex::encode(sha256(&[SNAPSHOTS[0]])));
    assert!(v.gas_used > 0 && v.gas_used <= verifier::EXPLOIT_GAS_BUDGET);
}

#[test]
fn noop_does_not_break_the_level() {
    let (input, v, _) = verdict("noop");
    assert!(!v.broken);
    assert_eq!(v.err, None);
    assert_eq!(v.gas_used, 0);
    assert_eq!(v.h_exploit, input.commit_hash);
}

/// Day-0 G5b shapes: every fake ends as a normal verdict (never a verifier error, which would be a free retry).
#[test]
fn abuse_shapes_are_normal_verdicts() {
    for name in VECTORS.iter().filter(|n| n.starts_with("abuse-")) {
        let (_, v, _) = verdict(name);
        assert!(!v.broken, "{name} must not break the level");
        assert!(v.gas_used <= verifier::EXPLOIT_GAS_BUDGET, "{name} gas {}", v.gas_used);
        if let Some(e) = &v.err {
            assert!(e.starts_with("exploit invalid: "), "{name}: {e}");
        }
        assert!(!v.h_enc.is_empty(), "{name}: a fake still gets a sealed copy, so commit binding is checked");
    }
}

/// The sealed box is deterministic: the same secrets give the same `enc`, byte for byte (hunter rebuilds it).
#[test]
fn enc_golden_vector() {
    let (_, v, enc) = verdict("fallback");
    golden("fallback.enc.hex", &hex::encode(&enc));
    assert_eq!(v.h_enc, hex::encode(sha256(&[&enc])));
    let (_, _, again) = verdict("fallback");
    assert_eq!(enc, again);
}

#[test]
fn binding_changes_with_hunter_and_salt() {
    let (_, mut input) = input("fallback");
    let secrets = input.secrets.clone().unwrap();
    let base = run(&input, &secrets, None).unwrap().verdict;
    input.hunter = "someone-else.testnet".into();
    let other = run(&input, &secrets, None).unwrap().verdict;
    assert_ne!(base.h_exploit, other.h_exploit, "a copied commit hash fails for another hunter (I7)");
    let mut s2 = secrets.clone();
    s2.salt = "33".repeat(32);
    let salted = run(&input, &s2, None).unwrap().verdict;
    assert_ne!(other.h_exploit, salted.h_exploit);
}

/// NEAR-mode output limit: 900 B, with every variable field at its cap and the worker's limits report attached.
#[test]
fn output_fits_900_bytes_worst_case() {
    let lim = verifier::Limits { i: Some(u64::MAX), m: Some(u64::MAX), s: Some(u64::MAX), mem: Some(u64::MAX) };
    let mut v = verifier::error_verdict(&"i".repeat(4000), "e".repeat(4000), Some(lim));
    v.h_exploit = "f".repeat(64);
    v.h_snapshot = "f".repeat(64);
    v.h_enc = "f".repeat(64);
    v.gas_used = u64::MAX;
    v.broken = true;
    let line = serde_json::to_string(&v).unwrap();
    assert!(line.len() <= 900, "{} B", line.len());
}

#[test]
fn committed_wasm_matches_its_sha256() {
    let wasm = std::fs::read(root().join("verifier.wasm")).expect("verifier.wasm committed at the repo root");
    let want = std::fs::read_to_string(root().join("verifier.wasm.sha256")).unwrap();
    assert_eq!(want.split_whitespace().next().unwrap(), hex::encode(sha256(&[&wasm])));
}

/// Same verdict bytes from the committed wasm under wasmtime as from the native build.
#[test]
fn wasmtime_prints_the_native_verdicts() {
    if Command::new("wasmtime").arg("--version").output().is_err() {
        eprintln!("SKIPPED: wasmtime not on PATH (native goldens still checked)");
        return;
    }
    let wasm = root().join("verifier.wasm");
    for name in VECTORS {
        let (raw, _) = input(name);
        let mut child = Command::new("wasmtime")
            .arg("run")
            .arg(&wasm)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        std::io::Write::write_all(child.stdin.as_mut().unwrap(), &raw).unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success(), "{name}: wasmtime exit {:?}", out.status);
        let mut got: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        got.as_object_mut().unwrap().remove("lim");
        let (_, v, _) = verdict(name);
        assert_eq!(serde_json::to_string(&got).unwrap(), serde_json::to_string(&v).unwrap(), "{name}");
    }
}
