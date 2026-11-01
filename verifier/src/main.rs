//! WASI entry point. stdin = public input JSON; env = sealed secrets (EXPLOIT, SALT, EPH_SK) and the worker's
//! enforced limits (NEAR_MAX_*). stdout = one verdict JSON line (≤ 900 B).

use std::io::Read;

use verifier::{error_verdict, run, Input, Limits, Secrets};

fn env_u64(k: &str) -> Option<u64> {
    std::env::var(k).ok().and_then(|v| v.trim().parse().ok())
}

#[cfg(target_arch = "wasm32")]
fn peak_memory() -> Option<u64> {
    // Linear memory never shrinks, so its size at exit is the peak.
    Some(core::arch::wasm32::memory_size(0) as u64 * 65536)
}

#[cfg(not(target_arch = "wasm32"))]
fn peak_memory() -> Option<u64> {
    None
}

fn limits() -> Limits {
    Limits {
        i: env_u64("NEAR_MAX_INSTRUCTIONS"),
        m: env_u64("NEAR_MAX_MEMORY_MB"),
        s: env_u64("NEAR_MAX_EXECUTION_SECONDS"),
        mem: None,
    }
}

fn secrets(input: &Input) -> Result<Secrets, String> {
    match (std::env::var("EXPLOIT"), std::env::var("SALT"), std::env::var("EPH_SK")) {
        (Ok(exploit), Ok(salt), Ok(eph_sk)) => Ok(Secrets { exploit, salt, eph_sk }),
        _ => input.secrets.clone().ok_or_else(|| "secret missing".to_string()),
    }
}

fn main() {
    let mut raw = Vec::new();
    let _ = std::io::stdin().read_to_end(&mut raw);
    let lim = limits();
    let verdict = match serde_json::from_slice::<Input>(&raw) {
        Err(_) => error_verdict("", "input invalid".into(), None),
        Ok(input) => match secrets(&input).and_then(|s| run(&input, &s, None)) {
            Ok(r) => {
                if std::env::var("SEALED_DEBUG_ENC").is_ok() {
                    eprintln!("enc={}", hex::encode(&r.enc));
                }
                r.verdict
            }
            Err(e) => error_verdict(&input.invariant_id, e, None),
        },
    };
    let mut verdict = verdict;
    let mut lim = lim;
    lim.mem = peak_memory();
    if lim != Limits::default() {
        verdict.lim = Some(lim);
    }
    println!("{}", serde_json::to_string(&verdict).expect("verdict serializes"));
}
