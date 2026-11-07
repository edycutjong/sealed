use std::process::{Command, Output};

const RUNTIME: &str = "61beef600052600160055560206000f3";
const REVERT_RUNTIME: &str = "60006000fd";

fn deploy_code(runtime: &str) -> String {
    let len = runtime.len() / 2;
    format!("60{len:02x}80600b6000396000f3{runtime}")
}

fn run(artifact: &str, value: &str) -> Output {
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let p = std::env::temp_dir().join(format!("snapgen-test-{}-{n}.json", std::process::id()));
    std::fs::write(&p, artifact).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_snapgen"))
        .args(["lvl", p.to_str().unwrap(), value])
        .output()
        .unwrap();
    let _ = std::fs::remove_file(&p);
    out
}

fn art(code: &str) -> String {
    format!(r#"{{"bytecode":{{"object":"0x{code}"}}}}"#)
}

#[test]
fn builds_snapshot() {
    let o = run(&art(&deploy_code(RUNTIME)), "7");
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["name"], "lvl");
    assert_eq!(v["chain_id"], 31337);
    assert_eq!(v["player"], "0x2000000000000000000000000000000000000002");
    assert_eq!(v["instance"], "0x000000000000000000000000000000000000beef");
    let factory = v["factory"].as_str().unwrap();
    let acc = &v["accounts"][factory];
    assert_eq!(acc["code"], RUNTIME);
    assert_eq!(acc["storage"]["0x5"], "0x1");
    assert_eq!(acc["balance"], "0x7");
    assert!(v["accounts"]["0x1000000000000000000000000000000000000001"].is_object());
}

#[test]
fn factory_deploy_failure_panics() {
    let o = run(&art("60006000fd"), "0");
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("factory deploy failed"));
}

#[test]
fn create_instance_failure_panics() {
    let o = run(&art(&deploy_code(REVERT_RUNTIME)), "0");
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("createInstance failed"));
}
