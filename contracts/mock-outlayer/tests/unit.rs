use mock_outlayer::MockOutlayer;
use near_sdk::serde_json::{json, Value};
use near_sdk::test_utils::VMContextBuilder;
use near_sdk::{testing_env, PromiseError};
use std::sync::Mutex;

// The mocked VM in near-sdk does not export the yield/resume host functions, so the test binary supplies
// recording stubs: `create` hands back a 32-byte data id (sha256 of "yield"), `resume` records the payload it was given.
static CREATED: Mutex<Vec<(String, Vec<u8>, u64)>> = Mutex::new(Vec::new());
static RESUMED: Mutex<Vec<(Vec<u8>, Vec<u8>)>> = Mutex::new(Vec::new());
static LOCK: Mutex<()> = Mutex::new(());

extern "C-unwind" {
    fn sha256(value_len: u64, value_ptr: u64, register_id: u64);
    fn promise_batch_create(account_id_len: u64, account_id_ptr: u64) -> u64;
}

#[no_mangle]
pub extern "C" fn promise_yield_create(
    fn_len: u64,
    fn_ptr: u64,
    args_len: u64,
    args_ptr: u64,
    gas: u64,
    _weight: u64,
    register_id: u64,
) -> u64 {
    unsafe {
        let name = std::slice::from_raw_parts(fn_ptr as *const u8, fn_len as usize).to_vec();
        let args = std::slice::from_raw_parts(args_ptr as *const u8, args_len as usize).to_vec();
        CREATED.lock().unwrap().push((String::from_utf8(name).unwrap(), args, gas));
        // The mock exposes no register writer; hashing a fixed input fills the register with a 32-byte id.
        sha256(5, b"yield".as_ptr() as u64, register_id);
        // A real (mock) promise index so the contract's `promise_return` is valid.
        promise_batch_create(10, b"yield.test".as_ptr() as u64)
    }
}

#[no_mangle]
pub extern "C" fn promise_yield_resume(id_len: u64, id_ptr: u64, pl_len: u64, pl_ptr: u64) -> u32 {
    unsafe {
        let id = std::slice::from_raw_parts(id_ptr as *const u8, id_len as usize).to_vec();
        let pl = std::slice::from_raw_parts(pl_ptr as *const u8, pl_len as usize).to_vec();
        RESUMED.lock().unwrap().push((id, pl));
    }
    1
}

fn setup() -> (MockOutlayer, std::sync::MutexGuard<'static, ()>) {
    let g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    CREATED.lock().unwrap().clear();
    RESUMED.lock().unwrap().clear();
    testing_env!(VMContextBuilder::new().build());
    (MockOutlayer::new(), g)
}

fn exec(c: &mut MockOutlayer) {
    c.request_execution(None, None, None, None, None, None);
}

fn resumed() -> Vec<Vec<u8>> {
    RESUMED.lock().unwrap().iter().map(|(id, p)| {
        assert_eq!(id, &near_sdk::env::sha256(b"yield"));
        p.clone()
    }).collect()
}

fn assert_created() {
    let c = CREATED.lock().unwrap();
    assert_eq!(c.len(), 1);
    assert_eq!(c[0].0, "resolve");
    assert_eq!(c[0].1, b"{}".to_vec());
    assert_eq!(c[0].2, 10_000_000_000_000);
}

#[test]
fn new_defaults_to_null_mode_and_resumes_null() {
    let (mut c, _g) = setup();
    exec(&mut c);
    assert_created();
    assert_eq!(resumed(), vec![b"null".to_vec()]);
}

#[test]
fn verdict_mode_resumes_with_verdict() {
    let (mut c, _g) = setup();
    c.arm(json!({ "mode": "verdict", "verdict": { "ok": true } }));
    exec(&mut c);
    assert_created();
    assert_eq!(resumed(), vec![br#"{"ok":true}"#.to_vec()]);
}

#[test]
fn verdict_mode_without_verdict_field_resumes_null() {
    let (mut c, _g) = setup();
    c.arm(json!({ "mode": "verdict" }));
    exec(&mut c);
    assert_eq!(resumed(), vec![b"null".to_vec()]);
}

#[test]
fn stall_mode_opens_yield_without_resuming() {
    let (mut c, _g) = setup();
    c.arm(json!({ "mode": "stall" }));
    exec(&mut c);
    assert_created();
    assert!(resumed().is_empty());
}

#[test]
fn missing_mode_defaults_to_null() {
    let (mut c, _g) = setup();
    c.arm(json!({ "other": 1 }));
    exec(&mut c);
    assert_eq!(resumed(), vec![b"null".to_vec()]);
}

#[test]
fn resolve_passes_value_through() {
    let (c, _g) = setup();
    assert_eq!(c.resolve(Ok(json!({ "a": 1 }))), json!({ "a": 1 }));
}

#[test]
fn resolve_maps_error_to_null() {
    let (c, _g) = setup();
    assert_eq!(c.resolve(Err(PromiseError::Failed)), Value::Null);
}
