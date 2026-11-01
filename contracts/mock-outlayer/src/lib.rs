//! Stands in for OutLayer's `request_execution`, modelling its real yield/resume shape so the bounty's
//! `on_verdict` (attached as `.then`) sees exactly what the worker path produces.
//!
//! `request_execution` opens a yield (as OutLayer does) and returns that promise. `arm` chooses what happens:
//! * `verdict` / `null` — resume the yield at once with the armed bytes (or JSON `null`). `on_verdict` runs
//!   this block, exactly as a fast worker would.
//! * `stall` — open the yield and do NOT resume it. The commit stays `Pending` until NEAR's own ~200-block
//!   yield timeout resumes it with empty data (→ `null` → verifier unavailable), modelling a worker that
//!   never answers. During that window a second commit sees the invariant busy (I3) and the reservation is
//!   held (I4) — both reachable to the tests.

use near_sdk::serde_json::{self, json, Value};
use near_sdk::{env, near, AccountId, CryptoHash, Gas, GasWeight, PanicOnDefault, PromiseError};

const RESOLVE_GAS: Gas = Gas::from_tgas(10);
const REGISTER: u64 = 0;

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct MockOutlayer {
    next: String,
}

#[near]
impl MockOutlayer {
    #[init]
    pub fn new() -> Self {
        Self { next: json!({ "mode": "null" }).to_string() }
    }

    pub fn arm(&mut self, next: Value) {
        self.next = next.to_string();
    }

    #[payable]
    pub fn request_execution(
        &mut self,
        source: Option<Value>,
        resource_limits: Option<Value>,
        input_data: Option<String>,
        secrets_ref: Option<Value>,
        response_format: Option<Value>,
        payer_account_id: Option<AccountId>,
    ) {
        let _ = (source, resource_limits, input_data, secrets_ref, response_format, payer_account_id);
        let next: Value = serde_json::from_str(&self.next).unwrap_or(Value::Null);
        let mode = next.get("mode").and_then(|m| m.as_str()).unwrap_or("null").to_string();

        // Open the yield; its callback `resolve` passes the resume bytes straight through to the bounty.
        let promise = env::promise_yield_create("resolve", b"{}", RESOLVE_GAS, GasWeight(0), REGISTER);
        let data_id: CryptoHash = env::read_register(REGISTER).expect("register").try_into().expect("32 bytes");

        match mode.as_str() {
            "verdict" => {
                let v = next.get("verdict").cloned().unwrap_or(Value::Null);
                env::promise_yield_resume(&data_id, serde_json::to_vec(&v).unwrap().as_slice());
            }
            "null" => {
                env::promise_yield_resume(&data_id, b"null");
            }
            // "stall": leave the yield dangling → NEAR times it out after ~200 blocks.
            _ => {}
        }
        env::promise_return(promise);
    }

    /// The yield callback. The resume payload arrives as `#[callback_result]`; on a real timeout it is an
    /// `Err`. Its return value is what the bounty's `on_verdict` receives (OutLayer `value_return`s the same
    /// shape: the worker output, or JSON `null`).
    pub fn resolve(&self, #[callback_result] response: Result<Value, PromiseError>) -> Value {
        response.unwrap_or(Value::Null)
    }
}
