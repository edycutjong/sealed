//! Day-0 probe. Deployed as NEAR global code by hash onto a keyless account (G9), it pins ONE verifier
//! (`WasmUrl` + sha256, fixed at init, no setter), asks OutLayer to run it (G6), and records what each
//! callback actually received — the arrival type, the raw bytes, and the block heights — so G5/G6/G7/G7d
//! are read from chain state, not from logs alone.
//!
//! Test fixture: initialises only on a `.testnet` account.

use near_sdk::json_types::{Base64VecU8, U128};
use near_sdk::serde_json::{self, json, Value};
use near_sdk::{
    env, near, require, AccountId, Gas, GasWeight, NearToken, PanicOnDefault, Promise, PromiseResult,
};

const CALLBACK_GAS: Gas = Gas::from_tgas(20);
const EXECUTION_GAS: Gas = Gas::from_tgas(100);
const MAX_RAW: usize = 1200;

#[near(serializers = [borsh, json])]
#[derive(Clone)]
pub struct Record {
    pub id: u32,
    pub caller: AccountId,
    pub label: String,
    /// `ok` (promise succeeded, bytes present), `ok-empty` (succeeded, no bytes), `err` (PromiseError).
    pub kind: String,
    /// What the callback got, as UTF-8 (truncated).
    pub raw: Option<String>,
    pub h_enc: Option<String>,
    pub broken: Option<bool>,
    pub requested_height: u64,
    pub requested_ns: u64,
    pub resolved_height: u64,
    pub resolved_ns: u64,
    pub delivered: bool,
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Probe {
    outlayer: AccountId,
    wasm_url: String,
    wasm_hash: String,
    records: Vec<Record>,
}

/// The verdict is the guest's stdout. OutLayer may hand it back as a JSON string, as an object, or wrapped;
/// look for the first object that has `h_enc`.
fn find_verdict(v: &Value) -> Option<Value> {
    match v {
        Value::Object(m) if m.contains_key("h_enc") => Some(v.clone()),
        Value::Object(m) => m.values().find_map(find_verdict),
        Value::String(s) => serde_json::from_str::<Value>(s.trim()).ok().and_then(|x| find_verdict(&x)),
        Value::Array(a) => a.iter().find_map(find_verdict),
        _ => None,
    }
}

#[near]
impl Probe {
    #[init]
    pub fn new(outlayer: AccountId, wasm_url: String, wasm_hash: String) -> Self {
        require!(env::current_account_id().as_str().ends_with(".testnet"), "test fixture: .testnet only");
        require!(
            wasm_hash.len() == 64 && wasm_hash.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
            "wasm_hash: 64 lowercase hex"
        );
        Self { outlayer, wasm_url, wasm_hash, records: Vec::new() }
    }

    /// Run the pinned verifier on `input_data`. The source is always the pinned url + hash; the caller
    /// chooses only the input, the limits, and (for G7) the secrets reference. Attach 300 Tgas.
    #[payable]
    pub fn request(
        &mut self,
        label: String,
        input_data: String,
        resource_limits: Value,
        secrets_ref: Option<Value>,
    ) -> Promise {
        let caller = env::predecessor_account_id();
        let deposit = env::attached_deposit();
        let id = self.records.len() as u32;
        self.records.push(Record {
            id,
            caller: caller.clone(),
            label,
            kind: "pending".into(),
            raw: None,
            h_enc: None,
            broken: None,
            requested_height: env::block_height(),
            requested_ns: env::block_timestamp(),
            resolved_height: 0,
            resolved_ns: 0,
            delivered: false,
        });
        let mut args = json!({
            "source": {"WasmUrl": {"url": self.wasm_url, "hash": self.wasm_hash, "build_target": "wasm32-wasip1"}},
            "resource_limits": resource_limits,
            "input_data": input_data,
            "response_format": "Text",
            "payer_account_id": caller,
        });
        if let Some(s) = secrets_ref {
            args["secrets_ref"] = s;
        }
        env::log_str(&format!("probe: request {id} source WasmUrl hash {}", self.wasm_hash));
        Promise::new(self.outlayer.clone())
            .function_call_weight(
                "request_execution".to_string(),
                serde_json::to_vec(&args).unwrap_or_else(|e| env::panic_str(&e.to_string())),
                deposit,
                EXECUTION_GAS,
                GasWeight(1),
            )
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(CALLBACK_GAS)
                    .with_unused_gas_weight(0)
                    .on_result(id, caller, U128(deposit.as_yoctonear())),
            )
    }

    #[private]
    pub fn on_result(&mut self, id: u32, caller: AccountId, deposit: U128) {
        let r = &mut self.records[id as usize];
        r.resolved_height = env::block_height();
        r.resolved_ns = env::block_timestamp();
        match env::promise_result(0) {
            PromiseResult::Successful(bytes) if bytes.is_empty() => r.kind = "ok-empty".into(),
            PromiseResult::Successful(bytes) => {
                r.kind = "ok".into();
                let text = String::from_utf8_lossy(&bytes).to_string();
                if let Some(v) = serde_json::from_slice::<Value>(&bytes).ok().and_then(|v| find_verdict(&v)) {
                    r.h_enc = v.get("h_enc").and_then(|x| x.as_str()).map(String::from);
                    r.broken = v.get("broken").and_then(|x| x.as_bool());
                }
                r.raw = Some(text.chars().take(MAX_RAW).collect());
            }
            PromiseResult::Failed => {
                r.kind = "err".into();
                env::log_str(&format!("probe: request {id} failed; {} yocto deposit returns to {caller}", deposit.0));
            }
        }
        env::log_str(&format!("probe: result {id} kind {} broken {:?}", r.kind, r.broken));
    }

    /// A `deliver`-shaped call: accepted only if sha256(enc) equals the attested `h_enc` of record `id`.
    pub fn deliver(&mut self, id: u32, enc: Base64VecU8) {
        let r = &mut self.records[id as usize];
        let want = r.h_enc.clone().unwrap_or_else(|| env::panic_str("no attested h_enc for this record"));
        let got: String = env::sha256(&enc.0).iter().map(|b| format!("{b:02x}")).collect();
        require!(got == want, "delivery mismatch: sha256(enc) != attested h_enc");
        r.delivered = true;
        env::log_str(&format!("probe: delivered {id} enc {} bytes sha256 {got}", enc.0.len()));
    }

    pub fn get_pin(&self) -> (String, String) {
        (self.wasm_url.clone(), self.wasm_hash.clone())
    }

    pub fn get_records(&self, from: Option<u32>) -> Vec<Record> {
        self.records.iter().skip(from.unwrap_or(0) as usize).cloned().collect()
    }

    /// Keeps the unused import honest on all paths.
    pub fn balance(&self) -> NearToken {
        env::account_balance()
    }
}
