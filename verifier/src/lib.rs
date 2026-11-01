//! Sealed verifier: runs a hunter's exploit against a committed EVM snapshot and asks the level's own
//! `validateInstance(instance, player)` whether the invariant broke. No Rust-side predicate, no RNG.

use std::collections::BTreeMap;

use revm::{
    context::{result::ExecutionResult, Context, TxEnv},
    handler::EthPrecompiles,
    precompile::Precompiles,
    database::{CacheDB, EmptyDB},
    primitives::{hardfork::SpecId, Address, Bytes, TxKind, U256},
    state::{AccountInfo, Bytecode},
    ExecuteCommitEvm, ExecuteEvm, MainBuilder, MainContext,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub mod seal;

/// Gas for ALL exploit txs together (each tx gets what is left). Frozen at day-0 G5b: the worst measured shape
/// (a KECCAK256 loop, ~787 wasm instructions per gas on the worker) keeps exploit + validate near 44% of its 2e9.
pub const EXPLOIT_GAS_BUDGET: u64 = 600_000;
/// Gas for the level's `validateInstance` call (it can reach hunter code, so it is bounded too).
pub const VALIDATE_GAS_LIMIT: u64 = 500_000;
/// Gas for building a snapshot (factory deploy + createInstance); never used on hunter input.
pub const SETUP_GAS_LIMIT: u64 = 30_000_000;
/// Max txs in one exploit.
pub const MAX_TXS: usize = 4;
/// Max total calldata across all txs.
pub const MAX_CALLDATA: usize = 24 * 1024;
/// `err` is capped so the verdict stays under OutLayer's 900 B NEAR-mode output limit.
pub const MAX_ERR: usize = 64;

/// Snapshots compiled into the verifier. Index = `target` in the input.
/// Order is frozen: a bounty pins `snapshot_hashes[target]`, so a new level is only ever appended.
pub const SNAPSHOTS: &[&[u8]] = &[
    include_bytes!("../snapshots/fallback.json"),   // 0 Fallback   (MVP)
    include_bytes!("../snapshots/telephone.json"),  // 1 Telephone  (MVP)
    include_bytes!("../snapshots/delegation.json"), // 2 Delegation (MVP)
    include_bytes!("../snapshots/force.json"),      // 3 Force      (stretch)
    include_bytes!("../snapshots/king.json"),       // 4 King       (stretch)
];

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SnapAccount {
    pub balance: String,
    pub nonce: u64,
    #[serde(default)]
    pub code: String,
    #[serde(default)]
    pub storage: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Snapshot {
    pub v: u32,
    pub name: String,
    pub chain_id: u64,
    pub block_number: u64,
    pub timestamp: u64,
    /// Ethernaut main contract stand-in: the caller of `validateInstance`.
    pub validator: String,
    pub factory: String,
    pub instance: String,
    pub player: String,
    pub accounts: BTreeMap<String, SnapAccount>,
}

/// Public input (`input_data`), built by the bounty contract.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Input {
    pub target: u8,
    pub invariant_id: String,
    pub hunter: String,
    pub commit_hash: String,
    pub protocol_enc_pk: String,
    /// Only read when the sealed env vars are absent (day-0 HTTPS runs without secrets). The bounty
    /// contract builds `input_data` itself and never sets this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secrets: Option<Secrets>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Secrets {
    #[serde(rename = "EXPLOIT")]
    pub exploit: String,
    #[serde(rename = "SALT")]
    pub salt: String,
    #[serde(rename = "EPH_SK")]
    pub eph_sk: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ExploitTx {
    pub to: Option<String>,
    #[serde(default)]
    pub data: String,
    #[serde(default)]
    pub value: String,
}

/// Resource limits the worker says it enforces, plus the verifier's own peak linear memory.
#[derive(Debug, Serialize, Clone, Default, PartialEq)]
pub struct Limits {
    pub i: Option<u64>,
    pub m: Option<u64>,
    pub s: Option<u64>,
    pub mem: Option<u64>,
}

#[derive(Debug, Serialize, Clone, PartialEq)]
pub struct Verdict {
    pub v: u32,
    pub broken: bool,
    pub invariant_id: String,
    pub h_exploit: String,
    pub h_snapshot: String,
    pub h_enc: String,
    pub gas_used: u64,
    pub err: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lim: Option<Limits>,
}

pub struct Run {
    pub verdict: Verdict,
    /// Sealed exploit for the protocol; the hunter rebuilds it locally and delivers it.
    pub enc: Vec<u8>,
}

fn cap(mut s: String) -> String {
    if s.len() > MAX_ERR {
        let mut n = MAX_ERR;
        while !s.is_char_boundary(n) {
            n -= 1;
        }
        s.truncate(n);
    }
    s
}

fn hex32(s: &str) -> Result<[u8; 32], String> {
    let b = hex::decode(s.trim_start_matches("0x")).map_err(|_| "bad hex".to_string())?;
    b.try_into().map_err(|_| "want 32 bytes".to_string())
}

fn u256(s: &str) -> Result<U256, String> {
    if s.is_empty() {
        return Ok(U256::ZERO);
    }
    let r = if let Some(h) = s.strip_prefix("0x") {
        U256::from_str_radix(h, 16)
    } else {
        U256::from_str_radix(s, 10)
    };
    r.map_err(|_| "bad uint".to_string())
}

fn addr(s: &str) -> Result<Address, String> {
    s.parse::<Address>().map_err(|_| "bad address".to_string())
}

pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

pub fn load_db(snap: &Snapshot) -> Result<CacheDB<EmptyDB>, String> {
    let mut db = CacheDB::new(EmptyDB::default());
    for (a, acc) in &snap.accounts {
        let address = addr(a)?;
        let code = hex::decode(acc.code.trim_start_matches("0x")).map_err(|_| "bad code hex")?;
        let mut info = AccountInfo {
            balance: u256(&acc.balance)?,
            nonce: acc.nonce,
            ..Default::default()
        };
        if !code.is_empty() {
            let bc = Bytecode::new_raw(Bytes::from(code));
            info.code_hash = bc.hash_slow();
            info.code = Some(bc);
        }
        db.insert_account_info(address, info);
        for (k, v) in &acc.storage {
            db.insert_account_storage(address, u256(k)?, u256(v)?)
                .map_err(|_| "storage insert")?;
        }
    }
    Ok(db)
}

type Evm = revm::handler::MainnetEvm<revm::handler::MainnetContext<CacheDB<EmptyDB>>>;

pub fn build_evm(snap: &Snapshot, db: CacheDB<EmptyDB>) -> Evm {
    let (chain_id, number, ts) = (snap.chain_id, snap.block_number, snap.timestamp);
    Context::mainnet()
        .modify_cfg_chained(|cfg| {
            cfg.set_spec_and_mainnet_gas_params(SpecId::CANCUN);
            cfg.chain_id = chain_id;
            cfg.disable_nonce_check = true;
            cfg.tx_chain_id_check = false;
        })
        .modify_block_chained(|b| {
            b.number = U256::from(number);
            b.timestamp = U256::from(ts);
            b.basefee = 0;
            b.gas_limit = u64::MAX;
        })
        .with_db(db)
        .build_mainnet()
        .with_precompiles(EthPrecompiles { precompiles: no_precompiles(), spec: SpecId::CANCUN })
}

/// The verifier EVM has NO precompiles: no kept level needs one, and some (BLAKE2F at 1 gas per round, MODEXP,
/// the bn254 pairing) cost far more wasm work per gas than any opcode, which would break the G5b bound.
/// Their addresses behave as empty accounts.
fn no_precompiles() -> &'static Precompiles {
    static NONE: std::sync::OnceLock<Precompiles> = std::sync::OnceLock::new();
    NONE.get_or_init(Precompiles::default)
}

/// `validateInstance(address,address)` selector.
pub const VALIDATE_SELECTOR: [u8; 4] = [0xd3, 0x8d, 0xef, 0x5b];

pub fn validate_calldata(instance: Address, player: Address) -> Bytes {
    let mut d = Vec::with_capacity(68);
    d.extend_from_slice(&VALIDATE_SELECTOR);
    d.extend_from_slice(&[0u8; 12]);
    d.extend_from_slice(instance.as_slice());
    d.extend_from_slice(&[0u8; 12]);
    d.extend_from_slice(player.as_slice());
    Bytes::from(d)
}

pub fn tx(caller: Address, kind: TxKind, data: Bytes, value: U256, gas_limit: u64) -> TxEnv {
    TxEnv::builder()
        .caller(caller)
        .kind(kind)
        .data(data)
        .value(value)
        .gas_limit(gas_limit)
        .gas_price(0)
        .build_fill()
}

/// Parse the exploit; any shape error is `exploit invalid` (a normal verdict, never a verifier error).
pub fn parse_exploit(bytes: &[u8]) -> Result<Vec<(Option<Address>, Bytes, U256)>, String> {
    let txs: Vec<ExploitTx> = serde_json::from_slice(bytes).map_err(|_| "exploit invalid: json")?;
    if txs.len() > MAX_TXS {
        return Err("exploit invalid: too many txs".into());
    }
    let mut out = Vec::new();
    let mut total = 0usize;
    for t in txs {
        let to = match &t.to {
            Some(s) => Some(addr(s).map_err(|_| "exploit invalid: to")?),
            None => None,
        };
        let data = hex::decode(t.data.trim_start_matches("0x")).map_err(|_| "exploit invalid: data")?;
        total += data.len();
        if total > MAX_CALLDATA {
            return Err("exploit invalid: calldata too large".into());
        }
        let value = u256(&t.value).map_err(|_| "exploit invalid: value")?;
        out.push((to, Bytes::from(data), value));
    }
    Ok(out)
}

fn trace(f: impl FnOnce() -> String) {
    if std::env::var_os("SEALED_TRACE").is_some() {
        eprintln!("trace: {}", f());
    }
}

fn outcome<H: core::fmt::Debug>(r: &ExecutionResult<H>) -> String {
    match r {
        ExecutionResult::Success { output, .. } => format!("success 0x{}", hex::encode(output.data())),
        ExecutionResult::Revert { output, .. } => format!("revert 0x{}", hex::encode(output)),
        ExecutionResult::Halt { reason, .. } => format!("halt {reason:?}"),
    }
}

/// Run every exploit tx from the player, then call the level's own `validateInstance` from the validator.
/// Returns (broken, gas_used, err).
pub fn execute(snap: &Snapshot, exploit_bytes: &[u8]) -> Result<(bool, u64, Option<String>), String> {
    let player = addr(&snap.player)?;
    let instance = addr(&snap.instance)?;
    let factory = addr(&snap.factory)?;
    let validator = addr(&snap.validator)?;
    let db = load_db(snap)?;
    let mut evm = build_evm(snap, db);

    let txs = match parse_exploit(exploit_bytes) {
        Ok(t) => t,
        Err(e) => return Ok((false, 0, Some(e))),
    };
    let mut gas = 0u64;
    for (to, data, value) in txs {
        let left = EXPLOIT_GAS_BUDGET - gas;
        let kind = match to {
            Some(a) => TxKind::Call(a),
            None => TxKind::Create,
        };
        // A tx whose intrinsic gas exceeds what is left is invalid and simply does not happen.
        match evm.transact_commit(tx(player, kind, data, value, left)) {
            // Revert / halt / out-of-gas are normal EVM outcomes.
            Ok(r) => {
                trace(|| format!("tx {kind:?} -> {}", outcome(&r)));
                gas = gas.saturating_add(r.tx_gas_used()).min(EXPLOIT_GAS_BUDGET)
            }
            // Invalid tx (e.g. value above the player's balance): the tx simply does not happen.
            Err(e) => trace(|| format!("tx {kind:?} -> invalid {e:?}")),
        }
    }
    let r = evm
        .transact(tx(validator, TxKind::Call(factory), validate_calldata(instance, player), U256::ZERO, VALIDATE_GAS_LIMIT))
        .map_err(|e| format!("validate failed: {e:?}"))?;
    trace(|| {
        format!("call validateInstance({instance:#x},{player:#x}) from {validator:#x} on factory {factory:#x} -> {}", outcome(&r.result))
    });
    let broken = match r.result {
        ExecutionResult::Success { output, .. } => {
            let o = output.data();
            o.len() == 32 && o[31] == 1 && o[..31].iter().all(|b| *b == 0)
        }
        _ => false,
    };
    Ok((broken, gas, None))
}

/// The whole verdict for one input. `exploit_bytes` is the exact `EXPLOIT` secret value.
pub fn run(input: &Input, secrets: &Secrets, lim: Option<Limits>) -> Result<Run, String> {
    let snap_bytes = *SNAPSHOTS.get(input.target as usize).ok_or("unknown target")?;
    let h_snapshot = sha256(&[snap_bytes]);
    let snap: Snapshot = serde_json::from_slice(snap_bytes).map_err(|_| "bad snapshot")?;
    let exploit_bytes = secrets.exploit.as_bytes();
    let salt = hex32(&secrets.salt).map_err(|e| format!("SALT: {e}"))?;
    let eph_sk = hex32(&secrets.eph_sk).map_err(|e| format!("EPH_SK: {e}"))?;
    let pk = hex32(&input.protocol_enc_pk).map_err(|e| format!("protocol_enc_pk: {e}"))?;

    let h_exploit = sha256(&[exploit_bytes, input.hunter.as_bytes(), &salt]);
    let (broken, gas_used, err) = execute(&snap, exploit_bytes)?;
    let enc = seal::seal(exploit_bytes, &salt, &input.hunter, &pk, &eph_sk)?;
    let h_enc = sha256(&[&enc]);
    Ok(Run {
        verdict: Verdict {
            v: 1,
            broken,
            invariant_id: cap(input.invariant_id.clone()),
            h_exploit: hex::encode(h_exploit),
            h_snapshot: hex::encode(h_snapshot),
            h_enc: hex::encode(h_enc),
            gas_used,
            err: err.map(cap),
            lim,
        },
        enc,
    })
}

/// Verdict for a run the verifier could not complete (bad input, missing secret): `broken:false` + `err`.
pub fn error_verdict(invariant_id: &str, err: String, lim: Option<Limits>) -> Verdict {
    Verdict {
        v: 1,
        broken: false,
        invariant_id: cap(invariant_id.to_string()),
        h_exploit: String::new(),
        h_snapshot: String::new(),
        h_enc: String::new(),
        gas_used: 0,
        err: Some(cap(err)),
        lim,
    }
}
