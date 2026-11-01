//! Sealed Exploit — the bounty contract.
//!
//! A keyless escrow over a NEP-141 pool. A hunter who can break one of the bounty's committed invariants
//! (each an Ethernaut level's own `validateInstance`, run inside an OutLayer TDX worker on the pinned
//! verifier) gets paid — but the sealed exploit becomes public only in the `deliver` that makes the escrow
//! irrevocably owed. The contract never holds the exploit before the money is owed, and no key can move a
//! reserved payout.
//!
//! State machine per invariant: `Open → Pending(c) → Awarded(c) → Delivered(c) → Paid(c)`, with refusals
//! returning it to `Open`. The whole claim-to-pay flow and every refusal are documented in
//! `ARCHITECTURE.md` at the repo root (§Commit to payout, §Refusals, §Invariants I1–I8). Every refusal is a
//! successful tx with a log, never a panic (panics are reserved for malformed arguments).

use near_sdk::borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::collections::{LookupMap, Vector};
use near_sdk::json_types::{U128, U64};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::serde_json::{self, json, Value};
use near_sdk::{
    env, near, require, AccountId, Gas, GasWeight, NearToken, PanicOnDefault, Promise, PromiseError,
    PromiseResult,
};

/// Gas handed to `request_execution` (the worker run + its internal yield). 100 Tgas, as the OutLayer
/// contract example attaches (`day0/results` were produced at 300 Tgas prepaid on `commit`).
const EXECUTION_GAS: Gas = Gas::from_tgas(100);
/// Gas reserved for each settlement callback. Measured against the sandbox worst case (D2).
const CB_GAS: Gas = Gas::from_tgas(40);
/// Gas for the token registration check and its callback.
const REG_GAS: Gas = Gas::from_tgas(15);
/// Gas for an `ft_transfer` and `on_paid`.
const FT_GAS: Gas = Gas::from_tgas(20);
/// One infra refund per `(hunter, invariant)` per this window; a repeat inside it is slashed.
const INFRA_REFUND_WINDOW_NS: u64 = 24 * 3_600_000_000_000;
/// A no-verdict arriving at least this long after the request never counts toward the infra-refund cap.
const LATE_NOVERDICT_NS: u64 = 10 * 60_000_000_000;
/// `release_stale` floor; the request→callback p99 margin is folded in by the deployer via `stale_after_ns`.
const RELEASE_STALE_FLOOR_NS: u64 = 30 * 60_000_000_000;
/// A matching `deliver` pays the hunter this NEP-141 amount note (1 yoctoNEAR is attached to `ft_transfer`).
const ONE_YOCTO: NearToken = NearToken::from_yoctonear(1);

#[near(serializers = [borsh, json])]
#[derive(Clone, PartialEq)]
pub enum InvState {
    Open,
    Pending(u64),
    Awarded(u64),
    Delivered(u64),
    Paid(u64),
}

#[near(serializers = [borsh, json])]
#[derive(Clone, PartialEq)]
pub enum CommitStatus {
    AwaitingRegistration,
    Pending,
    Awarded,
    Delivered,
    Paid,
    Refused(String),
    Voided,
}

#[near(serializers = [borsh, json])]
#[derive(Clone)]
pub struct Invariant {
    pub id: String,
    pub target: u8,
    pub amount: U128,
    pub bond: NearToken,
    pub state: InvState,
}

#[near(serializers = [borsh, json])]
#[derive(Clone)]
pub struct Commit {
    pub hunter: AccountId,
    pub commit_hash: String,
    pub invariant_id: String,
    pub payout_to: AccountId,
    pub secrets_profile: String,
    pub at_ns: u64,
    pub bond: NearToken,
    pub deposit: NearToken,
    pub h_enc: Option<String>,
    pub deliver_by_ns: Option<u64>,
    pub paying: bool,
    pub status: CommitStatus,
}

/// `create_bounty` config, recorded once; no method changes it later.
#[derive(Deserialize, Serialize, Clone)]
#[serde(crate = "near_sdk::serde")]
pub struct Config {
    pub protocol: AccountId,
    pub protocol_enc_pk: String,
    pub token: AccountId,
    pub outlayer: AccountId,
    pub verifier_wasm_hash: String,
    pub verifier_wasm_url: String,
    pub snapshot_hashes: Vec<String>,
    pub invariants: Vec<InvariantCfg>,
    pub bond_floor: NearToken,
    pub outlayer_deposit: NearToken,
    pub deliver_ttl_ns: u64,
    pub timelock_ns: u64,
    pub max_instructions: u64,
    pub max_memory_mb: u32,
    pub max_execution_seconds: u64,
    pub stale_after_ns: u64,
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(crate = "near_sdk::serde")]
pub struct InvariantCfg {
    pub id: String,
    pub target: u8,
    pub amount: U128,
    pub bond: NearToken,
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Bounty {
    protocol: AccountId,
    protocol_enc_pk: String,
    token: AccountId,
    outlayer: AccountId,
    verifier_wasm_hash: String,
    verifier_wasm_url: String,
    snapshot_hashes: Vec<String>,
    invariants: Vec<Invariant>,
    bond_floor: NearToken,
    outlayer_deposit: NearToken,
    deliver_ttl_ns: u64,
    timelock_ns: u64,
    stale_after_ns: u64,
    max_instructions: u64,
    max_memory_mb: u32,
    max_execution_seconds: u64,
    created_at_ns: u64,
    pool: u128,
    reserved: u128,
    escrow: u128,
    paid_total: u128,
    funded_total: u128,
    withdrawn_total: u128,
    bonds_held: u128,
    slashed: u128,
    infra_refunds: LookupMap<String, u64>,
    commits: Vector<Commit>,
}

fn now() -> u64 {
    env::block_timestamp()
}

fn refund_key(hunter: &AccountId, invariant_id: &str) -> String {
    format!("{hunter}|{invariant_id}")
}

#[near]
impl Bounty {
    #[init]
    pub fn new(cfg: Config) -> Self {
        require!(cfg.snapshot_hashes.len() >= 1, "at least one snapshot");
        require!(!cfg.invariants.is_empty(), "at least one invariant");
        require!(
            cfg.protocol_enc_pk.len() == 64 && cfg.verifier_wasm_hash.len() == 64,
            "enc pk and wasm hash are 32-byte hex"
        );
        for inv in &cfg.invariants {
            require!(inv.bond >= cfg.bond_floor, "a bond is below the floor");
            require!((inv.target as usize) < cfg.snapshot_hashes.len(), "target has no snapshot");
        }
        let invariants = cfg
            .invariants
            .iter()
            .map(|c| Invariant {
                id: c.id.clone(),
                target: c.target,
                amount: c.amount,
                bond: c.bond,
                state: InvState::Open,
            })
            .collect();
        Self {
            protocol: cfg.protocol,
            protocol_enc_pk: cfg.protocol_enc_pk,
            token: cfg.token,
            outlayer: cfg.outlayer,
            verifier_wasm_hash: cfg.verifier_wasm_hash,
            verifier_wasm_url: cfg.verifier_wasm_url,
            snapshot_hashes: cfg.snapshot_hashes,
            invariants,
            bond_floor: cfg.bond_floor,
            outlayer_deposit: cfg.outlayer_deposit,
            deliver_ttl_ns: cfg.deliver_ttl_ns,
            timelock_ns: cfg.timelock_ns,
            stale_after_ns: cfg.stale_after_ns.max(RELEASE_STALE_FLOOR_NS),
            max_instructions: cfg.max_instructions,
            max_memory_mb: cfg.max_memory_mb,
            max_execution_seconds: cfg.max_execution_seconds,
            created_at_ns: now(),
            pool: 0,
            reserved: 0,
            escrow: 0,
            paid_total: 0,
            funded_total: 0,
            withdrawn_total: 0,
            bonds_held: 0,
            slashed: 0,
            infra_refunds: LookupMap::new(b"r".to_vec()),
            commits: Vector::new(b"c".to_vec()),
        }
    }

    // ----- funding (NEP-141 ft_transfer_call) -----

    /// The protocol funds the USDC pool. Any `ft_transfer_call` to this bounty from its token adds to the
    /// pool; nothing else is accepted (unknown tokens are refunded by returning the full amount).
    pub fn ft_on_transfer(&mut self, sender_id: AccountId, amount: U128, msg: String) -> U128 {
        let _ = msg;
        if env::predecessor_account_id() != self.token {
            env::log_str("REFUSED: wrong token");
            return amount; // refund everything
        }
        self.pool += amount.0;
        self.funded_total += amount.0;
        env::log_str(&format!("FUNDED {} by {sender_id}; pool {}", amount.0, self.pool));
        U128(0)
    }

    // ----- commit (= the verification request) -----

    /// `commit` IS the verification request: there is no separate public `claim`. Attach `bond + outlayer
    /// deposit` in NEAR. Guards refuse (success + log, full refund) a low bond, a busy/paid invariant, or a
    /// pool that cannot cover the amount once `reserved` is subtracted; otherwise the amount is reserved in
    /// the same call and the token registration of `payout_to` is checked before any worker run.
    #[payable]
    pub fn commit(&mut self, commit_hash: String, invariant_id: String, payout_to: AccountId) {
        let hunter = env::predecessor_account_id();
        let attached = env::attached_deposit();
        let idx = match self.invariants.iter().position(|i| i.id == invariant_id) {
            Some(i) => i,
            None => env::panic_str("unknown invariant"),
        };
        require!(commit_hash.len() == 64 && commit_hash.bytes().all(|b| b.is_ascii_hexdigit()), "commit_hash is 32-byte hex");
        let inv = self.invariants[idx].clone();
        let min = inv.bond.saturating_add(self.outlayer_deposit);

        // Guard refusals: log, refund everything, reserve nothing. A Pending invariant is "claim pending";
        // an Awarded/Delivered/Paid one is "invariant already paid".
        let why = if attached < min {
            Some("bond")
        } else if matches!(inv.state, InvState::Pending(_)) {
            Some("claim pending")
        } else if !matches!(inv.state, InvState::Open) {
            Some("invariant already paid")
        } else if self.pool.saturating_sub(self.reserved) < inv.amount.0 {
            Some("pool short")
        } else {
            None
        };
        if let Some(why) = why {
            env::log_str(&format!("REFUSED: {why}"));
            if attached.as_yoctonear() > 0 {
                Promise::new(hunter).transfer(attached);
            }
            return;
        }

        let bond = inv.bond;
        let deposit = attached.saturating_sub(bond); // ≥ outlayer_deposit by the `min` guard
        let commit_id = self.commits.len();
        // Profile the hunter used in `store_secrets` BEFORE this call — derived from the commit hash it
        // already knows, never the commit index (which it cannot predict and which races concurrently).
        let secrets_profile = format!("c-{}", &commit_hash[..8]);
        self.commits.push(&Commit {
            hunter: hunter.clone(),
            commit_hash,
            invariant_id: invariant_id.clone(),
            payout_to: payout_to.clone(),
            secrets_profile,
            at_ns: now(),
            bond,
            deposit,
            h_enc: None,
            deliver_by_ns: None,
            paying: false,
            status: CommitStatus::AwaitingRegistration,
        });
        // Reserve the payout now, so no withdrawal can land between commit and callback. The invariant
        // stays Open — no slot is taken until a verdict request is actually emitted.
        self.reserved += inv.amount.0;
        self.bonds_held += bond.as_yoctonear();
        env::log_str(&format!("COMMIT {commit_id} {invariant_id} by {hunter}; reserved {}", self.reserved));

        Promise::new(self.token.clone())
            .function_call(
                "storage_balance_of".to_string(),
                json!({ "account_id": payout_to }).to_string().into_bytes(),
                NearToken::from_yoctonear(0),
                REG_GAS,
            )
            .then(Self::ext(env::current_account_id()).with_static_gas(REG_GAS).on_payout_checked(commit_id));
    }

    #[private]
    pub fn on_payout_checked(&mut self, commit_id: u64, #[callback_result] reg: Result<Option<Value>, PromiseError>) {
        let mut c = self.commits.get(commit_id).expect("commit");
        if c.status != CommitStatus::AwaitingRegistration {
            env::log_str(&format!("on_payout_checked {commit_id}: not awaiting ({:?}); no-op", status_tag(&c.status)));
            return;
        }
        let idx = self.inv_index(&c.invariant_id);
        // Another commit may have taken the slot while we were checking registration.
        match &self.invariants[idx].state {
            InvState::Pending(_) => return self.refund_commit(commit_id, &mut c, "claim pending"),
            InvState::Awarded(_) | InvState::Delivered(_) | InvState::Paid(_) => {
                return self.refund_commit(commit_id, &mut c, "invariant already paid")
            }
            InvState::Open => {}
        }
        match reg {
            Ok(Some(_balance)) => {
                // Registered: take the slot, carry the reservation, emit the worker run.
                self.invariants[idx].state = InvState::Pending(commit_id);
                c.status = CommitStatus::Pending;
                self.commits.replace(commit_id, &c);
                env::log_str(&format!("PENDING {commit_id} {}", c.invariant_id));
                let args = self.request_args(&c);
                Promise::new(self.outlayer.clone())
                    .function_call("request_execution".to_string(), args, c.deposit, EXECUTION_GAS)
                    .then(Self::ext(env::current_account_id()).with_static_gas(CB_GAS).on_verdict(commit_id));
            }
            Ok(None) => self.refund_commit(commit_id, &mut c, "payout_to not registered"),
            Err(_) => self.refund_commit(commit_id, &mut c, "registration check unavailable"),
        }
    }

    #[private]
    pub fn on_verdict(&mut self, commit_id: u64) {
        let mut c = self.commits.get(commit_id).expect("commit");
        if c.status != CommitStatus::Pending {
            env::log_str(&format!("on_verdict {commit_id}: not pending ({}); no-op", status_tag(&c.status)));
            return;
        }
        let idx = self.inv_index(&c.invariant_id);
        // The worker ran only when a real verdict comes back. A `Failed` promise means `request_execution`
        // itself failed (the deposit bounced to this account, never reaching a worker) — refund it too.
        let bytes = match env::promise_result(0) {
            PromiseResult::Successful(b) => b,
            PromiseResult::Failed => return self.no_verdict(commit_id, &mut c, idx, true),
        };
        // Every non-verdict (worker-answered failure, yield timeout, stale run) arrives as a SUCCESSFUL
        // promise whose bytes are JSON `null` (OutLayer `on_execution_response`). One rule for all of them.
        let verdict: Option<Value> = serde_json::from_slice::<Value>(&bytes).ok().and_then(find_verdict);
        let v = match verdict {
            Some(v) => v,
            None => return self.no_verdict(commit_id, &mut c, idx, false),
        };

        let inv = self.invariants[idx].clone();
        let broken = v.get("broken").and_then(|x| x.as_bool()).unwrap_or(false);
        let h_exploit = v.get("h_exploit").and_then(|x| x.as_str()).unwrap_or("");
        let h_snapshot = v.get("h_snapshot").and_then(|x| x.as_str()).unwrap_or("");
        let v_inv = v.get("invariant_id").and_then(|x| x.as_str()).unwrap_or("");
        let h_enc = v.get("h_enc").and_then(|x| x.as_str()).unwrap_or("");
        let err = v.get("err").and_then(|x| x.as_str());
        let want_snap = &self.snapshot_hashes[inv.target as usize];
        let h_enc_ok = h_enc.len() == 64 && h_enc.bytes().all(|b| b.is_ascii_hexdigit());

        // Hunter-caused refusals (I7 binding): slash the bond; the worker ran, so the OutLayer deposit is gone.
        let reason: Option<String> = if !broken {
            // The verifier already phrases decode/secret faults (e.g. "exploit invalid: too many txs",
            // "secret missing"); surface its `err` verbatim, or "no invariant broken" for a clean no-break.
            Some(err.map(|e| e.to_string()).unwrap_or_else(|| "no invariant broken".into()))
        } else if h_exploit != c.commit_hash {
            Some("commit mismatch".into())
        } else if v_inv != c.invariant_id {
            Some("wrong invariant".into())
        } else if h_snapshot != want_snap.as_str() {
            Some("snapshot mismatch".into())
        } else if !h_enc_ok {
            // A broken-but-malformed verdict (no valid h_enc) could never be delivered; reject it as a fault
            // rather than awarding an undeliverable escrow that only `expire` could clear.
            Some("malformed h_enc".into())
        } else {
            None
        };
        if let Some(why) = reason {
            self.reserved -= inv.amount.0;
            self.slash(&mut c);
            self.invariants[idx].state = InvState::Open;
            c.status = CommitStatus::Refused(why.clone());
            self.commits.replace(commit_id, &c);
            env::log_str(&format!("REFUSED {commit_id} {why}"));
            return;
        }

        // AWARDED: reserved → escrow, h_enc stored, deliver window opened. The exploit is still sealed.
        // `pool` holds `reserved` until award, so the amount leaves `pool` as it enters `escrow`.
        self.reserved -= inv.amount.0;
        self.pool -= inv.amount.0;
        self.escrow += inv.amount.0;
        c.h_enc = Some(h_enc.to_string());
        c.deliver_by_ns = Some(now() + self.deliver_ttl_ns);
        c.status = CommitStatus::Awarded;
        self.invariants[idx].state = InvState::Awarded(commit_id);
        self.commits.replace(commit_id, &c);
        env::log_str(&format!("AWARDED {commit_id} {} amount {} h_enc {h_enc}", c.invariant_id, inv.amount.0));
    }

    /// `verifier unavailable`: refund the bond once per `(hunter, invariant)` per 24 h, else slash. A
    /// no-verdict arriving ≥ 10 min after the commit refunds in full and never counts toward the cap.
    /// `deposit_bounced` = the `request_execution` promise itself failed, so the OutLayer deposit came back
    /// to this account (no worker ran) and is refunded alongside the bond.
    fn no_verdict(&mut self, commit_id: u64, c: &mut Commit, idx: usize, deposit_bounced: bool) {
        let amount = self.invariants[idx].amount.0;
        self.reserved -= amount;
        self.reopen(idx, commit_id);
        let late = now().saturating_sub(c.at_ns) >= LATE_NOVERDICT_NS;
        let key = refund_key(&c.hunter, &c.invariant_id);
        let last = self.infra_refunds.get(&key);
        let within = last.map(|t| now().saturating_sub(t) < INFRA_REFUND_WINDOW_NS).unwrap_or(false);
        if late || !within {
            if !late {
                self.infra_refunds.insert(&key, &now());
            }
            self.return_bond(c);
            c.status = CommitStatus::Refused("verifier unavailable".into());
            env::log_str(&format!("REFUSED {commit_id} verifier unavailable (bond returned)"));
        } else {
            self.slash(c);
            c.status = CommitStatus::Refused("verifier unavailable".into());
            env::log_str(&format!("REFUSED {commit_id} verifier unavailable (repeat within 24h: slashed)"));
        }
        if deposit_bounced && c.deposit.as_yoctonear() > 0 {
            Promise::new(c.hunter.clone()).transfer(c.deposit);
        }
        self.commits.replace(commit_id, c);
    }

    /// Reopen an invariant only if THIS commit still holds its slot, so a no-verdict/stale on one commit can
    /// never clobber another commit's Pending/Awarded state on the same invariant.
    fn reopen(&mut self, idx: usize, commit_id: u64) {
        if matches!(self.invariants[idx].state, InvState::Pending(id) if id == commit_id) {
            self.invariants[idx].state = InvState::Open;
        }
    }

    /// Anyone, after `stale_after_ns`: unstick a stuck commit. Bond back (+ deposit if never sent); uncounted.
    pub fn release_stale(&mut self, commit_id: u64) {
        let mut c = self.commits.get(commit_id).expect("commit");
        require!(now().saturating_sub(c.at_ns) >= self.stale_after_ns, "not stale yet");
        let idx = self.inv_index(&c.invariant_id);
        match c.status {
            CommitStatus::AwaitingRegistration => {
                self.refund_commit(commit_id, &mut c, "registration check unavailable");
            }
            CommitStatus::Pending => {
                self.reserved -= self.invariants[idx].amount.0;
                self.reopen(idx, commit_id);
                self.return_bond(&mut c);
                c.status = CommitStatus::Refused("verifier unavailable".into());
                self.commits.replace(commit_id, &c);
                env::log_str(&format!("RELEASE_STALE {commit_id} (full refund, uncounted)"));
            }
            _ => env::panic_str("commit is not stuck"),
        }
    }

    // ----- deliver / pay -----

    /// A matching `deliver` makes the escrow irrevocably owed in the same receipt (`paying` set), then pays.
    /// The protocol reads `enc` from this tx's public args; it is neither stored nor logged.
    pub fn deliver(&mut self, commit_id: u64, enc: near_sdk::json_types::Base64VecU8) {
        let mut c = self.commits.get(commit_id).expect("commit");
        require!(c.status == CommitStatus::Awarded, "commit is not awarded");
        require!(env::predecessor_account_id() == c.hunter, "only the hunter may deliver");
        let want = c.h_enc.clone().expect("awarded commit has h_enc");
        // delivery expired / delivery mismatch are on-chain refusal kinds: success + log, no state change.
        if now() > c.deliver_by_ns.expect("awarded commit has deliver_by") {
            return env::log_str(&format!("REFUSED {commit_id} delivery expired"));
        }
        let got = hex::encode(env::sha256(&enc.0));
        if got != want {
            return env::log_str(&format!("REFUSED {commit_id} delivery mismatch"));
        }
        let idx = self.inv_index(&c.invariant_id);
        c.status = CommitStatus::Delivered;
        c.paying = true;
        self.invariants[idx].state = InvState::Delivered(commit_id);
        self.commits.replace(commit_id, &c);
        env::log_str(&format!("DELIVERED {commit_id} {want}"));
        self.send_payout(commit_id, &c);
    }

    #[private]
    pub fn on_paid(&mut self, commit_id: u64, amount: U128, #[callback_result] res: Result<(), PromiseError>) {
        let mut c = self.commits.get(commit_id).expect("commit");
        c.paying = false;
        let idx = self.inv_index(&c.invariant_id);
        if res.is_ok() {
            self.escrow -= amount.0;
            self.paid_total += amount.0;
            c.status = CommitStatus::Paid;
            self.invariants[idx].state = InvState::Paid(commit_id);
            self.return_bond(&mut c);
            env::log_str(&format!("PAID {commit_id} {}", amount.0));
        } else {
            // Stays Delivered; the escrow is kept for this hunter and can be retried to payout_to.
            env::log_str(&format!("PAYOUT FAILED {commit_id}; escrow kept, retry to {}", c.payout_to));
        }
        self.commits.replace(commit_id, &c);
    }

    /// Anyone may retry a stuck payout to the committed `payout_to`; only the hunter may redirect it.
    pub fn retry_payout(&mut self, commit_id: u64, new_payout_to: Option<AccountId>) {
        let mut c = self.commits.get(commit_id).expect("commit");
        require!(c.status == CommitStatus::Delivered, "commit is not awaiting payout");
        require!(!c.paying, "a transfer is already in flight");
        if let Some(to) = new_payout_to {
            require!(env::predecessor_account_id() == c.hunter, "only the hunter may redirect");
            c.payout_to = to;
        }
        c.paying = true;
        self.commits.replace(commit_id, &c);
        self.send_payout(commit_id, &c);
    }

    // ----- expire / withdraw -----

    /// Anyone: an Awarded commit past `deliver_by` is voided (Delivered never expires). Escrow → pool, slash.
    pub fn expire(&mut self, commit_id: u64) {
        let mut c = self.commits.get(commit_id).expect("commit");
        require!(c.status == CommitStatus::Awarded, "commit is not awarded");
        require!(now() > c.deliver_by_ns.expect("deliver_by"), "not expired yet");
        let idx = self.inv_index(&c.invariant_id);
        let amount = self.invariants[idx].amount.0;
        self.escrow -= amount;
        self.pool += amount;
        self.slash(&mut c);
        self.invariants[idx].state = InvState::Open;
        c.status = CommitStatus::Voided;
        self.commits.replace(commit_id, &c);
        env::log_str(&format!("EXPIRED {commit_id}; escrow {amount} back to pool, bond slashed"));
    }

    /// Protocol only: withdraw unencumbered USDC after the timelock. Reserved and escrowed USDC never move.
    pub fn withdraw_pool(&mut self, amount: U128) -> bool {
        require!(env::predecessor_account_id() == self.protocol, "protocol only");
        if amount.0 > self.pool.saturating_sub(self.reserved) {
            env::log_str("REFUSED: claim pending");
            return false;
        }
        if now() < self.created_at_ns + self.timelock_ns {
            env::log_str("REFUSED: timelock");
            return false;
        }
        self.pool -= amount.0;
        self.withdrawn_total += amount.0;
        Promise::new(self.token.clone())
            .function_call(
                "ft_transfer".to_string(),
                json!({ "receiver_id": self.protocol, "amount": amount }).to_string().into_bytes(),
                ONE_YOCTO,
                FT_GAS,
            )
            .then(Self::ext(env::current_account_id()).with_static_gas(FT_GAS).on_withdrawn(amount));
        env::log_str(&format!("WITHDRAW_POOL {}", amount.0));
        true
    }

    /// Restore the ledger if the withdrawal transfer failed (protocol unregistered / blacklisted), so the
    /// USDC is never counted as withdrawn while it is still in the token account (I1).
    #[private]
    pub fn on_withdrawn(&mut self, amount: U128, #[callback_result] res: Result<(), PromiseError>) {
        if res.is_err() {
            self.pool += amount.0;
            self.withdrawn_total -= amount.0;
            env::log_str(&format!("WITHDRAW_POOL FAILED {}; pool restored", amount.0));
        }
    }

    /// Protocol only: sweep the slashed NEAR ledger. Never frozen — it does not touch the hunter-facing pool.
    pub fn withdraw_slashed(&mut self) {
        require!(env::predecessor_account_id() == self.protocol, "protocol only");
        let amount = self.slashed;
        require!(amount > 0, "nothing slashed");
        self.slashed = 0;
        Promise::new(self.protocol.clone()).transfer(NearToken::from_yoctonear(amount));
        env::log_str(&format!("WITHDRAW_SLASHED {amount}"));
    }

    // ----- helpers -----

    fn inv_index(&self, id: &str) -> usize {
        self.invariants.iter().position(|i| i.id == id).expect("invariant")
    }

    /// Release a commit's reservation and refund bond + OutLayer deposit (no worker run happened).
    fn refund_commit(&mut self, commit_id: u64, c: &mut Commit, why: &str) {
        let idx = self.inv_index(&c.invariant_id);
        if matches!(self.invariants[idx].state, InvState::Pending(id) if id == commit_id) {
            self.invariants[idx].state = InvState::Open;
        }
        self.reserved -= self.invariants[idx].amount.0;
        self.bonds_held -= c.bond.as_yoctonear();
        c.status = CommitStatus::Refused(why.into());
        self.commits.replace(commit_id, c);
        let back = c.bond.saturating_add(c.deposit);
        if back.as_yoctonear() > 0 {
            Promise::new(c.hunter.clone()).transfer(back);
        }
        env::log_str(&format!("REFUSED {commit_id} {why} (bond + deposit returned)"));
    }

    /// Slash this commit's bond into the NEAR `slashed` ledger (the OutLayer deposit is already spent).
    fn slash(&mut self, c: &mut Commit) {
        self.bonds_held -= c.bond.as_yoctonear();
        self.slashed += c.bond.as_yoctonear();
    }

    /// Return this commit's bond to the hunter from the NEAR ledger.
    fn return_bond(&mut self, c: &mut Commit) {
        self.bonds_held -= c.bond.as_yoctonear();
        if c.bond.as_yoctonear() > 0 {
            Promise::new(c.hunter.clone()).transfer(c.bond);
        }
    }

    fn send_payout(&mut self, commit_id: u64, c: &Commit) {
        let idx = self.inv_index(&c.invariant_id);
        let amount = self.invariants[idx].amount;
        Promise::new(self.token.clone())
            .function_call(
                "ft_transfer".to_string(),
                json!({ "receiver_id": c.payout_to, "amount": amount }).to_string().into_bytes(),
                ONE_YOCTO,
                FT_GAS,
            )
            .then(Self::ext(env::current_account_id()).with_static_gas(FT_GAS).on_paid(commit_id, amount));
    }

    fn request_args(&self, c: &Commit) -> Vec<u8> {
        let input = json!({
            "target": self.invariants[self.inv_index(&c.invariant_id)].target,
            "invariant_id": c.invariant_id,
            "hunter": c.hunter,
            "commit_hash": c.commit_hash,
            "protocol_enc_pk": self.protocol_enc_pk,
        })
        .to_string();
        json!({
            "source": {"WasmUrl": {"url": self.verifier_wasm_url, "hash": self.verifier_wasm_hash, "build_target": "wasm32-wasip1"}},
            "resource_limits": {"max_instructions": self.max_instructions, "max_memory_mb": self.max_memory_mb, "max_execution_seconds": self.max_execution_seconds},
            "input_data": input,
            "secrets_ref": {"profile": c.secrets_profile, "account_id": c.hunter},
            "response_format": "Text",
            "payer_account_id": c.hunter,
        })
        .to_string()
        .into_bytes()
    }

    // ----- views -----

    pub fn view_state(&self) -> Value {
        json!({
            "protocol": self.protocol,
            "token": self.token,
            "pool": U128(self.pool),
            "reserved": U128(self.reserved),
            "escrow": U128(self.escrow),
            "paid_total": U128(self.paid_total),
            "funded_total": U128(self.funded_total),
            "withdrawn_total": U128(self.withdrawn_total),
            "bonds_held": U128(self.bonds_held),
            "slashed": U128(self.slashed),
            "verifier_wasm_hash": self.verifier_wasm_hash,
            "verifier_wasm_url": self.verifier_wasm_url,
            "protocol_enc_pk": self.protocol_enc_pk,
            "outlayer": self.outlayer,
            "snapshot_hashes": self.snapshot_hashes,
            "bond_floor": self.bond_floor,
            "outlayer_deposit": self.outlayer_deposit,
            "deliver_ttl_ns": U64(self.deliver_ttl_ns),
            "timelock_ns": U64(self.timelock_ns),
            "created_at_ns": U64(self.created_at_ns),
            "invariants": self.invariants,
            "commits": self.commits.len(),
        })
    }

    pub fn view_commit(&self, commit_id: u64) -> Option<Commit> {
        self.commits.get(commit_id)
    }

    pub fn get_invariant(&self, invariant_id: String) -> Option<Invariant> {
        self.invariants.iter().find(|i| i.id == invariant_id).cloned()
    }
}

fn status_tag(s: &CommitStatus) -> &'static str {
    match s {
        CommitStatus::AwaitingRegistration => "awaiting-registration",
        CommitStatus::Pending => "pending",
        CommitStatus::Awarded => "awarded",
        CommitStatus::Delivered => "delivered",
        CommitStatus::Paid => "paid",
        CommitStatus::Refused(_) => "refused",
        CommitStatus::Voided => "voided",
    }
}

/// The verdict is the guest's stdout; OutLayer may hand it back as a JSON string, object, or wrapped. Find
/// the first object carrying `h_enc`. A JSON `null` (no verdict) finds nothing.
fn find_verdict(v: Value) -> Option<Value> {
    match v {
        Value::Object(ref m) if m.contains_key("h_enc") => Some(v),
        Value::Object(m) => m.into_iter().find_map(|(_, x)| find_verdict(x)),
        Value::String(s) => serde_json::from_str::<Value>(s.trim()).ok().and_then(find_verdict),
        Value::Array(a) => a.into_iter().find_map(find_verdict),
        _ => None,
    }
}

// A tiny hex encoder (no external dep in the contract crate).
mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
    }
}

// Keep GasWeight / BorshSerialize imports used across sdk versions honest.
#[allow(dead_code)]
fn _assert_imports() {
    let _ = GasWeight(1);
    fn _b<T: BorshSerialize + BorshDeserialize>() {}
}

#[cfg(test)]
mod unit {
    //! Unit coverage for the money-moving branches the near-workspaces sandbox cannot reach, because there
    //! a commit's callbacks always run (the `.then` gas is reserved up front). In `testing_env!` the
    //! cross-contract callbacks do NOT auto-run, so a commit sits in `AwaitingRegistration` exactly as it
    //! would if a top-level gas starvation stopped `on_payout_checked` — which is what `release_stale`
    //! defends. Here we drive that branch end to end and assert the ledger.
    use super::*;
    use near_sdk::test_utils::{accounts, VMContextBuilder};
    use near_sdk::{testing_env, NearToken};

    fn ctx(pred: AccountId, deposit: NearToken, ts: u64) -> VMContextBuilder {
        let mut b = VMContextBuilder::new();
        b.current_account_id(accounts(0)).predecessor_account_id(pred).attached_deposit(deposit).block_timestamp(ts);
        b
    }

    fn cfg() -> Config {
        Config {
            protocol: accounts(1),
            protocol_enc_pk: "7b".repeat(32),
            token: accounts(2),
            outlayer: accounts(3),
            verifier_wasm_hash: "92".repeat(32),
            verifier_wasm_url: "https://example.invalid/v.wasm".into(),
            snapshot_hashes: vec!["57".repeat(32)],
            invariants: vec![InvariantCfg { id: "inv-a".into(), target: 0, amount: U128(1_000_000), bond: NearToken::from_millinear(500) }],
            bond_floor: NearToken::from_millinear(500),
            outlayer_deposit: NearToken::from_millinear(100),
            deliver_ttl_ns: 3_600_000_000_000,
            timelock_ns: 0,
            max_instructions: 2_000_000_000,
            max_memory_mb: 512,
            max_execution_seconds: 120,
            stale_after_ns: 0,
        }
    }

    fn funded() -> Bounty {
        testing_env!(ctx(accounts(1), NearToken::from_yoctonear(0), 0).build());
        let mut c = Bounty::new(cfg());
        // Fund the pool as the token would via ft_on_transfer.
        testing_env!(ctx(accounts(2), NearToken::from_yoctonear(0), 0).build());
        c.ft_on_transfer(accounts(1), U128(1_000_000), String::new());
        c
    }

    #[test]
    fn release_stale_refunds_a_stuck_awaiting_registration_commit() {
        let mut c = funded();
        let hunter = accounts(4);
        let bond_plus_dep = NearToken::from_millinear(600);
        // commit: in testing_env the storage_balance_of callback never runs → stays AwaitingRegistration.
        testing_env!(ctx(hunter.clone(), bond_plus_dep, 1_000).build());
        c.commit("a".repeat(64), "inv-a".into(), accounts(5));
        let commit = c.view_commit(0).unwrap();
        assert!(matches!(commit.status, CommitStatus::AwaitingRegistration));
        assert_eq!(c.reserved, 1_000_000, "the amount is reserved at commit");
        assert_eq!(c.bonds_held, NearToken::from_millinear(500).as_yoctonear());

        // Past the (floored 30-min) window, anyone unsticks it; full refund, slot never taken.
        let t = RELEASE_STALE_FLOOR_NS + 2_000;
        testing_env!(ctx(accounts(0), NearToken::from_yoctonear(0), t).build());
        c.release_stale(0);
        let commit = c.view_commit(0).unwrap();
        assert!(matches!(commit.status, CommitStatus::Refused(_)));
        assert_eq!(c.reserved, 0, "reservation released");
        assert_eq!(c.bonds_held, 0, "bond returned, not slashed");
        assert_eq!(c.slashed, 0);
        assert!(matches!(c.invariants[0].state, InvState::Open));
        // I1 USDC conservation holds: pool + escrow + paid == funded - withdrawn.
        assert_eq!(c.pool + c.escrow + c.paid_total, c.funded_total - c.withdrawn_total);
    }

    #[test]
    fn release_stale_before_the_window_panics() {
        let mut c = funded();
        testing_env!(ctx(accounts(4), NearToken::from_millinear(600), 1_000).build());
        c.commit("b".repeat(64), "inv-a".into(), accounts(5));
        testing_env!(ctx(accounts(0), NearToken::from_yoctonear(0), 2_000).build());
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| c.release_stale(0)));
        assert!(r.is_err(), "release_stale before stale_after must panic");
    }

    #[test]
    fn commit_below_bond_floor_reserves_nothing() {
        let mut c = funded();
        testing_env!(ctx(accounts(4), NearToken::from_millinear(300), 1_000).build());
        c.commit("c".repeat(64), "inv-a".into(), accounts(5));
        assert_eq!(c.reserved, 0);
        assert_eq!(c.bonds_held, 0);
        assert_eq!(c.commits.len(), 0, "a guard refusal records no commit");
        assert!(matches!(c.invariants[0].state, InvState::Open));
    }
}
