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
//! `../../specs/architecture.md` (§Endpoints, §Refusal semantics, §Protocol Invariants). Every refusal is a
//! successful tx with a log, never a panic (panics are reserved for malformed arguments).

use near_sdk::borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::collections::{LookupMap, Vector};
use near_sdk::json_types::U128;
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
        require!(commit_hash.len() == 64, "commit_hash is 32-byte hex");
        let inv = self.invariants[idx].clone();
        let min = inv.bond.saturating_add(self.outlayer_deposit);

        // Guard refusals: refund everything, reserve nothing.
        let refuse = |why: &str| -> Option<&'static str> {
            env::log_str(&format!("REFUSED: {why}"));
            None
        };
        let bad = if attached < min {
            refuse("bond").map(|_| ());
            Some(())
        } else if !matches!(inv.state, InvState::Open | InvState::Pending(_)) {
            env::log_str("REFUSED: invariant already paid");
            Some(())
        } else if matches!(inv.state, InvState::Pending(_)) {
            env::log_str("REFUSED: claim pending");
            Some(())
        } else if self.pool.saturating_sub(self.reserved) < inv.amount.0 {
            env::log_str("REFUSED: pool short");
            Some(())
        } else {
            None
        };
        if bad.is_some() {
            if attached.as_yoctonear() > 0 {
                Promise::new(hunter).transfer(attached);
            }
            return;
        }

        let bond = inv.bond;
        let deposit = attached.saturating_sub(bond); // ≥ outlayer_deposit by the `min` guard
        let commit_id = self.commits.len();
        self.commits.push(&Commit {
            hunter: hunter.clone(),
            commit_hash,
            invariant_id: invariant_id.clone(),
            payout_to: payout_to.clone(),
            secrets_profile: format!("c-{}", &self.commits.len().to_string()),
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
        let bytes = match env::promise_result(0) {
            PromiseResult::Successful(b) => b,
            PromiseResult::Failed => return self.no_verdict(commit_id, &mut c, idx),
        };
        // Every non-verdict (worker-answered failure, yield timeout, stale run) arrives as a SUCCESSFUL
        // promise whose bytes are JSON `null` (OutLayer `on_execution_response`). One rule for all of them.
        let verdict: Option<Value> = serde_json::from_slice::<Value>(&bytes).ok().and_then(find_verdict);
        let v = match verdict {
            Some(v) => v,
            None => return self.no_verdict(commit_id, &mut c, idx),
        };

        let inv = self.invariants[idx].clone();
        let broken = v.get("broken").and_then(|x| x.as_bool()).unwrap_or(false);
        let h_exploit = v.get("h_exploit").and_then(|x| x.as_str()).unwrap_or("");
        let h_snapshot = v.get("h_snapshot").and_then(|x| x.as_str()).unwrap_or("");
        let v_inv = v.get("invariant_id").and_then(|x| x.as_str()).unwrap_or("");
        let h_enc = v.get("h_enc").and_then(|x| x.as_str()).unwrap_or("");
        let want_snap = &self.snapshot_hashes[inv.target as usize];

        // Hunter-caused refusals (I7 binding): slash the bond; the worker ran, so the OutLayer deposit is gone.
        let reason = if !broken {
            Some("no invariant broken")
        } else if h_exploit != c.commit_hash {
            Some("commit mismatch")
        } else if v_inv != c.invariant_id {
            Some("wrong invariant")
        } else if h_snapshot != want_snap.as_str() {
            Some("snapshot mismatch")
        } else {
            None
        };
        if let Some(why) = reason {
            self.reserved -= inv.amount.0;
            self.slash(&mut c);
            self.invariants[idx].state = InvState::Open;
            c.status = CommitStatus::Refused(why.into());
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
    /// no-verdict arriving ≥ 10 min after the request refunds in full and never counts toward the cap.
    fn no_verdict(&mut self, commit_id: u64, c: &mut Commit, idx: usize) {
        let amount = self.invariants[idx].amount.0;
        self.reserved -= amount;
        self.invariants[idx].state = InvState::Open;
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
        self.commits.replace(commit_id, c);
    }

    /// Anyone, after `stale_after_ns`: unstick a commit whose callback never ran. Full refund, never counted.
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
                self.invariants[idx].state = InvState::Open;
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
        let want = c.h_enc.clone().expect("awarded commit has h_enc");
        require!(now() <= c.deliver_by_ns.expect("awarded commit has deliver_by"), "delivery expired");
        let got = hex::encode(env::sha256(&enc.0));
        require!(got == want, "delivery mismatch");
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
        Promise::new(self.token.clone()).function_call(
            "ft_transfer".to_string(),
            json!({ "receiver_id": self.protocol, "amount": amount }).to_string().into_bytes(),
            ONE_YOCTO,
            FT_GAS,
        );
        env::log_str(&format!("WITHDRAW_POOL {}", amount.0));
        true
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
