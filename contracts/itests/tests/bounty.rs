//! Sandbox integration tests for the bounty contract (I1–I8 and the D2 refusal paths).
//!
//! The mock OutLayer returns the worker bytes the bounty's `on_verdict` sees: an awarded verdict, a tampered
//! one (I7), JSON `null` (every no-verdict), or a `stall` that starves the callback so the commit stays
//! Pending. The mock token stands in for USDC registration + payout, with flags to fail a payout or starve
//! the registration callback. The USDC conservation invariant `pool + escrow + paid = funded − withdrawn`
//! (I1) is asserted after every meaningful transition.

use near_workspaces::types::{Gas, NearToken};
use near_workspaces::{Account, Contract, Worker};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const WASM_DIR: &str = "../target/wasm32-unknown-unknown/release";
const AMOUNT: u128 = 1_000_000; // 1 tUSDC (6 decimals)
const BOND: NearToken = NearToken::from_millinear(500);
const DEPOSIT: NearToken = NearToken::from_millinear(100);
const SNAP0: &str = "11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa1";
const SNAP1: &str = "22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb2";
const ENC_PK: &str = "7b0d47d93427f8311160781c7c733fd89f88970aef490d8aa0ee19a4cb8a1b14";

fn wasm(name: &str) -> Vec<u8> {
    std::fs::read(format!("{WASM_DIR}/{name}.wasm")).unwrap_or_else(|e| panic!("{name}.wasm: {e} (run: cd contracts && cargo +1.85.0 build --target wasm32-unknown-unknown --release)"))
}

fn commit_deposit() -> NearToken {
    BOND.saturating_add(DEPOSIT)
}

fn sha256_hex(b: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b);
    hex::encode(h.finalize())
}

mod hex {
    pub fn encode(b: impl AsRef<[u8]>) -> String {
        b.as_ref().iter().map(|x| format!("{x:02x}")).collect()
    }
}

struct Env {
    worker: Worker<near_workspaces::network::Sandbox>,
    bounty: Contract,
    outlayer: Contract,
    token: Contract,
    protocol: Account,
    hunter: Account,
    hunter2: Account,
    payout: Account,
}

async fn setup(timelock_ns: u64, deliver_ttl_ns: u64, stale_after_ns: u64) -> anyhow::Result<Env> {
    let worker = near_workspaces::sandbox().await?;
    let token = worker.dev_deploy(&wasm("mock_token")).await?;
    token.call("new").transact().await?.into_result()?;
    let outlayer = worker.dev_deploy(&wasm("mock_outlayer")).await?;
    outlayer.call("new").transact().await?.into_result()?;
    let bounty = worker.dev_deploy(&wasm("bounty")).await?;

    let protocol = worker.dev_create_account().await?;
    let hunter = worker.dev_create_account().await?;
    let hunter2 = worker.dev_create_account().await?;
    let payout = worker.dev_create_account().await?;

    let cfg = json!({
        "protocol": protocol.id(),
        "protocol_enc_pk": ENC_PK,
        "token": token.id(),
        "outlayer": outlayer.id(),
        "verifier_wasm_hash": "92a4681dd4eebe23cd0d230bd3d8012a902e94a51cfa8654e5300e547c6a179a",
        "verifier_wasm_url": "https://example.invalid/verifier.wasm",
        "snapshot_hashes": [SNAP0, SNAP1],
        "invariants": [
            {"id": "inv-a", "target": 0u8, "amount": AMOUNT.to_string(), "bond": BOND},
            {"id": "inv-b", "target": 1u8, "amount": AMOUNT.to_string(), "bond": BOND},
        ],
        "bond_floor": BOND,
        "outlayer_deposit": DEPOSIT,
        "deliver_ttl_ns": deliver_ttl_ns,
        "timelock_ns": timelock_ns,
        "max_instructions": 2_000_000_000u64,
        "max_memory_mb": 512u32,
        "max_execution_seconds": 120u64,
        "stale_after_ns": stale_after_ns,
    });
    bounty.call("new").args_json(json!({ "cfg": cfg })).transact().await?.into_result()?;

    // Register the usual payout + the bounty itself on the token.
    for a in [payout.id(), hunter.id(), hunter2.id(), bounty.id()] {
        token.call("register").args_json(json!({ "account_id": a })).transact().await?.into_result()?;
    }
    Ok(Env { worker, bounty, outlayer, token, protocol, hunter, hunter2, payout })
}

impl Env {
    async fn fund(&self, amount: u128) -> anyhow::Result<()> {
        // The token account is the only allowed caller of ft_on_transfer.
        self.token
            .as_account()
            .call(self.bounty.id(), "ft_on_transfer")
            .args_json(json!({ "sender_id": self.protocol.id(), "amount": amount.to_string(), "msg": "" }))
            .transact()
            .await?
            .into_result()?;
        Ok(())
    }

    async fn arm(&self, next: Value) -> anyhow::Result<()> {
        self.outlayer.call("arm").args_json(json!({ "next": next })).transact().await?.into_result()?;
        Ok(())
    }

    async fn arm_award(&self, commit_hash: &str, invariant_id: &str, snap: &str, h_enc: &str) -> anyhow::Result<()> {
        self.arm(json!({"mode":"verdict","verdict":{
            "v":1,"broken":true,"invariant_id":invariant_id,"h_exploit":commit_hash,
            "h_snapshot":snap,"h_enc":h_enc,"gas_used":106932u64,"err":Value::Null
        }})).await
    }

    async fn commit(&self, who: &Account, commit_hash: &str, invariant_id: &str, payout_to: &Account) -> anyhow::Result<()> {
        self.commit_logs(who, commit_hash, invariant_id, payout_to).await.map(|_| ())
    }

    /// Commit and return the joined logs across all receipts (guard refusals log but record no commit).
    async fn commit_logs(&self, who: &Account, commit_hash: &str, invariant_id: &str, payout_to: &Account) -> anyhow::Result<String> {
        let r = who
            .call(self.bounty.id(), "commit")
            .args_json(json!({ "commit_hash": commit_hash, "invariant_id": invariant_id, "payout_to": payout_to.id() }))
            .deposit(commit_deposit())
            .gas(Gas::from_tgas(300))
            .transact()
            .await?
            .into_result()?;
        Ok(r.logs().join("\n"))
    }

    async fn commits_len(&self) -> anyhow::Result<u64> {
        Ok(self.state().await?["commits"].as_u64().unwrap())
    }

    async fn state(&self) -> anyhow::Result<Value> {
        Ok(self.bounty.view("view_state").await?.json()?)
    }

    async fn commit_view(&self, id: u64) -> anyhow::Result<Value> {
        Ok(self.bounty.view("view_commit").args_json(json!({ "commit_id": id })).await?.json()?)
    }

    async fn inv_state(&self, id: &str) -> anyhow::Result<String> {
        let inv: Value = self.bounty.view("get_invariant").args_json(json!({ "invariant_id": id })).await?.json()?;
        // InvState serializes as "Open" or {"Pending": n} etc.
        Ok(match &inv["state"] {
            Value::String(s) => s.clone(),
            Value::Object(m) => m.keys().next().cloned().unwrap_or_default(),
            _ => String::new(),
        })
    }

    async fn token_balance(&self, a: &Account) -> anyhow::Result<u128> {
        let v: Value = self.token.view("ft_balance_of").args_json(json!({ "account_id": a.id() })).await?.json()?;
        Ok(v.as_str().unwrap().parse()?)
    }

    /// I1 (USDC): pool + escrow + paid = funded − withdrawn.
    async fn assert_conservation(&self) -> anyhow::Result<()> {
        let s = self.state().await?;
        let u = |k: &str| -> u128 { s[k].as_str().unwrap().parse().unwrap() };
        assert_eq!(
            u("pool") + u("escrow") + u("paid_total"),
            u("funded_total") - u("withdrawn_total"),
            "I1 USDC conservation: {s}"
        );
        Ok(())
    }
}

fn status(c: &Value) -> String {
    match &c["status"] {
        Value::String(s) => s.clone(),
        Value::Object(m) => m.keys().next().cloned().unwrap_or_default(),
        _ => String::new(),
    }
}
fn refused_reason(c: &Value) -> String {
    c["status"]["Refused"].as_str().unwrap_or("").to_string()
}

#[tokio::test]
async fn happy_path_commit_award_deliver_pay() -> anyhow::Result<()> {
    let e = setup(0, 3_600_000_000_000, 1_800_000_000_000_000).await?;
    e.fund(AMOUNT).await?;
    e.assert_conservation().await?;

    let ch = "a".repeat(64);
    let enc = b"the-sealed-exploit-bytes".to_vec();
    let h_enc = sha256_hex(&enc);
    e.arm_award(&ch, "inv-a", SNAP0, &h_enc).await?;
    e.commit(&e.hunter, &ch, "inv-a", &e.payout).await?;

    let c = e.commit_view(0).await?;
    assert_eq!(status(&c), "Awarded", "{c}");
    assert_eq!(c["h_enc"].as_str().unwrap(), h_enc);
    let s = e.state().await?;
    assert_eq!(s["escrow"].as_str().unwrap(), AMOUNT.to_string());
    assert_eq!(s["reserved"].as_str().unwrap(), "0");
    e.assert_conservation().await?;

    // I8: the exploit becomes public, and the escrow owed, only in a deliver whose sha256(enc) == h_enc.
    // A mismatch is an on-chain refusal (success + log), leaving the commit Awarded and nothing paid.
    use base64::{engine::general_purpose::STANDARD, Engine};
    let wrong = e
        .hunter
        .call(e.bounty.id(), "deliver")
        .args_json(json!({ "commit_id": 0u64, "enc": STANDARD.encode(b"not the exploit") }))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?
        .into_result()?;
    assert!(wrong.logs().join("\n").contains("delivery mismatch"), "logs: {:?}", wrong.logs());
    assert_eq!(status(&e.commit_view(0).await?), "Awarded", "mismatch leaves the award intact");
    assert_eq!(e.token_balance(&e.payout).await?, 0);

    // Only the hunter may deliver (even with the right enc).
    let stranger = e.worker.dev_create_account().await?;
    let bad = stranger
        .call(e.bounty.id(), "deliver")
        .args_json(json!({ "commit_id": 0u64, "enc": STANDARD.encode(&enc) }))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?;
    assert!(format!("{:?}", bad.into_result().err()).contains("only the hunter may deliver"));

    e.hunter
        .call(e.bounty.id(), "deliver")
        .args_json(json!({ "commit_id": 0u64, "enc": STANDARD.encode(&enc) }))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?
        .into_result()?;

    let c = e.commit_view(0).await?;
    assert_eq!(status(&c), "Paid", "{c}");
    // The profile the worker is handed is derived from the commit hash the hunter knew before committing.
    assert_eq!(c["secrets_profile"].as_str().unwrap(), format!("c-{}", &ch[..8]));
    assert_eq!(e.token_balance(&e.payout).await?, AMOUNT);
    let s = e.state().await?;
    assert_eq!(s["escrow"].as_str().unwrap(), "0");
    assert_eq!(s["paid_total"].as_str().unwrap(), AMOUNT.to_string());
    assert_eq!(s["bonds_held"].as_str().unwrap(), "0", "a paid commit's bond is returned");
    assert_eq!(s["slashed"].as_str().unwrap(), "0");
    assert_eq!(e.inv_state("inv-a").await?, "Paid");
    e.assert_conservation().await?;
    Ok(())
}

// A fake (verdict with broken:false) is slashed; I2b the reservation is released and the invariant reopens.
#[tokio::test]
async fn fake_is_slashed_and_reopens() -> anyhow::Result<()> {
    let e = setup(0, 3_600_000_000_000, 1_800_000_000_000_000).await?;
    e.fund(AMOUNT).await?;
    let ch = "b".repeat(64);
    e.arm(json!({"mode":"verdict","verdict":{
        "v":1,"broken":false,"invariant_id":"inv-a","h_exploit":ch,"h_snapshot":SNAP0,"h_enc":"00","gas_used":0u64,"err":Value::Null
    }})).await?;
    e.commit(&e.hunter, &ch, "inv-a", &e.payout).await?;
    let c = e.commit_view(0).await?;
    assert_eq!(status(&c), "Refused");
    assert_eq!(refused_reason(&c), "no invariant broken", "{c}");
    let s = e.state().await?;
    assert_eq!(s["reserved"].as_str().unwrap(), "0");
    assert_eq!(s["slashed"].as_str().unwrap(), BOND.as_yoctonear().to_string(), "the bond is slashed");
    assert_eq!(s["bonds_held"].as_str().unwrap(), "0");
    assert_eq!(e.inv_state("inv-a").await?, "Open");
    e.assert_conservation().await?;
    Ok(())
}

// I7 binding: a verdict whose h_exploit != commit_hash (a copied commit) is refused "commit mismatch".
#[tokio::test]
async fn commit_mismatch_is_refused() -> anyhow::Result<()> {
    let e = setup(0, 3_600_000_000_000, 1_800_000_000_000_000).await?;
    e.fund(AMOUNT).await?;
    let ch = "c".repeat(64);
    e.arm_award(&"d".repeat(64), "inv-a", SNAP0, &"00".to_string()).await?; // h_exploit differs from ch
    e.commit(&e.hunter, &ch, "inv-a", &e.payout).await?;
    let c = e.commit_view(0).await?;
    assert_eq!(refused_reason(&c), "commit mismatch", "{c}");
    let s = e.state().await?;
    assert_eq!(s["reserved"].as_str().unwrap(), "0");
    assert_eq!(s["slashed"].as_str().unwrap(), BOND.as_yoctonear().to_string(), "I7 breach is slashed");
    assert_eq!(s["bonds_held"].as_str().unwrap(), "0");
    assert_eq!(e.inv_state("inv-a").await?, "Open");
    e.assert_conservation().await?;
    Ok(())
}

// I7 binding: a verdict carrying the wrong invariant_id is refused "wrong invariant" and slashed.
#[tokio::test]
async fn wrong_invariant_is_refused() -> anyhow::Result<()> {
    let e = setup(0, 3_600_000_000_000, 1_800_000_000_000_000).await?;
    e.fund(AMOUNT).await?;
    let ch = "a1".repeat(32);
    // broken + right h_exploit + right snapshot, but the verdict names a different invariant.
    e.arm(json!({"mode":"verdict","verdict":{
        "v":1,"broken":true,"invariant_id":"inv-b","h_exploit":ch,"h_snapshot":SNAP0,
        "h_enc":"ab".repeat(32),"gas_used":1u64,"err":Value::Null
    }})).await?;
    e.commit(&e.hunter, &ch, "inv-a", &e.payout).await?;
    let c = e.commit_view(0).await?;
    assert_eq!(refused_reason(&c), "wrong invariant", "{c}");
    assert_eq!(e.state().await?["slashed"].as_str().unwrap(), BOND.as_yoctonear().to_string());
    assert_eq!(e.inv_state("inv-a").await?, "Open");
    e.assert_conservation().await?;
    Ok(())
}

// I7 binding: a verdict on the wrong snapshot is refused "snapshot mismatch" (mocked-callback case).
#[tokio::test]
async fn snapshot_mismatch_is_refused() -> anyhow::Result<()> {
    let e = setup(0, 3_600_000_000_000, 1_800_000_000_000_000).await?;
    e.fund(AMOUNT).await?;
    let ch = "e".repeat(64);
    e.arm_award(&ch, "inv-a", SNAP1, &"00".to_string()).await?; // inv-a's snapshot is SNAP0, not SNAP1
    e.commit(&e.hunter, &ch, "inv-a", &e.payout).await?;
    let c = e.commit_view(0).await?;
    assert_eq!(refused_reason(&c), "snapshot mismatch", "{c}");
    let s = e.state().await?;
    assert_eq!(s["slashed"].as_str().unwrap(), BOND.as_yoctonear().to_string());
    assert_eq!(s["bonds_held"].as_str().unwrap(), "0");
    assert_eq!(s["reserved"].as_str().unwrap(), "0");
    e.assert_conservation().await?;
    Ok(())
}

// delivery expired: past deliver_by, a correct enc is refused (success + log); the award can then be expired.
#[tokio::test]
async fn delivery_after_deadline_is_refused() -> anyhow::Result<()> {
    let e = setup(0, 1, 1_800_000_000_000_000).await?; // deliver_ttl 1 ns
    e.fund(AMOUNT).await?;
    let ch = "e1".repeat(32);
    let enc = b"late".to_vec();
    e.arm_award(&ch, "inv-a", SNAP0, &sha256_hex(&enc)).await?;
    e.commit(&e.hunter, &ch, "inv-a", &e.payout).await?;
    assert_eq!(status(&e.commit_view(0).await?), "Awarded");
    e.worker.fast_forward(2).await?;
    use base64::{engine::general_purpose::STANDARD, Engine};
    let r = e
        .hunter
        .call(e.bounty.id(), "deliver")
        .args_json(json!({ "commit_id": 0u64, "enc": STANDARD.encode(&enc) }))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?
        .into_result()?;
    assert!(r.logs().join("\n").contains("delivery expired"), "logs: {:?}", r.logs());
    assert_eq!(status(&e.commit_view(0).await?), "Awarded", "still awarded; nothing paid");
    assert_eq!(e.token_balance(&e.payout).await?, 0);
    e.assert_conservation().await?;
    Ok(())
}

// I3 one-at-a-time: while a commit is Pending (stalled), a second commit on the same invariant is refused
// "claim pending"; exactly one commit holds the slot.
#[tokio::test]
async fn second_commit_on_pending_invariant_is_refused() -> anyhow::Result<()> {
    let e = setup(0, 3_600_000_000_000, 1_800_000_000_000_000).await?;
    e.fund(AMOUNT).await?;
    e.arm(json!({ "mode": "stall" })).await?;
    e.commit(&e.hunter, &"1".repeat(64), "inv-a", &e.payout).await?;
    assert_eq!(status(&e.commit_view(0).await?), "Pending");
    assert_eq!(e.inv_state("inv-a").await?, "Pending");

    let logs = e.commit_logs(&e.hunter2, &"2".repeat(64), "inv-a", &e.payout).await?;
    assert!(logs.contains("REFUSED: claim pending"), "logs: {logs}");
    // The guard refused before recording: only the one Pending commit exists, only its amount reserved.
    assert_eq!(e.commits_len().await?, 1);
    assert_eq!(e.state().await?["reserved"].as_str().unwrap(), AMOUNT.to_string());
    e.assert_conservation().await?;
    Ok(())
}

// I4 encumbrance: a pending/awarded amount can never be withdrawn, even after the timelock.
#[tokio::test]
async fn withdraw_respects_encumbrance_and_timelock() -> anyhow::Result<()> {
    let e = setup(0, 3_600_000_000_000, 1_800_000_000_000_000).await?;
    e.fund(AMOUNT).await?;
    e.arm(json!({ "mode": "stall" })).await?;
    e.commit(&e.hunter, &"1".repeat(64), "inv-a", &e.payout).await?; // reserves AMOUNT, stays Pending

    // timelock_ns = 0, so the only thing blocking withdrawal is the reservation (I4).
    let ok: bool = e
        .protocol
        .call(e.bounty.id(), "withdraw_pool")
        .args_json(json!({ "amount": AMOUNT.to_string() }))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?
        .json()?;
    assert!(!ok, "withdrawing the reserved amount must be refused (claim pending)");
    assert_eq!(e.state().await?["pool"].as_str().unwrap(), AMOUNT.to_string(), "nothing left the pool");

    // Fund an extra, unencumbered unit: that part is withdrawable.
    e.fund(AMOUNT).await?;
    let ok: bool = e
        .protocol
        .call(e.bounty.id(), "withdraw_pool")
        .args_json(json!({ "amount": AMOUNT.to_string() }))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?
        .json()?;
    assert!(ok, "the unencumbered unit is withdrawable");
    e.assert_conservation().await?;
    Ok(())
}

// Timelock: before it elapses, even an unencumbered withdrawal is refused.
#[tokio::test]
async fn withdraw_blocked_before_timelock() -> anyhow::Result<()> {
    let e = setup(60_000_000_000_000, 3_600_000_000_000, 1_800_000_000_000_000).await?;
    e.fund(AMOUNT).await?;
    let ok: bool = e
        .protocol
        .call(e.bounty.id(), "withdraw_pool")
        .args_json(json!({ "amount": AMOUNT.to_string() }))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?
        .json()?;
    assert!(!ok, "withdrawal before the timelock is refused");
    assert_eq!(e.state().await?["pool"].as_str().unwrap(), AMOUNT.to_string());
    Ok(())
}

// I8: a failing ft_transfer after deliver leaves the escrow owed; retry_payout pays it once the token recovers.
#[tokio::test]
async fn failed_payout_leaves_escrow_owed_then_retry_pays() -> anyhow::Result<()> {
    let e = setup(0, 3_600_000_000_000, 1_800_000_000_000_000).await?;
    e.fund(AMOUNT).await?;
    let ch = "f".repeat(64);
    let enc = b"exploit-xyz".to_vec();
    let h_enc = sha256_hex(&enc);
    e.arm_award(&ch, "inv-a", SNAP0, &h_enc).await?;
    e.commit(&e.hunter, &ch, "inv-a", &e.payout).await?;
    assert_eq!(status(&e.commit_view(0).await?), "Awarded");

    e.token.call("set_fail_transfer").args_json(json!({ "v": true })).transact().await?.into_result()?;
    use base64::{engine::general_purpose::STANDARD, Engine};
    e.hunter
        .call(e.bounty.id(), "deliver")
        .args_json(json!({ "commit_id": 0u64, "enc": STANDARD.encode(&enc) }))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?
        .into_result()?;
    // Delivered, payout failed: escrow kept, paying cleared, not Paid.
    let c = e.commit_view(0).await?;
    assert_eq!(status(&c), "Delivered", "{c}");
    assert_eq!(c["paying"].as_bool().unwrap(), false);
    assert_eq!(e.state().await?["escrow"].as_str().unwrap(), AMOUNT.to_string());

    // retry_payout to a new destination requires the hunter; a stranger cannot redirect.
    let stranger = e.worker.dev_create_account().await?;
    let bad = stranger
        .call(e.bounty.id(), "retry_payout")
        .args_json(json!({ "commit_id": 0u64, "new_payout_to": stranger.id() }))
        .transact()
        .await?;
    assert!(format!("{:?}", bad.into_result().err()).contains("only the hunter"), "stranger cannot redirect");

    e.token.call("set_fail_transfer").args_json(json!({ "v": false })).transact().await?.into_result()?;
    e.hunter
        .call(e.bounty.id(), "retry_payout")
        .args_json(json!({ "commit_id": 0u64, "new_payout_to": Value::Null }))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?
        .into_result()?;
    assert_eq!(status(&e.commit_view(0).await?), "Paid");
    assert_eq!(e.token_balance(&e.payout).await?, AMOUNT);
    e.assert_conservation().await?;
    Ok(())
}

// retry_payout is refused once the commit is Paid (nothing owed; guards I2 single-pay).
#[tokio::test]
async fn retry_refused_when_not_awaiting_payout() -> anyhow::Result<()> {
    let e = setup(0, 3_600_000_000_000, 1_800_000_000_000_000).await?;
    e.fund(AMOUNT).await?;
    let ch = "7".repeat(64);
    let enc = b"abc".to_vec();
    e.arm_award(&ch, "inv-a", SNAP0, &sha256_hex(&enc)).await?;
    e.commit(&e.hunter, &ch, "inv-a", &e.payout).await?;
    use base64::{engine::general_purpose::STANDARD, Engine};
    e.hunter.call(e.bounty.id(), "deliver").args_json(json!({ "commit_id": 0u64, "enc": STANDARD.encode(&enc) })).gas(Gas::from_tgas(100)).transact().await?.into_result()?;
    assert_eq!(status(&e.commit_view(0).await?), "Paid");
    let bad = e.hunter.call(e.bounty.id(), "retry_payout").args_json(json!({ "commit_id": 0u64, "new_payout_to": Value::Null })).transact().await?;
    assert!(format!("{:?}", bad.into_result().err()).contains("not awaiting payout"));
    Ok(())
}

// expire: an awarded commit past deliver_by is voided, the escrow returns to the pool and the bond is slashed.
#[tokio::test]
async fn awarded_commit_expires() -> anyhow::Result<()> {
    let e = setup(0, 1, 1_800_000_000_000_000).await?; // deliver_ttl 1 ns
    e.fund(AMOUNT).await?;
    let ch = "8".repeat(64);
    e.arm_award(&ch, "inv-a", SNAP0, &"ab".repeat(32)).await?;
    e.commit(&e.hunter, &ch, "inv-a", &e.payout).await?;
    assert_eq!(status(&e.commit_view(0).await?), "Awarded");
    e.worker.fast_forward(2).await?;
    e.worker.dev_create_account().await?.call(e.bounty.id(), "expire").args_json(json!({ "commit_id": 0u64 })).transact().await?.into_result()?;
    let c = e.commit_view(0).await?;
    assert_eq!(status(&c), "Voided", "{c}");
    let s = e.state().await?;
    assert_eq!(s["escrow"].as_str().unwrap(), "0");
    assert_eq!(s["pool"].as_str().unwrap(), AMOUNT.to_string(), "escrow returned to pool");
    assert_eq!(s["slashed"].as_str().unwrap(), BOND.as_yoctonear().to_string());
    assert_eq!(e.inv_state("inv-a").await?, "Open");
    e.assert_conservation().await?;
    Ok(())
}

// No verdict (null): first time per (hunter, invariant) the bond is returned; a repeat within 24 h is slashed.
#[tokio::test]
async fn verifier_unavailable_refunds_once_then_slashes() -> anyhow::Result<()> {
    let e = setup(0, 3_600_000_000_000, 1_800_000_000_000_000).await?;
    e.fund(AMOUNT).await?;
    e.arm(json!({ "mode": "null" })).await?;
    e.commit(&e.hunter, &"9".repeat(64), "inv-a", &e.payout).await?;
    let c = e.commit_view(0).await?;
    assert_eq!(refused_reason(&c), "verifier unavailable", "{c}");
    assert_eq!(e.state().await?["slashed"].as_str().unwrap(), "0", "first time: bond returned");
    assert_eq!(e.inv_state("inv-a").await?, "Open");

    // Same hunter, same invariant, still null, within 24 h → slashed.
    e.commit(&e.hunter, &"9".repeat(64), "inv-a", &e.payout).await?;
    assert_eq!(refused_reason(&e.commit_view(1).await?), "verifier unavailable");
    assert_eq!(e.state().await?["slashed"].as_str().unwrap(), BOND.as_yoctonear().to_string(), "repeat within 24h is slashed");
    e.assert_conservation().await?;
    Ok(())
}

// release_stale guard: a commit that is genuinely Pending (the yield is still dangling, as when the worker
// has not answered) cannot be released before the 30-min floor. The *firing* of release_stale needs NEAR's
// own yield auto-resume to have failed — which the sandbox cannot induce (the yield times out into a `null`
// verdict at ~200 blocks, long before 30 min), so the refund branch is covered by code review; see
// specs/progress.md Decisions.
#[tokio::test]
async fn release_stale_refuses_before_window() -> anyhow::Result<()> {
    let e = setup(0, 3_600_000_000_000, 0).await?; // stale_after floored to 30 min
    e.fund(AMOUNT).await?;
    e.arm(json!({ "mode": "stall" })).await?;
    e.commit(&e.hunter, &"a".repeat(64), "inv-a", &e.payout).await?;
    assert_eq!(status(&e.commit_view(0).await?), "Pending", "a dangling yield keeps the commit Pending");

    let early = e
        .worker
        .dev_create_account()
        .await?
        .call(e.bounty.id(), "release_stale")
        .args_json(json!({ "commit_id": 0u64 }))
        .transact()
        .await?;
    assert!(format!("{:?}", early.into_result().err()).contains("not stale yet"));
    // Still Pending, still reserved — nothing leaked.
    assert_eq!(status(&e.commit_view(0).await?), "Pending");
    assert_eq!(e.state().await?["reserved"].as_str().unwrap(), AMOUNT.to_string());
    e.assert_conservation().await?;
    Ok(())
}

// I2 single pay: a second commit on an already-awarded invariant is refused "invariant already paid".
#[tokio::test]
async fn commit_on_awarded_invariant_is_refused() -> anyhow::Result<()> {
    let e = setup(0, 3_600_000_000_000, 1_800_000_000_000_000).await?;
    e.fund(AMOUNT + AMOUNT).await?;
    let ch = "3".repeat(64);
    e.arm_award(&ch, "inv-a", SNAP0, &"ab".repeat(32)).await?;
    e.commit(&e.hunter, &ch, "inv-a", &e.payout).await?;
    assert_eq!(status(&e.commit_view(0).await?), "Awarded");

    let logs = e.commit_logs(&e.hunter2, &"4".repeat(64), "inv-a", &e.payout).await?;
    assert!(logs.contains("REFUSED: invariant already paid"), "logs: {logs}");
    // The guard refused before recording; the awarded amount stays escrowed, nothing newly reserved.
    assert_eq!(e.commits_len().await?, 1);
    let s = e.state().await?;
    assert_eq!(s["escrow"].as_str().unwrap(), AMOUNT.to_string());
    assert_eq!(s["reserved"].as_str().unwrap(), "0");
    e.assert_conservation().await?;
    Ok(())
}

// A registration check that fails (token call errors) is refused "registration check unavailable" with a
// full refund, in on_payout_checked's Err branch — the slot is never taken. (A commit stuck *before* that
// callback runs is unreachable in the sandbox: the .then callback's gas is reserved up front, so it always
// runs; release_stale's AwaitingRegistration branch defends only a top-level gas starvation and is covered
// by code review, not a sandbox test — see specs/progress.md Decisions.)
#[tokio::test]
async fn registration_unavailable_is_refused() -> anyhow::Result<()> {
    let e = setup(0, 3_600_000_000_000, 1_800_000_000_000_000).await?;
    e.fund(AMOUNT).await?;
    e.token.call("set_burn_gas_on_reg").args_json(json!({ "v": true })).transact().await?.into_result()?;
    e.commit(&e.hunter, &"b".repeat(64), "inv-a", &e.payout).await?;
    assert_eq!(refused_reason(&e.commit_view(0).await?), "registration check unavailable");
    assert_eq!(e.state().await?["reserved"].as_str().unwrap(), "0");
    assert_eq!(e.state().await?["bonds_held"].as_str().unwrap(), "0");
    assert_eq!(e.inv_state("inv-a").await?, "Open");
    e.assert_conservation().await?;
    Ok(())
}

// A commit for an unregistered payout_to is refused in on_payout_checked; the slot is never taken.
#[tokio::test]
async fn unregistered_payout_is_refused() -> anyhow::Result<()> {
    let e = setup(0, 3_600_000_000_000, 1_800_000_000_000_000).await?;
    e.fund(AMOUNT).await?;
    let unreg = e.worker.dev_create_account().await?; // not registered on the token
    e.commit(&e.hunter, &"c".repeat(64), "inv-a", &unreg).await?;
    assert_eq!(refused_reason(&e.commit_view(0).await?), "payout_to not registered");
    assert_eq!(e.state().await?["reserved"].as_str().unwrap(), "0");
    assert_eq!(e.inv_state("inv-a").await?, "Open");
    e.assert_conservation().await?;
    Ok(())
}

// A commit below the bond floor is refused with a full refund, no reservation.
#[tokio::test]
async fn low_bond_is_refused() -> anyhow::Result<()> {
    let e = setup(0, 3_600_000_000_000, 1_800_000_000_000_000).await?;
    e.fund(AMOUNT).await?;
    e.hunter
        .call(e.bounty.id(), "commit")
        .args_json(json!({ "commit_hash": "d".repeat(64), "invariant_id": "inv-a", "payout_to": e.payout.id() }))
        .deposit(NearToken::from_millinear(300)) // below bond + deposit
        .gas(Gas::from_tgas(300))
        .transact()
        .await?
        .into_result()?;
    assert_eq!(e.state().await?["reserved"].as_str().unwrap(), "0");
    assert_eq!(e.state().await?["bonds_held"].as_str().unwrap(), "0");
    assert_eq!(e.inv_state("inv-a").await?, "Open");
    Ok(())
}

// pool short: a commit whose amount exceeds pool − reserved is refused.
#[tokio::test]
async fn pool_short_is_refused() -> anyhow::Result<()> {
    let e = setup(0, 3_600_000_000_000, 1_800_000_000_000_000).await?;
    // Pool is empty: the amount cannot be reserved.
    e.commit(&e.hunter, &"e".repeat(64), "inv-a", &e.payout).await?;
    assert_eq!(e.state().await?["reserved"].as_str().unwrap(), "0");
    assert_eq!(e.inv_state("inv-a").await?, "Open");
    // No commit was recorded past guard? A guard refusal still records nothing in commits.
    assert_eq!(e.state().await?["commits"].as_u64().unwrap(), 0);
    Ok(())
}

// A verdict with broken:false AND an `err` (the verifier's decode/secret error) is surfaced as the spec's
// "exploit invalid: <err>" refusal, and slashed.
#[tokio::test]
async fn exploit_invalid_reason_is_surfaced() -> anyhow::Result<()> {
    let e = setup(0, 3_600_000_000_000, 1_800_000_000_000_000).await?;
    e.fund(AMOUNT).await?;
    let ch = "cd".repeat(32);
    e.arm(json!({"mode":"verdict","verdict":{
        "v":1,"broken":false,"invariant_id":"inv-a","h_exploit":ch,"h_snapshot":SNAP0,
        "h_enc":"ab".repeat(32),"gas_used":0u64,"err":"exploit invalid: too many txs"
    }})).await?;
    e.commit(&e.hunter, &ch, "inv-a", &e.payout).await?;
    let c = e.commit_view(0).await?;
    assert_eq!(refused_reason(&c), "exploit invalid: too many txs", "{c}");
    assert_eq!(e.state().await?["slashed"].as_str().unwrap(), BOND.as_yoctonear().to_string());
    e.assert_conservation().await?;
    Ok(())
}
