//! Integration-style unit tests driving the bounty contract through near-sdk's mocked VM.
//! Callbacks are invoked directly with predecessor == current account and mocked promise results.
use bounty::*;
use near_sdk::json_types::{Base64VecU8, U128};
use near_sdk::serde_json::{json, Value};
use near_sdk::test_utils::{accounts, get_logs, VMContextBuilder};
use near_sdk::{testing_env, AccountId, NearToken, PromiseError, PromiseResult};
use std::panic::{catch_unwind, AssertUnwindSafe};

const AMT: u128 = 1_000_000;
const TTL: u64 = 3_600_000_000_000;
const HOUR: u64 = 3_600_000_000_000;

fn mn(n: u128) -> NearToken {
    NearToken::from_millinear(n)
}

fn ctx(pred: AccountId, deposit: NearToken, ts: u64) -> VMContextBuilder {
    let mut b = VMContextBuilder::new();
    b.current_account_id(accounts(0)).predecessor_account_id(pred).attached_deposit(deposit).block_timestamp(ts);
    b
}

fn env_at(pred: AccountId, deposit: NearToken, ts: u64) {
    testing_env!(ctx(pred, deposit, ts).build());
}

fn env_promise(ts: u64, res: PromiseResult) {
    testing_env!(
        ctx(accounts(0), NearToken::from_yoctonear(0), ts).build(),
        near_sdk::test_vm_config(),
        near_sdk::RuntimeFeesConfig::test(),
        Default::default(),
        vec![res]
    );
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
        invariants: vec![InvariantCfg { id: "inv-a".into(), target: 0, amount: U128(AMT), bond: mn(500) }],
        bond_floor: mn(500),
        outlayer_deposit: mn(100),
        deliver_ttl_ns: TTL,
        timelock_ns: 0,
        max_instructions: 2_000_000_000,
        max_memory_mb: 512,
        max_execution_seconds: 120,
        stale_after_ns: 0,
    }
}

fn funded_with(cfg: Config, pool: u128) -> Bounty {
    env_at(accounts(1), NearToken::from_yoctonear(0), 0);
    let mut c = Bounty::new(cfg);
    env_at(accounts(2), NearToken::from_yoctonear(0), 0);
    c.ft_on_transfer(accounts(1), U128(pool), String::new());
    c
}

fn funded() -> Bounty {
    funded_with(cfg(), AMT)
}

fn st(c: &Bounty, k: &str) -> String {
    c.view_state()[k].as_str().unwrap().to_string()
}

fn panics<F: FnOnce()>(f: F) -> bool {
    catch_unwind(AssertUnwindSafe(f)).is_err()
}

fn hash(ch: &str) -> String {
    ch.repeat(64)
}

fn commit_at(c: &mut Bounty, ts: u64, ch: &str) {
    env_at(accounts(4), mn(600), ts);
    c.commit(hash(ch), "inv-a".into(), accounts(5));
}

fn registered(c: &mut Bounty, id: u64, ts: u64) {
    env_at(accounts(0), NearToken::from_yoctonear(0), ts);
    c.on_payout_checked(id, Ok(Some(json!({"total": "1"}))));
}

fn sha_hex(b: &[u8]) -> String {
    testing_env!(VMContextBuilder::new().build());
    near_sdk::env::sha256(b).iter().map(|x| format!("{x:02x}")).collect()
}

fn good_verdict(ch: &str, h_enc: &str) -> Value {
    json!({"broken": true, "h_exploit": hash(ch), "h_snapshot": "57".repeat(32), "invariant_id": "inv-a", "h_enc": h_enc})
}

fn verdict(c: &mut Bounty, id: u64, ts: u64, v: &Value) {
    env_promise(ts, PromiseResult::Successful(v.to_string().into_bytes()));
    c.on_verdict(id);
}

fn inv_state(c: &Bounty) -> Value {
    c.view_state()["invariants"][0]["state"].clone()
}

/// commit 0 -> Pending -> Awarded for enc = b"exploit"; returns the awarded bounty.
fn awarded() -> Bounty {
    let mut c = funded();
    commit_at(&mut c, 1_000, "a");
    registered(&mut c, 0, 1_100);
    let h = sha_hex(b"exploit");
    verdict(&mut c, 0, 1_200, &good_verdict("a", &h));
    c
}

fn delivered() -> Bounty {
    let mut c = awarded();
    env_at(accounts(4), NearToken::from_yoctonear(0), 2_000);
    c.deliver(0, Base64VecU8(b"exploit".to_vec()));
    c
}

#[test]
fn new_validates_config() {
    let mut a = cfg();
    a.snapshot_hashes = vec![];
    assert!(panics(|| { Bounty::new(a); }));
    let mut b = cfg();
    b.invariants = vec![];
    assert!(panics(|| { Bounty::new(b); }));
    let mut d = cfg();
    d.protocol_enc_pk = "ab".into();
    assert!(panics(|| { Bounty::new(d); }));
    let mut e = cfg();
    e.verifier_wasm_hash = "ab".into();
    assert!(panics(|| { Bounty::new(e); }));
    let mut f = cfg();
    f.invariants[0].bond = mn(1);
    assert!(panics(|| { Bounty::new(f); }));
    let mut g = cfg();
    g.invariants[0].target = 1;
    assert!(panics(|| { Bounty::new(g); }));
}

#[test]
fn new_floors_stale_window_and_views() {
    let c = funded();
    assert_eq!(st(&c, "pool"), "1000000");
    assert_eq!(st(&c, "funded_total"), "1000000");
    assert_eq!(c.view_state()["commits"], 0);
    assert!(c.get_invariant("inv-a".into()).is_some());
    assert!(c.get_invariant("nope".into()).is_none());
    assert!(c.view_commit(0).is_none());
}

#[test]
fn ft_on_transfer_wrong_token_refunds_all() {
    let mut c = funded();
    env_at(accounts(3), NearToken::from_yoctonear(0), 0);
    let back = c.ft_on_transfer(accounts(1), U128(77), "x".into());
    assert_eq!(back.0, 77);
    assert_eq!(st(&c, "pool"), "1000000");
    assert!(get_logs().iter().any(|l| l.contains("wrong token")));
}

#[test]
fn commit_panics_on_bad_args() {
    let mut c = funded();
    env_at(accounts(4), mn(600), 1);
    assert!(panics(|| c.commit(hash("a"), "zzz".into(), accounts(5))));
    assert!(panics(|| c.commit("short".into(), "inv-a".into(), accounts(5))));
    assert!(panics(|| c.commit("g".repeat(64), "inv-a".into(), accounts(5))));
}

#[test]
fn commit_refusals() {
    // zero deposit -> bond refusal, nothing recorded
    let mut c = funded();
    env_at(accounts(4), NearToken::from_yoctonear(0), 1);
    c.commit(hash("a"), "inv-a".into(), accounts(5));
    assert!(get_logs().iter().any(|l| l == "REFUSED: bond"));
    assert!(c.view_commit(0).is_none());

    // pool short
    let mut s = funded_with(cfg(), AMT - 1);
    commit_at(&mut s, 1, "a");
    assert!(get_logs().iter().any(|l| l == "REFUSED: pool short"));
    assert!(s.view_commit(0).is_none());

    // claim pending
    let mut p = funded();
    commit_at(&mut p, 1, "a");
    registered(&mut p, 0, 2);
    commit_at(&mut p, 3, "b");
    assert!(get_logs().iter().any(|l| l == "REFUSED: claim pending"));
    assert!(p.view_commit(1).is_none());

    // already paid (awarded)
    let mut a = awarded();
    commit_at(&mut a, 5_000, "b");
    assert!(get_logs().iter().any(|l| l == "REFUSED: invariant already paid"));
    assert!(a.view_commit(1).is_none());
}

#[test]
fn commit_records_and_reserves() {
    let mut c = funded();
    commit_at(&mut c, 1_000, "a");
    let cm = c.view_commit(0).unwrap();
    assert!(matches!(cm.status, CommitStatus::AwaitingRegistration));
    assert_eq!(cm.secrets_profile, "c-aaaaaaaa");
    assert_eq!(cm.deposit, mn(100));
    assert_eq!(st(&c, "reserved"), "1000000");
    assert!(get_logs().iter().any(|l| l.starts_with("COMMIT 0 inv-a")));
}

#[test]
fn on_payout_checked_registered_goes_pending() {
    let mut c = funded();
    commit_at(&mut c, 1_000, "a");
    registered(&mut c, 0, 1_100);
    assert!(matches!(c.view_commit(0).unwrap().status, CommitStatus::Pending));
    assert_eq!(inv_state(&c), json!({"Pending": 0}));
    // second call is a no-op
    registered(&mut c, 0, 1_200);
    assert!(get_logs().iter().any(|l| l.contains("not awaiting (\"pending\")")));
}

#[test]
fn on_payout_checked_refund_paths() {
    let mut c = funded();
    commit_at(&mut c, 1, "a");
    env_at(accounts(0), NearToken::from_yoctonear(0), 2);
    c.on_payout_checked(0, Ok(None));
    assert!(c.view_commit(0).unwrap().status == CommitStatus::Refused("payout_to not registered".into()));
    assert_eq!(st(&c, "reserved"), "0");
    assert_eq!(st(&c, "bonds_held"), "0");

    commit_at(&mut c, 3, "b");
    env_at(accounts(0), NearToken::from_yoctonear(0), 4);
    c.on_payout_checked(1, Err(PromiseError::Failed));
    assert!(c.view_commit(1).unwrap().status == CommitStatus::Refused("registration check unavailable".into()));
}

#[test]
fn on_payout_checked_slot_taken_by_another_commit() {
    // Pending slot
    let mut c = funded_with(cfg(), 2 * AMT);
    commit_at(&mut c, 1, "a");
    commit_at(&mut c, 2, "b");
    registered(&mut c, 0, 3);
    registered(&mut c, 1, 4);
    assert!(c.view_commit(1).unwrap().status == CommitStatus::Refused("claim pending".into()));
    assert_eq!(inv_state(&c), json!({"Pending": 0}));

    // Awarded slot
    let mut d = funded_with(cfg(), 2 * AMT);
    commit_at(&mut d, 1, "a");
    commit_at(&mut d, 2, "b");
    registered(&mut d, 0, 3);
    verdict(&mut d, 0, 4, &good_verdict("a", &sha_hex(b"exploit")));
    registered(&mut d, 1, 5);
    assert!(d.view_commit(1).unwrap().status == CommitStatus::Refused("invariant already paid".into()));
    assert_eq!(inv_state(&d), json!({"Awarded": 0}));
}

#[test]
fn on_verdict_not_pending_is_noop() {
    let mut c = funded();
    commit_at(&mut c, 1, "a");
    env_promise(2, PromiseResult::Successful(b"null".to_vec()));
    c.on_verdict(0);
    assert!(get_logs().iter().any(|l| l.contains("not pending (awaiting-registration)")));
}

#[test]
fn on_verdict_award_moves_ledger() {
    let c = awarded();
    assert_eq!(st(&c, "escrow"), "1000000");
    assert_eq!(st(&c, "pool"), "0");
    assert_eq!(st(&c, "reserved"), "0");
    let cm = c.view_commit(0).unwrap();
    assert!(matches!(cm.status, CommitStatus::Awarded));
    assert_eq!(cm.h_enc.unwrap(), sha_hex(b"exploit"));
    assert_eq!(cm.deliver_by_ns, Some(1_200 + TTL));
    assert_eq!(inv_state(&c), json!({"Awarded": 0}));
}

#[test]
fn on_verdict_accepts_wrapped_verdicts() {
    let h = sha_hex(b"exploit");
    let v = good_verdict("a", &h);
    let wrappers = vec![
        Value::String(v.to_string()),
        json!({"a": 1, "output": v}),
        json!([1, {"x": 2}, v]),
    ];
    for w in wrappers {
        let mut c = funded();
        commit_at(&mut c, 1, "a");
        registered(&mut c, 0, 2);
        verdict(&mut c, 0, 3, &w);
        assert!(matches!(c.view_commit(0).unwrap().status, CommitStatus::Awarded), "{w}");
    }
}

#[test]
fn on_verdict_hunter_faults_slash_bond() {
    let h = sha_hex(b"exploit");
    let mut cases: Vec<(Value, String)> = vec![];
    let mut v = good_verdict("a", &h);
    v["broken"] = json!(false);
    cases.push((v.clone(), "no invariant broken".into()));
    v["err"] = json!("secret missing");
    cases.push((v, "secret missing".into()));
    cases.push((good_verdict("b", &h), "commit mismatch".into()));
    let mut v = good_verdict("a", &h);
    v["invariant_id"] = json!("other");
    cases.push((v, "wrong invariant".into()));
    let mut v = good_verdict("a", &h);
    v["h_snapshot"] = json!("00");
    cases.push((v, "snapshot mismatch".into()));
    cases.push((good_verdict("a", "zz"), "malformed h_enc".into()));
    for (v, why) in cases {
        let mut c = funded();
        commit_at(&mut c, 1, "a");
        registered(&mut c, 0, 2);
        verdict(&mut c, 0, 3, &v);
        assert!(c.view_commit(0).unwrap().status == CommitStatus::Refused(why.clone()));
        assert_eq!(st(&c, "slashed"), mn(500).as_yoctonear().to_string());
        assert_eq!(st(&c, "bonds_held"), "0");
        assert_eq!(st(&c, "reserved"), "0");
        assert_eq!(inv_state(&c), json!("Open"));
    }
}

#[test]
fn on_verdict_no_verdict_refund_then_slash_then_late() {
    let mut c = funded();
    // first: failed promise (deposit bounced) -> bond returned, counted
    commit_at(&mut c, 1_000, "a");
    registered(&mut c, 0, 1_100);
    env_promise(1_500, PromiseResult::Failed);
    c.on_verdict(0);
    assert!(c.view_commit(0).unwrap().status == CommitStatus::Refused("verifier unavailable".into()));
    assert_eq!(st(&c, "slashed"), "0");
    assert_eq!(st(&c, "bonds_held"), "0");
    assert_eq!(inv_state(&c), json!("Open"));

    // repeat within 24h with a null verdict -> slashed
    commit_at(&mut c, 2_000, "b");
    registered(&mut c, 1, 2_100);
    env_promise(2_500, PromiseResult::Successful(b"null".to_vec()));
    c.on_verdict(1);
    assert_eq!(st(&c, "slashed"), mn(500).as_yoctonear().to_string());
    assert!(get_logs().iter().any(|l| l.contains("repeat within 24h: slashed")));

    // late no-verdict (>= 10 min) refunds in full and is uncounted, even inside the window
    let late = 2_000 + LATE;
    commit_at(&mut c, 2_000, "c");
    registered(&mut c, 2, 2_100);
    env_promise(late, PromiseResult::Successful(b"not json".to_vec()));
    c.on_verdict(2);
    assert_eq!(st(&c, "slashed"), mn(500).as_yoctonear().to_string());
    assert!(get_logs().iter().any(|l| l.contains("bond returned")));
}

const LATE: u64 = 10 * 60_000_000_000;

#[test]
fn no_verdict_after_window_refunds_again() {
    let mut c = funded();
    commit_at(&mut c, 1_000, "a");
    registered(&mut c, 0, 1_100);
    env_promise(1_500, PromiseResult::Successful(b"null".to_vec()));
    c.on_verdict(0);
    let t = 1_500 + 25 * HOUR;
    commit_at(&mut c, t, "b");
    registered(&mut c, 1, t + 1);
    env_promise(t + 2, PromiseResult::Successful(b"null".to_vec()));
    c.on_verdict(1);
    assert_eq!(st(&c, "slashed"), "0");
}

#[test]
fn release_stale_paths() {
    let mut c = funded();
    commit_at(&mut c, 1_000, "a");
    let t = 1_000 + 30 * 60_000_000_000;
    // not stale yet
    env_at(accounts(0), NearToken::from_yoctonear(0), 2_000);
    assert!(panics(|| c.release_stale(0)));
    // pending -> released
    registered(&mut c, 0, 1_100);
    env_at(accounts(0), NearToken::from_yoctonear(0), t);
    c.release_stale(0);
    assert!(c.view_commit(0).unwrap().status == CommitStatus::Refused("verifier unavailable".into()));
    assert_eq!(inv_state(&c), json!("Open"));
    assert_eq!(st(&c, "reserved"), "0");
    assert_eq!(st(&c, "bonds_held"), "0");
    // refused is not stuck
    assert!(panics(|| c.release_stale(0)));
    // awaiting registration -> refund_commit
    commit_at(&mut c, t, "b");
    env_at(accounts(0), NearToken::from_yoctonear(0), t + 30 * 60_000_000_000);
    c.release_stale(1);
    assert!(c.view_commit(1).unwrap().status == CommitStatus::Refused("registration check unavailable".into()));
}

#[test]
fn deliver_guards_and_refusals() {
    let mut c = awarded();
    // wrong state
    let mut e = funded();
    env_at(accounts(4), NearToken::from_yoctonear(0), 1);
    assert!(panics(|| e.deliver(0, Base64VecU8(vec![]))));
    // not hunter
    env_at(other(), NearToken::from_yoctonear(0), 2_000);
    assert!(panics(|| c.deliver(0, Base64VecU8(b"exploit".to_vec()))));
    // mismatch
    env_at(accounts(4), NearToken::from_yoctonear(0), 2_000);
    c.deliver(0, Base64VecU8(b"wrong".to_vec()));
    assert!(get_logs().iter().any(|l| l.contains("delivery mismatch")));
    assert!(matches!(c.view_commit(0).unwrap().status, CommitStatus::Awarded));
    // expired
    env_at(accounts(4), NearToken::from_yoctonear(0), 1_200 + TTL + 1);
    c.deliver(0, Base64VecU8(b"exploit".to_vec()));
    assert!(get_logs().iter().any(|l| l.contains("delivery expired")));
}

#[test]
fn deliver_then_paid() {
    let mut c = delivered();
    let cm = c.view_commit(0).unwrap();
    assert!(matches!(cm.status, CommitStatus::Delivered));
    assert!(cm.paying);
    assert_eq!(inv_state(&c), json!({"Delivered": 0}));
    env_at(accounts(0), NearToken::from_yoctonear(0), 3_000);
    c.on_paid(0, U128(AMT), Ok(()));
    let cm = c.view_commit(0).unwrap();
    assert!(matches!(cm.status, CommitStatus::Paid));
    assert!(!cm.paying);
    assert_eq!(st(&c, "paid_total"), "1000000");
    assert_eq!(st(&c, "escrow"), "0");
    assert_eq!(st(&c, "bonds_held"), "0");
    assert_eq!(inv_state(&c), json!({"Paid": 0}));
}

#[test]
fn payout_failure_and_retry() {
    let mut c = delivered();
    // retry while in flight
    env_at(accounts(4), NearToken::from_yoctonear(0), 3_000);
    assert!(panics(|| c.retry_payout(0, None)));
    env_at(accounts(0), NearToken::from_yoctonear(0), 3_000);
    c.on_paid(0, U128(AMT), Err(PromiseError::Failed));
    assert!(get_logs().iter().any(|l| l.contains("PAYOUT FAILED 0")));
    assert!(matches!(c.view_commit(0).unwrap().status, CommitStatus::Delivered));
    assert_eq!(st(&c, "escrow"), "1000000");
    // non-hunter cannot redirect
    env_at(other(), NearToken::from_yoctonear(0), 3_100);
    assert!(panics(|| c.retry_payout(0, Some(other()))));
    // anyone retries to committed payout_to
    c.retry_payout(0, None);
    assert!(c.view_commit(0).unwrap().paying);
    assert_eq!(c.view_commit(0).unwrap().payout_to, accounts(5));
    env_at(accounts(0), NearToken::from_yoctonear(0), 3_200);
    c.on_paid(0, U128(AMT), Err(PromiseError::Failed));
    // hunter redirects
    env_at(accounts(4), NearToken::from_yoctonear(0), 3_300);
    c.retry_payout(0, Some(other()));
    assert_eq!(c.view_commit(0).unwrap().payout_to, other());
    // not delivered -> panic
    let mut a = awarded();
    env_at(accounts(4), NearToken::from_yoctonear(0), 3_300);
    assert!(panics(|| a.retry_payout(0, None)));
}

#[test]
fn expire_voids_awarded() {
    let mut c = awarded();
    env_at(other(), NearToken::from_yoctonear(0), 1_200 + TTL);
    assert!(panics(|| c.expire(0)), "not expired yet");
    env_at(other(), NearToken::from_yoctonear(0), 1_200 + TTL + 1);
    c.expire(0);
    assert!(c.view_commit(0).unwrap().status == CommitStatus::Voided);
    assert_eq!(st(&c, "pool"), "1000000");
    assert_eq!(st(&c, "escrow"), "0");
    assert_eq!(st(&c, "slashed"), mn(500).as_yoctonear().to_string());
    assert_eq!(inv_state(&c), json!("Open"));
    assert!(panics(|| c.expire(0)), "no longer awarded");
}

#[test]
fn withdraw_pool_rules() {
    let mut c = funded_with(
        { let mut x = cfg(); x.timelock_ns = 1_000; x },
        AMT,
    );
    env_at(other(), NearToken::from_yoctonear(0), 5_000);
    assert!(panics(|| { c.withdraw_pool(U128(1)); }), "protocol only");
    env_at(accounts(1), NearToken::from_yoctonear(0), 5_000);
    assert!(!c.withdraw_pool(U128(AMT + 1)));
    assert!(get_logs().iter().any(|l| l == "REFUSED: claim pending"));
    // timelock: created_at is 0, timelock 1000
    env_at(accounts(1), NearToken::from_yoctonear(0), 500);
    assert!(!c.withdraw_pool(U128(1)));
    assert!(get_logs().iter().any(|l| l == "REFUSED: timelock"));
    env_at(accounts(1), NearToken::from_yoctonear(0), 5_000);
    assert!(c.withdraw_pool(U128(400)));
    assert_eq!(st(&c, "pool"), "999600");
    assert_eq!(st(&c, "withdrawn_total"), "400");
    // callback success: no change; failure: restored
    env_at(accounts(0), NearToken::from_yoctonear(0), 5_001);
    c.on_withdrawn(U128(400), Ok(()));
    assert_eq!(st(&c, "pool"), "999600");
    c.on_withdrawn(U128(400), Err(PromiseError::Failed));
    assert_eq!(st(&c, "pool"), "1000000");
    assert_eq!(st(&c, "withdrawn_total"), "0");
}

#[test]
fn withdraw_slashed_rules() {
    let mut c = funded();
    env_at(other(), NearToken::from_yoctonear(0), 1);
    assert!(panics(|| c.withdraw_slashed()));
    env_at(accounts(1), NearToken::from_yoctonear(0), 1);
    assert!(panics(|| c.withdraw_slashed()), "nothing slashed");
    // slash via an expired award
    let mut c = awarded();
    env_at(other(), NearToken::from_yoctonear(0), 1_200 + TTL + 1);
    c.expire(0);
    env_at(accounts(1), NearToken::from_yoctonear(0), 1_200 + TTL + 2);
    c.withdraw_slashed();
    assert_eq!(st(&c, "slashed"), "0");
    assert!(get_logs().iter().any(|l| l.starts_with("WITHDRAW_SLASHED")));
}

fn other() -> AccountId {
    "mallory.near".parse().unwrap()
}

#[test]
fn on_payout_checked_noop_names_every_status() {
    fn noop(c: &mut Bounty, tag: &str) {
        env_at(accounts(0), NearToken::from_yoctonear(0), 9_000);
        c.on_payout_checked(0, Ok(None));
        assert!(get_logs().iter().any(|l| l.contains(&format!("(\"{tag}\")"))), "{tag}");
    }
    noop(&mut awarded(), "awarded");
    let mut d = delivered();
    noop(&mut d, "delivered");
    env_at(accounts(0), NearToken::from_yoctonear(0), 3_000);
    d.on_paid(0, U128(AMT), Ok(()));
    noop(&mut d, "paid");
    let mut v = awarded();
    env_at(other(), NearToken::from_yoctonear(0), 1_200 + TTL + 1);
    v.expire(0);
    noop(&mut v, "voided");
    let mut r = funded();
    commit_at(&mut r, 1, "a");
    env_at(accounts(0), NearToken::from_yoctonear(0), 2);
    r.on_payout_checked(0, Ok(None));
    noop(&mut r, "refused");
}
