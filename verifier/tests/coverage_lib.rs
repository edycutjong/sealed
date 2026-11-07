//! Extra coverage for `verifier::execute`: revert/halt outcomes (traced) and a failing `validateInstance`.
use std::collections::BTreeMap;

use verifier::{execute, SnapAccount, Snapshot};

const PLAYER: &str = "0x00000000000000000000000000000000000000a1";
const VALIDATOR: &str = "0x00000000000000000000000000000000000000a2";
const FACTORY: &str = "0x00000000000000000000000000000000000000a3";
const INSTANCE: &str = "0x00000000000000000000000000000000000000a4";
const REVERTER: &str = "0x00000000000000000000000000000000000000b1";
const HALTER: &str = "0x00000000000000000000000000000000000000b2";

fn acct(code: &str) -> SnapAccount {
    SnapAccount { balance: "0".into(), nonce: 0, code: code.into(), storage: BTreeMap::new() }
}

fn snap(factory_code: &str) -> Snapshot {
    let mut accounts = BTreeMap::new();
    accounts.insert(PLAYER.to_string(), acct(""));
    accounts.insert(VALIDATOR.to_string(), acct(""));
    accounts.insert(FACTORY.to_string(), acct(factory_code));
    accounts.insert(INSTANCE.to_string(), acct(""));
    accounts.insert(REVERTER.to_string(), acct("0x5f5ffd")); // PUSH0 PUSH0 REVERT
    accounts.insert(HALTER.to_string(), acct("0xfe")); // INVALID
    Snapshot {
        v: 1,
        name: "t".into(),
        chain_id: 1,
        block_number: 1,
        timestamp: 1,
        validator: VALIDATOR.into(),
        factory: FACTORY.into(),
        instance: INSTANCE.into(),
        player: PLAYER.into(),
        accounts,
    }
}

#[test]
fn reverting_and_halting_txs_and_failing_validate_are_normal_verdicts() {
    // Tracing makes `execute` format every tx outcome (success / revert / halt).
    std::env::set_var("SEALED_TRACE", "1");
    let exploit = format!(
        r#"[{{"to":"{REVERTER}"}},{{"to":"{HALTER}"}},{{"to":"{INSTANCE}","data":"0x"}}]"#
    );
    // Factory reverts on validateInstance -> not broken, but no error.
    let (broken, gas, err) = execute(&snap("0x5f5ffd"), exploit.as_bytes()).expect("execute");
    assert!(!broken);
    assert!(gas > 0, "reverting/halting txs still burn gas");
    assert_eq!(err, None);
}

#[test]
fn validate_returning_one_is_broken() {
    // Factory returns uint256(1): PUSH1 1 PUSH0 MSTORE PUSH1 32 PUSH0 RETURN
    let (broken, _, err) = execute(&snap("0x60015f5260205ff3"), b"[]").expect("execute");
    assert!(broken);
    assert_eq!(err, None);
}

#[test]
fn invalid_exploit_json_is_reported_not_raised() {
    let (broken, gas, err) = execute(&snap("0x5f5ffd"), b"nope").expect("execute");
    assert!(!broken);
    assert_eq!(gas, 0);
    assert_eq!(err.as_deref(), Some("exploit invalid: json"));
}

use verifier::{load_db, parse_exploit, run, Input, Secrets};

fn err_of(s: &Snapshot) -> String {
    execute(s, b"[]").expect_err("must fail")
}

#[test]
fn execute_rejects_bad_snapshot_fields() {
    for field in ["player", "instance", "factory", "validator"] {
        let mut s = snap("");
        match field {
            "player" => s.player = "zz".into(),
            "instance" => s.instance = "zz".into(),
            "factory" => s.factory = "zz".into(),
            _ => s.validator = "zz".into(),
        }
        assert_eq!(err_of(&s), "bad address", "{field}");
    }
    let mut s = snap("");
    s.accounts.get_mut(PLAYER).unwrap().code = "0xzz".into();
    assert_eq!(err_of(&s), "bad code hex");
}

#[test]
fn load_db_rejects_bad_address_balance_and_storage() {
    let mut s = snap("");
    s.accounts.insert("nope".into(), acct(""));
    assert_eq!(load_db(&s).err().as_deref(), Some("bad address"));

    let mut s = snap("");
    s.accounts.get_mut(PLAYER).unwrap().balance = "0xzz".into();
    assert_eq!(load_db(&s).err().as_deref(), Some("bad uint"));

    let mut s = snap("");
    s.accounts.get_mut(PLAYER).unwrap().storage.insert("0xzz".into(), "1".into());
    assert_eq!(load_db(&s).err().as_deref(), Some("bad uint"));
    let mut s = snap("");
    s.accounts.get_mut(PLAYER).unwrap().storage.insert("1".into(), "0xzz".into());
    assert_eq!(load_db(&s).err().as_deref(), Some("bad uint"));

    let mut s = snap("0x5f5ffd");
    s.accounts.get_mut(PLAYER).unwrap().storage.insert("1".into(), "0x2".into());
    assert!(load_db(&s).is_ok());
}

#[test]
fn parse_exploit_reports_each_field_error() {
    let e = |j: &str| parse_exploit(j.as_bytes()).unwrap_err();
    assert_eq!(e(r#"[{"to":"zz"}]"#), "exploit invalid: to");
    assert_eq!(e(r#"[{"to":null,"data":"0xzz"}]"#), "exploit invalid: data");
    assert_eq!(e(r#"[{"to":null,"value":"0xzz"}]"#), "exploit invalid: value");
    let big = format!(r#"[{{"to":null,"data":"0x{}"}}]"#, "00".repeat(24 * 1024 + 1));
    assert_eq!(e(&big), "exploit invalid: calldata too large");
}

fn input(target: u8, pk: &str) -> Input {
    Input {
        target,
        invariant_id: "inv".into(),
        hunter: "hunter.near".into(),
        commit_hash: "00".into(),
        protocol_enc_pk: pk.into(),
        secrets: None,
    }
}

fn secrets(salt: &str, sk: &str) -> Secrets {
    Secrets { exploit: "[]".into(), salt: salt.into(), eph_sk: sk.into() }
}

#[test]
fn run_names_the_failing_input() {
    let good = "11".repeat(32);
    assert_eq!(run(&input(250, &good), &secrets(&good, &good), None).err().as_deref(), Some("unknown target"));
    assert_eq!(run(&input(0, &good), &secrets("zz", &good), None).err().as_deref(), Some("SALT: bad hex"));
    assert_eq!(run(&input(0, &good), &secrets(&good, "00"), None).err().as_deref(), Some("EPH_SK: want 32 bytes"));
    assert_eq!(run(&input(0, "x"), &secrets(&good, &good), None).err().as_deref(), Some("protocol_enc_pk: bad hex"));
    // Success path with limits and an err cap carried through.
    let r = run(&input(0, &good), &secrets(&good, &good), None).expect("run");
    assert!(!r.verdict.broken);
}
