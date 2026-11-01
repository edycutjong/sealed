//! Build a level snapshot natively: the validator (Ethernaut stand-in) deploys the level factory, then calls
//! `createInstance(player)`; the resulting state is dumped as the committed snapshot the verifier embeds.
//!
//! usage: snapgen <name> <forge-artifact.json> <create_value_wei> > verifier/snapshots/<name>.json

use std::collections::BTreeMap;

use revm::{
    context::result::{ExecutionResult, Output},
    database::{CacheDB, EmptyDB},
    primitives::{Address, Bytes, TxKind, U256},
    state::AccountInfo,
    ExecuteCommitEvm,
};
use verifier::{build_evm, tx, SnapAccount, Snapshot};

const VALIDATOR: &str = "0x1000000000000000000000000000000000000001";
const PLAYER: &str = "0x2000000000000000000000000000000000000002";
const PLAYER_BALANCE: u128 = 1_000_000_000_000_000_000; // 1 ether
const VALIDATOR_BALANCE: u128 = 100_000_000_000_000_000_000; // 100 ether

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let (name, artifact, value) = (&a[1], &a[2], a[3].parse::<u128>().expect("value"));
    let art: serde_json::Value = serde_json::from_slice(&std::fs::read(artifact).expect("artifact")).expect("json");
    let initcode = hex::decode(art["bytecode"]["object"].as_str().expect("bytecode").trim_start_matches("0x"))
        .expect("hex");

    let validator: Address = VALIDATOR.parse().unwrap();
    let player: Address = PLAYER.parse().unwrap();
    let mut db = CacheDB::new(EmptyDB::default());
    db.insert_account_info(validator, AccountInfo { balance: U256::from(VALIDATOR_BALANCE), ..Default::default() });
    db.insert_account_info(player, AccountInfo { balance: U256::from(PLAYER_BALANCE), ..Default::default() });

    let mut snap = Snapshot {
        v: 1,
        name: name.clone(),
        chain_id: 31337,
        block_number: 1,
        timestamp: 1_762_000_000,
        validator: VALIDATOR.into(),
        factory: String::new(),
        instance: String::new(),
        player: PLAYER.into(),
        accounts: BTreeMap::new(),
    };
    let mut evm = build_evm(&snap, db);

    let r = evm.transact_commit(tx(validator, TxKind::Create, Bytes::from(initcode), U256::ZERO)).expect("deploy");
    let factory = match r {
        ExecutionResult::Success { output: Output::Create(_, Some(addr)), .. } => addr,
        other => panic!("factory deploy failed: {other:?}"),
    };
    let mut data = vec![0x77, 0x26, 0xf7, 0x76]; // createInstance(address)
    data.extend_from_slice(&[0u8; 12]);
    data.extend_from_slice(player.as_slice());
    let r = evm
        .transact_commit(tx(validator, TxKind::Call(factory), Bytes::from(data), U256::from(value)))
        .expect("createInstance");
    let instance = match r {
        ExecutionResult::Success { output, .. } => Address::from_slice(&output.data()[12..32]),
        other => panic!("createInstance failed: {other:?}"),
    };

    let db = &evm.ctx.journaled_state.database;
    for (addr, acc) in db.cache.accounts.iter() {
        let code = acc.info.code.as_ref().map(|c| hex::encode(c.original_bytes())).unwrap_or_default();
        let storage = acc
            .storage
            .iter()
            .filter(|(_, v)| !v.is_zero())
            .map(|(k, v)| (format!("{k:#x}"), format!("{v:#x}")))
            .collect();
        snap.accounts.insert(
            format!("{addr:#x}"),
            SnapAccount { balance: format!("{:#x}", acc.info.balance), nonce: acc.info.nonce, code, storage },
        );
    }
    snap.factory = format!("{factory:#x}");
    snap.instance = format!("{instance:#x}");
    println!("{}", serde_json::to_string_pretty(&snap).unwrap());
}
