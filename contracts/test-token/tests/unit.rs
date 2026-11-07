use near_contract_standards::fungible_token::core::FungibleTokenCore;
use near_contract_standards::fungible_token::metadata::{FungibleTokenMetadataProvider, FT_METADATA_SPEC};
use near_contract_standards::fungible_token::resolver::FungibleTokenResolver;
use near_contract_standards::storage_management::StorageManagement;
use near_sdk::json_types::U128;
use near_sdk::test_utils::{get_logs, VMContextBuilder};
use near_sdk::{testing_env, AccountId, NearToken};
use test_token::Contract;

fn acc(s: &str) -> AccountId {
    s.parse().unwrap()
}

fn ctx(pred: &str, deposit: NearToken) {
    testing_env!(VMContextBuilder::new()
        .predecessor_account_id(acc(pred))
        .current_account_id(acc("token.testnet"))
        .attached_deposit(deposit)
        .build());
}

fn fresh() -> Contract {
    ctx("owner.testnet", NearToken::from_yoctonear(0));
    Contract::new(acc("owner.testnet"), U128(1_000), 6)
}

#[test]
fn new_mints_supply_to_owner_and_logs() {
    let c = fresh();
    assert_eq!(get_logs(), vec!["test token minted by us: 1000 to owner.testnet".to_string()]);
    assert_eq!(c.ft_total_supply(), U128(1_000));
    assert_eq!(c.ft_balance_of(acc("owner.testnet")), U128(1_000));
    assert_eq!(c.ft_balance_of(acc("nobody.testnet")), U128(0));
}

#[test]
fn metadata_reports_decimals() {
    let c = fresh();
    let m = c.ft_metadata();
    assert_eq!(m.spec, FT_METADATA_SPEC);
    assert_eq!(m.name, "Sealed Test USDC");
    assert_eq!(m.symbol, "tUSDC");
    assert_eq!(m.decimals, 6);
    assert!(m.icon.is_none() && m.reference.is_none() && m.reference_hash.is_none());
}

#[test]
fn storage_register_then_transfer() {
    let mut c = fresh();
    let bounds = c.storage_balance_bounds();
    ctx("hunter.testnet", bounds.min);
    let sb = c.storage_deposit(None, Some(true));
    assert_eq!(sb.total, bounds.min);
    assert_eq!(c.storage_balance_of(acc("hunter.testnet")).unwrap().total, bounds.min);
    assert!(c.storage_balance_of(acc("stranger.testnet")).is_none());

    ctx("owner.testnet", NearToken::from_yoctonear(1));
    c.ft_transfer(acc("hunter.testnet"), U128(250), Some("memo".into()));
    assert_eq!(c.ft_balance_of(acc("hunter.testnet")), U128(250));
    assert_eq!(c.ft_balance_of(acc("owner.testnet")), U128(750));
    assert_eq!(c.ft_total_supply(), U128(1_000));
}

#[test]
fn storage_withdraw_and_unregister() {
    let mut c = fresh();
    let bounds = c.storage_balance_bounds();
    ctx("hunter.testnet", bounds.min);
    c.storage_deposit(None, Some(true));
    ctx("hunter.testnet", NearToken::from_yoctonear(1));
    let w = c.storage_withdraw(None);
    assert_eq!(w.available, NearToken::from_yoctonear(0));
    assert!(c.storage_unregister(None));
    assert!(c.storage_balance_of(acc("hunter.testnet")).is_none());
}

#[test]
fn transfer_call_returns_promise() {
    let mut c = fresh();
    let bounds = c.storage_balance_bounds();
    ctx("bounty.testnet", bounds.min);
    c.storage_deposit(None, Some(true));
    ctx("owner.testnet", NearToken::from_yoctonear(1));
    let _ = c.ft_transfer_call(acc("bounty.testnet"), U128(100), None, "fund".into());
    // tokens are debited from sender optimistically before the receiver callback resolves
    assert_eq!(c.ft_balance_of(acc("bounty.testnet")), U128(100));
    assert_eq!(c.ft_balance_of(acc("owner.testnet")), U128(900));
}

#[test]
fn resolve_transfer_is_private_and_refunds_unused() {
    let mut c = fresh();
    let bounds = c.storage_balance_bounds();
    ctx("bounty.testnet", bounds.min);
    c.storage_deposit(None, Some(true));
    ctx("owner.testnet", NearToken::from_yoctonear(1));
    c.ft_transfer(acc("bounty.testnet"), U128(100), None);

    // private callback: predecessor must be the contract itself; promise result = unused amount "40"
    testing_env!(
        VMContextBuilder::new()
            .predecessor_account_id(acc("token.testnet"))
            .current_account_id(acc("token.testnet"))
            .build(),
        near_sdk::test_vm_config(),
        near_sdk::RuntimeFeesConfig::test(),
        Default::default(),
        vec![near_sdk::PromiseResult::Successful(b"\"40\"".to_vec())]
    );
    let used = c.ft_resolve_transfer(acc("owner.testnet"), acc("bounty.testnet"), U128(100));
    assert_eq!(used, U128(60));
    assert_eq!(c.ft_balance_of(acc("bounty.testnet")), U128(60));
    assert_eq!(c.ft_balance_of(acc("owner.testnet")), U128(940));
}

#[test]
#[should_panic]
fn resolve_transfer_rejects_external_caller() {
    let mut c = fresh();
    ctx("attacker.testnet", NearToken::from_yoctonear(0));
    c.ft_resolve_transfer(acc("owner.testnet"), acc("bounty.testnet"), U128(1));
}

#[test]
#[should_panic]
fn transfer_to_unregistered_panics() {
    let mut c = fresh();
    ctx("owner.testnet", NearToken::from_yoctonear(1));
    c.ft_transfer(acc("ghost.testnet"), U128(1), None);
}
