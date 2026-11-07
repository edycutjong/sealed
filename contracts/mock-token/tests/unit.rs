use mock_token::MockToken;
use near_sdk::json_types::U128;
use near_sdk::test_utils::VMContextBuilder;
use near_sdk::{testing_env, AccountId};

fn acc(s: &str) -> AccountId {
    s.parse().unwrap()
}

fn fresh() -> MockToken {
    testing_env!(VMContextBuilder::new().build());
    MockToken::new()
}

#[test]
fn balances_default_zero_and_mint_accumulates() {
    let mut t = fresh();
    assert_eq!(t.ft_balance_of(acc("a.testnet")), U128(0));
    t.mint(acc("a.testnet"), U128(5));
    t.mint(acc("a.testnet"), U128(7));
    assert_eq!(t.ft_balance_of(acc("a.testnet")), U128(12));
    assert_eq!(t.ft_balance_of(acc("b.testnet")), U128(0));
}

#[test]
fn storage_balance_of_reflects_registration() {
    let mut t = fresh();
    assert!(t.storage_balance_of(acc("a.testnet")).is_none());
    t.register(acc("a.testnet"));
    let v = t.storage_balance_of(acc("a.testnet")).unwrap();
    assert_eq!(v["total"], "1250000000000000000000");
    assert_eq!(v["available"], "0");
    assert!(t.storage_balance_of(acc("b.testnet")).is_none());
}

#[test]
fn ft_transfer_credits_receiver() {
    let mut t = fresh();
    t.ft_transfer(acc("a.testnet"), U128(3), Some("memo".to_string()));
    t.ft_transfer(acc("a.testnet"), U128(4), None);
    assert_eq!(t.ft_balance_of(acc("a.testnet")), U128(7));
}

#[test]
#[should_panic(expected = "ft_transfer refused (test)")]
fn ft_transfer_fails_when_flag_set() {
    let mut t = fresh();
    t.set_fail_transfer(true);
    t.ft_transfer(acc("a.testnet"), U128(3), None);
}

#[test]
fn fail_transfer_flag_can_be_cleared() {
    let mut t = fresh();
    t.set_fail_transfer(true);
    t.set_fail_transfer(false);
    t.ft_transfer(acc("a.testnet"), U128(3), None);
    assert_eq!(t.ft_balance_of(acc("a.testnet")), U128(3));
}

#[test]
fn burn_gas_flag_traps_on_gas_exhaustion() {
    let mut t = fresh();
    t.set_burn_gas_on_reg(true);
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        t.storage_balance_of(acc("a.testnet"))
    }));
    assert!(r.is_err());
}
