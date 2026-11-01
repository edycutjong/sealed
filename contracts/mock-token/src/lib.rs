//! A NEP-141 subset for the bounty tests: `storage_balance_of` (registration), `ft_transfer` (payout),
//! `ft_balance_of`, plus a `fail_transfer` flag (a payout fails after `deliver`, escrow stays owed) and a
//! `burn_gas_on_reg` flag (the registration callback starves, commit stays AwaitingRegistration).

use near_sdk::json_types::U128;
use near_sdk::serde_json::{json, Value};
use near_sdk::store::LookupMap;
use near_sdk::{env, near, AccountId, PanicOnDefault};

/// Burn until the call traps on gas exhaustion, so `storage_balance_of` fails outright and the bounty's
/// `on_payout_checked` sees a `PromiseError` (the "registration check unavailable" path).
fn burn_all_gas() -> ! {
    loop {
        let _ = env::sha256(b"burn");
    }
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct MockToken {
    balances: LookupMap<AccountId, u128>,
    registered: LookupMap<AccountId, bool>,
    fail_transfer: bool,
    burn_gas_on_reg: bool,
}

#[near]
impl MockToken {
    #[init]
    pub fn new() -> Self {
        Self {
            balances: LookupMap::new(b"b"),
            registered: LookupMap::new(b"r"),
            fail_transfer: false,
            burn_gas_on_reg: false,
        }
    }

    pub fn register(&mut self, account_id: AccountId) {
        self.registered.insert(account_id, true);
    }
    pub fn set_fail_transfer(&mut self, v: bool) {
        self.fail_transfer = v;
    }
    pub fn set_burn_gas_on_reg(&mut self, v: bool) {
        self.burn_gas_on_reg = v;
    }
    pub fn mint(&mut self, account_id: AccountId, amount: U128) {
        let b = self.balances.get(&account_id).copied().unwrap_or(0);
        self.balances.insert(account_id, b + amount.0);
    }
    pub fn ft_balance_of(&self, account_id: AccountId) -> U128 {
        U128(self.balances.get(&account_id).copied().unwrap_or(0))
    }

    pub fn storage_balance_of(&self, account_id: AccountId) -> Option<Value> {
        if self.burn_gas_on_reg {
            burn_all_gas();
        }
        if self.registered.get(&account_id).copied().unwrap_or(false) {
            Some(json!({ "total": "1250000000000000000000", "available": "0" }))
        } else {
            None
        }
    }

    #[payable]
    pub fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>) {
        let _ = memo;
        if self.fail_transfer {
            env::panic_str("ft_transfer refused (test)");
        }
        let b = self.balances.get(&receiver_id).copied().unwrap_or(0);
        self.balances.insert(receiver_id, b + amount.0);
    }
}
