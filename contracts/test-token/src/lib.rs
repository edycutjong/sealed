//! A minimal NEP-141 test token used only on testnet in place of Circle USDC (if that is unavailable on
//! NEAR testnet). Fixed supply, minted once to the deployer at `new`; there is NO mint, burn, or admin
//! method, so the "pool" a bounty holds is backed by real token balances the contract can never inflate.
//! The README labels every balance "test token minted by us".

use near_contract_standards::fungible_token::metadata::{
    FungibleTokenMetadata, FungibleTokenMetadataProvider, FT_METADATA_SPEC,
};
use near_contract_standards::fungible_token::{FungibleToken, FungibleTokenCore, FungibleTokenResolver};
use near_sdk::json_types::U128;
use near_sdk::{near, AccountId, NearToken, PanicOnDefault, PromiseOrValue};

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Contract {
    token: FungibleToken,
    decimals: u8,
}

#[near]
impl Contract {
    /// Mints the whole `total_supply` to `owner` once. No other code path ever changes the supply.
    #[init]
    pub fn new(owner: AccountId, total_supply: U128, decimals: u8) -> Self {
        let mut token = FungibleToken::new(b"t".to_vec());
        token.internal_register_account(&owner);
        token.internal_deposit(&owner, total_supply.0);
        near_sdk::env::log_str(&format!("test token minted by us: {} to {owner}", total_supply.0));
        Self { token, decimals }
    }
}

#[near]
impl FungibleTokenCore for Contract {
    #[payable]
    fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>) {
        self.token.ft_transfer(receiver_id, amount, memo)
    }
    #[payable]
    fn ft_transfer_call(
        &mut self,
        receiver_id: AccountId,
        amount: U128,
        memo: Option<String>,
        msg: String,
    ) -> PromiseOrValue<U128> {
        self.token.ft_transfer_call(receiver_id, amount, memo, msg)
    }
    fn ft_total_supply(&self) -> U128 {
        self.token.ft_total_supply()
    }
    fn ft_balance_of(&self, account_id: AccountId) -> U128 {
        self.token.ft_balance_of(account_id)
    }
}

#[near]
impl FungibleTokenResolver for Contract {
    #[private]
    fn ft_resolve_transfer(
        &mut self,
        sender_id: AccountId,
        receiver_id: AccountId,
        amount: U128,
    ) -> U128 {
        self.token.ft_resolve_transfer(sender_id, receiver_id, amount)
    }
}

// NEP-145 storage management: hunters/bounties must register before receiving the token.
use near_contract_standards::storage_management::{StorageBalance, StorageBalanceBounds, StorageManagement};

#[near]
impl StorageManagement for Contract {
    #[payable]
    fn storage_deposit(&mut self, account_id: Option<AccountId>, registration_only: Option<bool>) -> StorageBalance {
        self.token.storage_deposit(account_id, registration_only)
    }
    #[payable]
    fn storage_withdraw(&mut self, amount: Option<NearToken>) -> StorageBalance {
        self.token.storage_withdraw(amount)
    }
    #[payable]
    fn storage_unregister(&mut self, force: Option<bool>) -> bool {
        self.token.storage_unregister(force)
    }
    fn storage_balance_bounds(&self) -> StorageBalanceBounds {
        self.token.storage_balance_bounds()
    }
    fn storage_balance_of(&self, account_id: AccountId) -> Option<StorageBalance> {
        self.token.storage_balance_of(account_id)
    }
}

#[near]
impl FungibleTokenMetadataProvider for Contract {
    fn ft_metadata(&self) -> FungibleTokenMetadata {
        FungibleTokenMetadata {
            spec: FT_METADATA_SPEC.to_string(),
            name: "Sealed Test USDC".to_string(),
            symbol: "tUSDC".to_string(),
            icon: None,
            reference: None,
            reference_hash: None,
            decimals: self.decimals,
        }
    }
}
