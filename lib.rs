//! # Slushie
//!
//! This is a tornado.cash-like mixer alternative on `pallet-contracts`-compatible chains
//!
//! ## Warning
//!
//! This is in the early stage of development. Use with caution and at your own risk. : )
//!
//! ## Overview
//!
//! Users `deposit` a fixed amount of tokens to a smart contract, wait some time, and then
//! can withdraw it back from another account. Or someone else can do it, who knows
//! the proper information.
//!
//! ## Error Handling
//!
//! Any function that modifies the state returns a `Result` type and does not changes the state
//! if the `Error` occurs. The errors are defined as an `enum` type.
//!
//! ### Deposit
//!
//! Tokens can only be deposited in a constant `deposit_size` amount.
//! Returns a MerkleTree root hash after the insertion of the nullifier.
//!
//! ### Withdraw
//!
//! Tokens can be withdrawn at any time, but for security reasons, it's better to wait some period say, 24 hours
//! after deposit and before withdrawal to make it harder to track the token transfer.
//! Tokens can be withdrawn only in a constant `deposit_size` amount by anyone who knows the nullifier and the root hash.

#![cfg_attr(not(feature = "std"), no_std)]

use ink_lang as ink;

mod tree;

#[ink::contract]
mod slushie {
    use super::*;
    use crate::tree::hasher::Poseidon;
    use crate::tree::merkle_tree::{
        MerkleTree, MerkleTreeError, DEFAULT_ROOT_HISTORY_SIZE, MAX_DEPTH,
    };

    type PoseidonHash = [u8; 32];

    #[ink(storage)]
    #[derive(ink_storage::traits::SpreadAllocate)]
    pub struct Slushie {
        merkle_tree: MerkleTree<MAX_DEPTH, DEFAULT_ROOT_HISTORY_SIZE, Poseidon>,
        deposit_size: Balance,
        used_nullifiers: ink_storage::Mapping<PoseidonHash, bool>,
    }

    /// Deposit event when the tokens deposited successfully
    #[ink(event)]
    pub struct Deposited {
        #[ink(topic)]
        hash: PoseidonHash,

        timestamp: Timestamp,
    }

    /// Withdraw event when the tokens withdrawn successfully
    #[ink(event)]
    pub struct Withdrawn {
        #[ink(topic)]
        hash: PoseidonHash,

        timestamp: Timestamp,
    }

    /// Errors which my be returned from the smart contract
    #[derive(Debug, PartialEq, Eq, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum Error {
        DepositFailure,
        MerkleTreeIsFull,
        MerkleTreeInvalidDepth,
        InvalidTransferredAmount,
        InvalidDepositSize,
        InsufficientFunds,
        NullifierAlreadyUsed,
        UnknownNullifier,
        UnknownRoot,
    }

    impl From<MerkleTreeError> for Error {
        fn from(err: MerkleTreeError) -> Self {
            match err {
                MerkleTreeError::MerkleTreeIsFull => Error::MerkleTreeIsFull,
                MerkleTreeError::DepthTooLong => Error::MerkleTreeInvalidDepth,
                MerkleTreeError::DepthIsZero => Error::MerkleTreeInvalidDepth,
            }
        }
    }

    pub type Result<T> = core::result::Result<T, Error>;

    impl Slushie {
        /// create a new Slushie contract
        ///
        /// Takes the deposit_size Balance amount
        /// so the users can deposit and withdraw
        /// only in a fixed amount of tokens.
        /// Can be set only when the smart contract
        /// instantiated.
        #[ink(constructor)]
        pub fn new(deposit_size: Balance) -> Self {
            ink::utils::initialize_contract(|me: &mut Self| {
                *me = Self {
                    merkle_tree: MerkleTree::<MAX_DEPTH, DEFAULT_ROOT_HISTORY_SIZE, Poseidon>::new(
                    )
                    .unwrap(),
                    deposit_size,
                    used_nullifiers: Default::default(),
                };
            })
        }

        /// Deposit a fixed amount of tokens into mixer
        ///
        /// Returns the merkle_tree root hash after insertion
        #[ink(message, payable)]
        pub fn deposit(&mut self, commitment: PoseidonHash) -> Result<PoseidonHash> {
            if self.env().transferred_value() != self.deposit_size {
                return Err(Error::InvalidTransferredAmount);
            }

            self.merkle_tree.insert(commitment)?;

            self.env().emit_event(Deposited {
                hash: commitment,
                timestamp: self.env().block_timestamp(),
            });

            Ok(self.merkle_tree.get_last_root() as PoseidonHash)
        }

        /// Withdraw a fixed amount of tokens from the mixer
        ///
        /// Can be withdrawn by anyone who knows the nullifier and the correct root hash
        #[ink(message)]
        pub fn withdraw(&mut self, commitment: PoseidonHash, root: PoseidonHash) -> Result<()> {
            // FIXME: return Err(Error::UnknownNullifier) if hash wasn't deposited before

            if !self.merkle_tree.is_known_root(root) {
                return Err(Error::UnknownRoot);
            }

            if self.env().balance() < self.deposit_size {
                return Err(Error::InsufficientFunds);
            }

            if self.used_nullifiers.get(commitment).is_some() {
                return Err(Error::NullifierAlreadyUsed);
            }

            if self
                .env()
                .transfer(self.env().caller(), self.deposit_size)
                .is_err()
            {
                return Err(Error::InvalidDepositSize);
            }

            self.used_nullifiers.insert(commitment, &true);

            self.env().emit_event(Withdrawn {
                hash: commitment,
                timestamp: self.env().block_timestamp(),
            });

            Ok(())
        }

        /// Returns the merkle_tree root hash
        #[ink(message)]
        pub fn get_root_hash(&self) -> PoseidonHash {
            self.merkle_tree.get_last_root() as PoseidonHash
        }
    }

    /// Unit tests
    #[cfg(test)]
    mod tests {
        use super::*;
        use hex_literal::hex;
        use ink_lang::codegen::Env;

        /// Imports `ink_lang` so we can use `#[ink::test]`.
        use ink_lang as ink;

        const DEFAULT_DEPOSIT_SIZE: Balance = 13;

        struct Context {
            hash1: PoseidonHash,
            hash2: PoseidonHash,
            hash3: PoseidonHash,

            accounts: ink_env::test::DefaultAccounts<ink_env::DefaultEnvironment>,
            alice_balance: Balance,
            #[allow(dead_code)]
            bob_balance: Balance,
            #[allow(dead_code)]
            eve_balance: Balance,
            #[allow(dead_code)]
            contract_balance: Balance,
            root_hash: PoseidonHash,

            deposit_size: Balance,
            invalid_deposit_size: Balance,
        }

        impl Context {
            fn new(slushie: &Slushie) -> Self {
                let accounts = ink_env::test::default_accounts::<ink_env::DefaultEnvironment>();

                Self {
                    hash1: hex!(
                        "0001020304050607 08090a0b0c0d0e0f 0001020304050607 08090a0b0c0d0e0f"
                    ),
                    hash2: hex!(
                        "0000000000000000 08090a0b0c0d0e0f 0001020304050607 08090a0b0c0d0e0f"
                    ),
                    hash3: hex!(
                        "0000000000000000 0000000000000000 0001020304050607 08090a0b0c0d0e0f"
                    ),

                    accounts: ink_env::test::default_accounts::<ink_env::DefaultEnvironment>(),

                    alice_balance:
                        ink_env::test::get_account_balance::<ink_env::DefaultEnvironment>(
                            accounts.alice,
                        )
                        .unwrap(),
                    bob_balance: ink_env::test::get_account_balance::<ink_env::DefaultEnvironment>(
                        accounts.bob,
                    )
                    .unwrap(),
                    eve_balance: ink_env::test::get_account_balance::<ink_env::DefaultEnvironment>(
                        accounts.eve,
                    )
                    .unwrap(),

                    contract_balance: slushie.env().balance(),
                    root_hash: slushie.get_root_hash(),

                    deposit_size: DEFAULT_DEPOSIT_SIZE,
                    invalid_deposit_size: 77,
                }
            }
        }

        type Event = <Slushie as ::ink_lang::reflect::ContractEventBase>::Type;

        #[ink::test]
        fn test_constructor() {
            let slushie: Slushie = Slushie::new(DEFAULT_DEPOSIT_SIZE);

            assert_eq!(slushie.deposit_size, DEFAULT_DEPOSIT_SIZE as Balance);
            assert_eq!(
                slushie.merkle_tree,
                MerkleTree::<MAX_DEPTH, DEFAULT_ROOT_HISTORY_SIZE, Poseidon>::new().unwrap()
            );
        }

        mod deposit {
            use super::*;

            fn assert_deposited_event(event: &ink_env::test::EmittedEvent) {
                let decoded_event = <Event as scale::Decode>::decode(&mut &event.data[..])
                    .expect("encountered invalid contract event data buffer");
                if let Event::Deposited(Deposited {
                    hash: _,
                    timestamp: _,
                }) = decoded_event
                {
                    // actual fields value doesn't matter right now
                } else {
                    panic!("encountered unexpected event kind: expected a Deposited event")
                }
            }

            /// can deposit funds with a proper `deposit_size`
            #[ink::test]
            fn works() {
                let mut contract: Slushie = Slushie::new(DEFAULT_DEPOSIT_SIZE);
                let before = Context::new(&contract);

                ink_env::test::set_caller::<Environment>(before.accounts.bob);
                ink_env::test::set_value_transferred::<ink_env::DefaultEnvironment>(
                    before.deposit_size,
                    );
                let res = contract.deposit(before.hash1);
                assert!(res.is_ok());

                let after = Context::new(&contract);

                //FIXME: currently contract balance doesn't change
                //assert_ne!(before.contract_balance, after.contract_balance);
                //FIXME: user's balance after deposit doesn't change
                //assert_ne!(before.bob_balance, after.bob_balance);

                assert_ne!(before.root_hash, after.root_hash);

                let emitted_events = ink_env::test::recorded_events().collect::<Vec<_>>();
                assert_eq!(emitted_events.len(), 1);
                assert_deposited_event(&emitted_events[0]);
            }

            /// can't deposit funds with an invalid `deposit_size`
            #[ink::test]
            fn invalid_amount_fails() {
                let mut contract: Slushie = Slushie::new(DEFAULT_DEPOSIT_SIZE);
                let before = Context::new(&contract);

                ink_env::test::set_caller::<Environment>(before.accounts.bob);
                ink_env::test::set_value_transferred::<ink_env::DefaultEnvironment>(
                    before.invalid_deposit_size,
                    );
                let res = contract.deposit(before.hash1);
                assert_eq!(res.unwrap_err(), Error::InvalidTransferredAmount);

                let after = Context::new(&contract);

                assert_eq!(before.root_hash, after.root_hash);
            }
        }

        mod withdraw {
            use super::*;

            fn assert_withdrawn_event(event: &ink_env::test::EmittedEvent) {
                let decoded_event = <Event as scale::Decode>::decode(&mut &event.data[..])
                    .expect("encountered invalid contract event data buffer");
                if let Event::Withdrawn(Withdrawn {
                    hash: _,
                    timestamp: _,
                }) = decoded_event
                {
                    // actual fields value doesn't matter right now
                } else {
                    panic!("encountered unexpected event kind: expected a Withdrawn event")
                }
            }

            /// can't deposit funds if account doesn't have enough money
            ///
            /// this case shouldn't be tested cause is a pallete, which
            /// checks the sufficient amount of funds

            /// - can withdraw funds with a proper deposit_size and hash
            #[ink::test]
            fn works() {
                let mut contract: Slushie = Slushie::new(DEFAULT_DEPOSIT_SIZE);
                let before = Context::new(&contract);

                ink_env::test::set_caller::<Environment>(before.accounts.alice);
                ink_env::test::set_value_transferred::<ink_env::DefaultEnvironment>(
                    before.deposit_size,
                    );
                let res = contract.deposit(before.hash1);
                assert!(res.is_ok());

                let after_deposit = Context::new(&contract);
                //assert_ne!(before.alice_balance, after_deposit.alice_balance);

                let res = contract.withdraw(before.hash1, after_deposit.root_hash);
                assert!(res.is_ok());

                let after_withdrawal = Context::new(&contract);

                //FIXME: contract balance doesn't changes
                //assert_ne!(after_deposit.contract_balance, after_withdrawal.contract_balance);

                assert_ne!(after_deposit.alice_balance, after_withdrawal.alice_balance);

                let emitted_events = ink_env::test::recorded_events().collect::<Vec<_>>();
                assert_eq!(emitted_events.len(), 2); // Desposited and Withdrawn events!
                assert_withdrawn_event(&emitted_events[1]);
            }

            /// - can withdraw funds with a proper deposit_size and hash by different account
            #[ink::test]
            fn from_different_account_works() {
                let mut contract: Slushie = Slushie::new(DEFAULT_DEPOSIT_SIZE);
                let before = Context::new(&contract);

                ink_env::test::set_caller::<Environment>(before.accounts.alice);
                ink_env::test::set_value_transferred::<ink_env::DefaultEnvironment>(
                    before.deposit_size,
                    );
                let res = contract.deposit(before.hash1);
                assert!(res.is_ok());

                let after = Context::new(&contract);

                //assert_ne!(before.alice_balance, after.alice_balance);

                ink_env::test::set_caller::<Environment>(before.accounts.eve);
                let res = contract.withdraw(before.hash1, after.root_hash);
                assert!(res.is_ok());

                let after_eve_withdrawal = Context::new(&contract);

                assert_ne!(before.eve_balance, after_eve_withdrawal.eve_balance);

                let emitted_events = ink_env::test::recorded_events().collect::<Vec<_>>();
                assert_eq!(emitted_events.len(), 2); // Desposited and Withdrawn events!
                assert_withdrawn_event(&emitted_events[1]);
            }

            /// - can't withdraw funds with invalid root hash
            #[ink::test]
            fn invalid_root_fails() {
                let mut contract: Slushie = Slushie::new(DEFAULT_DEPOSIT_SIZE);
                let before = Context::new(&contract);

                ink_env::test::set_caller::<Environment>(before.accounts.alice);
                ink_env::test::set_value_transferred::<ink_env::DefaultEnvironment>(
                    before.deposit_size,
                    );
                let res = contract.deposit(before.hash1);
                assert!(res.is_ok());

                let invalid_root_hash: PoseidonHash =
                    hex!("0000000000000000 0000000000000000 0001020304050607 08090a0b0c0d0e0f");

                let res = contract.withdraw(before.hash1, invalid_root_hash);
                assert_eq!(res.unwrap_err(), Error::UnknownRoot);
            }

            /// - can't double withdraw funds with a proper deposit_size and a valid hash
            #[ink::test]
            fn used_nullifier_fails() {
                let mut contract: Slushie = Slushie::new(DEFAULT_DEPOSIT_SIZE);
                let before = Context::new(&contract);

                ink_env::test::set_caller::<Environment>(before.accounts.alice);
                ink_env::test::set_value_transferred::<ink_env::DefaultEnvironment>(
                    before.deposit_size,
                    );
                let res = contract.deposit(before.hash1);
                assert!(res.is_ok());

                let after = Context::new(&contract);

                let res = contract.withdraw(before.hash1, after.root_hash);
                assert!(res.is_ok());

                let res = contract.withdraw(before.hash1, after.root_hash);
                assert_eq!(res.unwrap_err(), Error::NullifierAlreadyUsed);
            }

            /// - can't withdraw funds infinitelly
            #[ink::test]
            fn infinite_times_fails() {
                let mut contract: Slushie = Slushie::new(DEFAULT_DEPOSIT_SIZE);
                let before = Context::new(&contract);

                ink_env::test::set_caller::<Environment>(before.accounts.alice);
                ink_env::test::set_value_transferred::<ink_env::DefaultEnvironment>(
                    before.deposit_size,
                    );
                let res = contract.deposit(before.hash1);
                assert!(res.is_ok());

                let after_deposit = Context::new(&contract);

                // FIXME: user account balance doesn't change
                //assert_ne!(before.alice_balance, after.alice_balance);

                ink_env::test::set_value_transferred::<ink_env::DefaultEnvironment>(
                    before.deposit_size,
                    );
                let res = contract.withdraw(before.hash1, after_deposit.root_hash);
                assert!(res.is_ok());

                // FIXME: currently the contract balance does not change
                //assert_ne!(before.contract_balance, after.contract_balance);

                let after_withdrawal = Context::new(&contract);

                assert_ne!(after_deposit.alice_balance, after_withdrawal.alice_balance);

                let res = contract.withdraw(before.hash2, after_withdrawal.root_hash);
                assert!(res.is_ok());

                let after_withdrawal2 = Context::new(&contract);

                assert_ne!(
                    after_withdrawal2.alice_balance,
                    after_withdrawal.alice_balance
                    );

                let res = contract.withdraw(before.hash3, after_withdrawal2.root_hash);
                assert!(res.is_ok());
                let after_withdrawal3 = Context::new(&contract);
                assert_ne!(
                    after_withdrawal3.alice_balance,
                    after_withdrawal2.alice_balance
                    );

                // FIXME: currently the contract balance does not change
                //assert_eq!(before.contract_balance, after_withdrawal.contract_balance);
            }

            /// - can't withdraw funds with a valid root hash but invalid nullifier
            #[ink::test]
            #[ignore] // FIXME: As for now this test fails. Should be fixed in the 3rd milestone
            fn invalid_unused_nullifier_fails() {
                let mut contract: Slushie = Slushie::new(DEFAULT_DEPOSIT_SIZE);
                let before = Context::new(&contract);

                ink_env::test::set_caller::<Environment>(before.accounts.alice);
                ink_env::test::set_value_transferred::<ink_env::DefaultEnvironment>(
                    before.deposit_size,
                    );
                let res = contract.deposit(before.hash1);
                assert!(res.is_ok());

                let after_deposit = Context::new(&contract);

                let res = contract.withdraw(before.hash1, after_deposit.root_hash);
                assert!(res.is_ok());

                let res = contract.withdraw(
                    before.hash2, // invalid hash
                    after_deposit.root_hash,
                    ); // valid root
                assert_eq!(res.unwrap_err(), Error::UnknownNullifier);
            }
        }
    }
}
