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
mod Slushie {
    use super::*;
    use crate::tree::merkle_tree::{
        MerkleTree, MerkleTreeError, DEFAULT_ROOT_HISTORY_SIZE, MAX_DEPTH,
    };

    type PoseidonHash = [u8; 32];

    #[ink(storage)]
    #[derive(ink_storage::traits::SpreadAllocate)]
    pub struct Slushie {
        merkle_tree: MerkleTree<MAX_DEPTH, DEFAULT_ROOT_HISTORY_SIZE>,
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
                    merkle_tree: MerkleTree::<MAX_DEPTH, DEFAULT_ROOT_HISTORY_SIZE>::new().unwrap(),
                    deposit_size,
                    used_nullifiers: Default::default(),
                };
            })
        }

        /// Deposit a fixed amount of tokens into mixer
        ///
        /// Returns the merkle_tree root hash after insertion
        #[ink(message, payable)]
        pub fn deposit(&mut self, hash: PoseidonHash) -> Result<PoseidonHash> {
            self.merkle_tree.insert(hash)?;

            if self.env().transferred_value() != self.deposit_size {
                return Err(Error::InvalidTransferredAmount); // FIXME: suggest a better name
            }

            self.env().emit_event(Deposited {
                hash,
                timestamp: self.env().block_timestamp(),
            });

            Ok(self.merkle_tree.get_last_root() as PoseidonHash)
        }

        /// Withdraw a fixed amount of tokens from the mixer
        ///
        /// Can be withdrawn by anyone who knows the nullifier and the correct root hash
        #[ink(message)]
        pub fn withdraw(&mut self, hash: PoseidonHash, root: PoseidonHash) -> Result<()> {
            if !self.merkle_tree.is_known_root(root) {
                return Err(Error::UnknownRoot);
            }

            if self.env().balance() < self.deposit_size {
                return Err(Error::InsufficientFunds);
            }

            if self
                .env()
                .transfer(self.env().caller(), self.deposit_size)
                .is_err()
            {
                return Err(Error::InvalidDepositSize);
            }

            if self.used_nullifiers.get(hash).is_some() {
                return Err(Error::NullifierAlreadyUsed);
            }

            self.used_nullifiers.insert(hash, &true);

            self.env().emit_event(Withdrawn {
                hash,
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

    /// Unit tests in Rust are normally defined within such a `#[cfg(test)]`
    /// module and test functions are marked with a `#[test]` attribute.
    /// The below code is technically just normal Rust code.
    #[cfg(test)]
    mod tests {
        /// Imports all the definitions from the outer scope so we can use them here.
        use super::*;

        /// Imports `ink_lang` so we can use `#[ink::test]`.
        use ink_lang as ink;

        /// We test if the default constructor does its job.
        #[ink::test]
        fn default_works() {
            let Slushie = Slushie::default();
            assert_eq!(Slushie.get(), false);
        }

        /// We test a simple use case of our contract.
        #[ink::test]
        fn it_works() {
            let mut Slushie = Slushie::new(false);
            assert_eq!(Slushie.get(), false);
            Slushie.flip();
            assert_eq!(Slushie.get(), true);
        }
    }
}
