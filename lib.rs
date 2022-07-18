#![cfg_attr(not(feature = "std"), no_std)]

use ink_lang as ink;

mod tree;

#[ink::contract]
mod Slushie {
    use super::*;
    use crate::tree::merkle_tree::{MerkleTree, MerkleTreeError, MAX_DEPTH};

    type PoseidonHash = [u8; 32];

    #[ink(storage)]
    #[derive(ink_storage::traits::SpreadAllocate)]
    pub struct Slushie {
        merkle_tree: MerkleTree<MAX_DEPTH>,
        deposit_size: Balance,
        used_nullifiers: ink_storage::Mapping<PoseidonHash, bool>,
    }

    #[ink(event)]
    pub struct DepositEvent {
        #[ink(topic)]
        hash: PoseidonHash,

        timestamp: Timestamp,
    }

    #[ink(event)]
    pub struct WithdrawEvent {
        #[ink(topic)]
        hash: PoseidonHash,

        timestamp: Timestamp,
    }

    #[derive(Debug, PartialEq, Eq, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum Error {
        DepositFailure,
        MerkleTreeIsFull,
        InvalidTransferredAmount,
        WithdrawalFailure,
        WithdrawalFailure_InvalidDepositSize,
        WithdrawalFailure_InsufficientFunds,
        WithdrawalFailure_NullifierAlreadyUsed,
        UnknownRoot,
    }

    pub type Result<T> = core::result::Result<T, Error>;

    impl Slushie {
        /// create a new Slushie contract
        ///
        /// Takes the deposit_size Balance amount
        /// so the users can deposit and withdraw
        /// only a fixed amount of tokens.
        #[ink(constructor)]
        pub fn new(deposit_size: Balance) -> Self {
            ink::utils::initialize_contract(|me: &mut Self| {
                *me = Self { merkle_tree: MerkleTree::<MAX_DEPTH>::new().unwrap(),
                    deposit_size,
                    used_nullifiers: Default::default(),
                };
            })
        }

        
        #[ink(message, payable)]
        pub fn deposit(&mut self, hash: PoseidonHash) -> Result<PoseidonHash> {
            let res = self.merkle_tree.insert(hash);
            if res.is_err() {
                // FIXME: implement From trait for MerkleTreeError;
                match res {
                    Err(MerkleTreeError::MerkleTreeIsFull) => return Err(Error::MerkleTreeIsFull),
                    _ => return Err(Error::DepositFailure),
                }
            }

            if self.env().transferred_value() != self.deposit_size {
                return Err(Error::InvalidTransferredAmount); // FIXME: suggest a better name
            }

            self.env().emit_event(
                DepositEvent {
                    hash,
                    timestamp: self.env().block_timestamp(),
                });

            Ok(self.merkle_tree.get_last_root() as PoseidonHash)
        }

        #[ink(message)]
        pub fn withdraw(&mut self, hash: PoseidonHash, root: PoseidonHash) -> Result<()> {
            if !self.merkle_tree.is_known_root(root) {
                return Err(Error::UnknownRoot);
            }

            if self.env().balance() < self.deposit_size {
                return Err(Error::WithdrawalFailure_InsufficientFunds);
            }

            if self.env().transfer(self.env().caller(), self.deposit_size).is_err() {
                return Err(Error::WithdrawalFailure_InvalidDepositSize);
            }

            if self.used_nullifiers.get(hash).is_some() {
                return Err(Error::WithdrawalFailure_NullifierAlreadyUsed);
            }

            self.used_nullifiers.insert(hash, &true);

            self.env().emit_event(
                WithdrawEvent {
                    hash,
                    timestamp: self.env().block_timestamp(),
                });

            Ok(())
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
