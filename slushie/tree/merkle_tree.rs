#[cfg(feature = "std")]
use ink_primitives::KeyPtr;
#[cfg(feature = "std")]
use ink_storage::traits::{ExtKeyPtr, StorageLayout};
use ink_storage::traits::{PackedLayout, SpreadAllocate, SpreadLayout};

/// Merkle tree maximum depth
pub const MAX_DEPTH: usize = 32;
/// Merkle tree history size
pub const DEFAULT_ROOT_HISTORY_SIZE: usize = 100;

///Merkle tree with history for storing commitments in it
#[derive(scale::Encode, scale::Decode, PackedLayout, SpreadLayout, SpreadAllocate, PartialEq)]
#[cfg_attr(feature = "std", derive(Debug, StorageLayout))]
pub(crate) struct MerkleTree<
    const DEPTH: usize,
    const ROOT_HISTORY_SIZE: usize,
    Hash: MerkleTreeHasher,
> {
    ///Current root index in the history
    pub current_root_index: u64,
    /// Next leaf index
    pub next_index: u64,
    ///Hashes last filled subtrees on every level
    pub filled_subtrees: Array<Hash::Output, DEPTH>,
    /// Merkle tree roots history
    pub roots: Array<Hash::Output, ROOT_HISTORY_SIZE>,
}

impl<const DEPTH: usize, const ROOT_HISTORY_SIZE: usize, Hash: MerkleTreeHasher>
    MerkleTree<DEPTH, ROOT_HISTORY_SIZE, Hash>
{
    ///Create merkle tree
    pub fn new() -> Result<Self, MerkleTreeError> {
        if DEPTH > MAX_DEPTH {
            return Err(MerkleTreeError::DepthTooLong);
        }

        if DEPTH == 0 {
            return Err(MerkleTreeError::DepthIsZero);
        }

        let roots = Array([Hash::ZEROS[DEPTH - 1]; ROOT_HISTORY_SIZE]);

        let mut filled_subtrees: Array<Hash::Output, DEPTH> = Default::default();
        filled_subtrees.0.copy_from_slice(&Hash::ZEROS[0..DEPTH]);

        Ok(Self {
            current_root_index: 0,
            next_index: 0,
            filled_subtrees,
            roots,
        })
    }

    /// Get last root hash
    pub fn get_last_root(&self) -> Hash::Output {
        self.roots.0[self.current_root_index as usize]
    }

    /// Check existing provided root in roots history
    pub fn is_known_root(&self, root: Hash::Output) -> bool {
        if root == Default::default() {
            return false;
        }

        let root_history_size_u64 = ROOT_HISTORY_SIZE as u64;

        for i in 0..root_history_size_u64 {
            let current_index = ((root_history_size_u64 + self.current_root_index - i)
                % root_history_size_u64) as usize;

            if root == self.roots.0[current_index] {
                return true;
            }
        }

        false
    }

    ///Insert leaf in the merkle tree
    pub fn insert(&mut self, leaf: Hash::Output) -> Result<usize, MerkleTreeError> {
        let next_index = self.next_index as usize;

        if self.next_index == 2u64.pow(DEPTH as u32) {
            return Err(MerkleTreeError::MerkleTreeIsFull);
        }

        let root_history_size_u64 = ROOT_HISTORY_SIZE as u64;
        let mut current_index = next_index;
        let mut current_hash = leaf;

        for i in 0..DEPTH {
            let left;
            let right;

            if current_index % 2 == 0 {
                right = Hash::ZEROS[i];
                left = current_hash;

                self.filled_subtrees.0[i] = current_hash;
            } else {
                left = self.filled_subtrees.0[i];
                right = current_hash;
            }

            current_hash = Hash::hash_left_right(left, right);
            current_index /= 2;
        }

        self.current_root_index = (self.current_root_index + 1) % root_history_size_u64;

        self.roots.0[self.current_root_index as usize] = current_hash;

        self.next_index += 1;

        Ok(next_index)
    }
}

///Enum with contain merkle tree errors
#[derive(Debug, PartialEq)]
pub(crate) enum MerkleTreeError {
    ///Merkle tree is full
    MerkleTreeIsFull,
    ///Depth should be in range 1..MAX_DEPTH
    DepthTooLong,
    ///Depth can not be 0
    DepthIsZero,
}

#[derive(scale::Encode, scale::Decode, PackedLayout, SpreadLayout, SpreadAllocate, PartialEq)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct Array<T: Default + Clone + Copy, const N: usize>([T; N]);

#[cfg(feature = "std")]
use ink_metadata::layout::{ArrayLayout, Layout, LayoutKey};

use super::hasher::MerkleTreeHasher;

#[cfg(feature = "std")]
impl<T: Default + Clone + Copy, const N: usize> StorageLayout for Array<T, N>
where
    T: StorageLayout + SpreadLayout,
{
    fn layout(key_ptr: &mut KeyPtr) -> Layout {
        let len: u32 = N as u32;
        let elem_footprint = <T as SpreadLayout>::FOOTPRINT;
        Layout::Array(ArrayLayout::new(
            LayoutKey::from(key_ptr.next_for::<[T; N]>()),
            len,
            elem_footprint,
            <T as StorageLayout>::layout(&mut key_ptr.clone()),
        ))
    }
}

impl<T: Default + Clone + Copy, const N: usize> Default for Array<T, N> {
    fn default() -> Self {
        Self([Default::default(); N])
    }
}

#[cfg(test)]
mod tests {
    use dusk_bls12_381::BlsScalar;
    use ink_env::hash::{Blake2x256, CryptoHash};

    use crate::tree::hasher::{Blake, Poseidon};

    use super::*;
    const TEST_MAX_DEPTH: usize = 10;

    #[test]
    fn test_get_zero_root() {
        let tree = MerkleTree::<TEST_MAX_DEPTH, 30, Blake>::new().unwrap();
        assert_eq!(tree.get_last_root(), Blake::ZEROS[TEST_MAX_DEPTH - 1]);

        for i in 0..TEST_MAX_DEPTH {
            assert_eq!(tree.filled_subtrees.0[i], Blake::ZEROS[i]);
        }
    }

    #[test]
    fn test_insert() {
        let mut tree = MerkleTree::<TEST_MAX_DEPTH, 30, Blake>::new().unwrap();
        assert_eq!(tree.get_last_root(), Blake::ZEROS[TEST_MAX_DEPTH - 1]);

        tree.insert([4; 32]).unwrap();

        assert!(tree.is_known_root(Blake::ZEROS[TEST_MAX_DEPTH - 1]));
        assert!(!tree.is_known_root(Blake::ZEROS[4]));

        assert_ne!(tree.get_last_root(), Blake::ZEROS[TEST_MAX_DEPTH - 1]);
    }

    #[test]
    fn test_tree_indexes() {
        let mut tree = MerkleTree::<TEST_MAX_DEPTH, 30, Blake>::new().unwrap();

        for i in 0..2usize.pow(TEST_MAX_DEPTH as u32) {
            let index = tree.insert([i as u8; 32]).unwrap();
            assert_eq!(i, index);
            assert_eq!(i + 1, tree.next_index as usize);
        }
    }

    #[test]
    fn test_error_when_tree_is_full() {
        let mut tree = MerkleTree::<3, 30, Blake>::new().unwrap();

        for i in 0..2usize.pow(3) {
            tree.insert([i as u8 + 1; 32]).unwrap();
        }

        let err = tree.insert([6; 32]);

        assert_eq!(err, Err(MerkleTreeError::MerkleTreeIsFull));
    }

    #[test]
    fn test_error_when_tree_depth_too_long() {
        const MAX_DEPTH_PLUS_1: usize = MAX_DEPTH + 1;

        let tree = MerkleTree::<MAX_DEPTH_PLUS_1, 30, Blake>::new();

        assert_eq!(tree, Err(MerkleTreeError::DepthTooLong));
    }

    #[test]
    fn test_error_when_tree_depth_is_0() {
        let tree = MerkleTree::<0, 30, Blake>::new();

        assert_eq!(tree, Err(MerkleTreeError::DepthIsZero));
    }

    #[test]
    fn test_is_known_root() {
        let mut tree = MerkleTree::<TEST_MAX_DEPTH, 30, Blake>::new().unwrap();

        let mut known_roots = vec![Blake::ZEROS[TEST_MAX_DEPTH - 1]];

        for i in 0..6 {
            tree.insert([i as u8 * 2; 32]).unwrap();
            let known_root = tree.get_last_root();

            known_roots.push(known_root);
        }

        for root in &known_roots {
            assert!(tree.is_known_root(*root));
        }
    }

    #[test]
    fn test_roots_field() {
        let mut tree = MerkleTree::<TEST_MAX_DEPTH, 30, Blake>::new().unwrap();

        let mut roots = vec![Blake::ZEROS[TEST_MAX_DEPTH - 1]; 30];

        for i in 0..TEST_MAX_DEPTH {
            tree.insert([i as u8 * 3; 32]).unwrap();
            let root = tree.get_last_root();
            let index = tree.current_root_index;

            roots[index as usize] = root;
        }

        assert_eq!(&tree.roots.0[..], &roots[..]);
    }

    #[test]
    fn test_check_tree_zeros_correctness() {
        let mut tree = MerkleTree::<TEST_MAX_DEPTH, 3, Blake>::new().unwrap();
        for _i in 0..2u64.pow(TEST_MAX_DEPTH as u32) {
            tree.insert(Blake::ZEROS[0]).unwrap();
        }

        for i in 0..TEST_MAX_DEPTH {
            assert_eq!(tree.filled_subtrees.0[i], Blake::ZEROS[i]);
        }
    }

    #[test]
    fn test_check_zeros_correctness() {
        let mut result: [u8; 32] = Default::default();
        Blake2x256::hash(b"slushie", &mut result);

        for i in 0..MAX_DEPTH {
            assert_eq!(result, Blake::ZEROS[i]);

            Blake2x256::hash(&[result, result].concat(), &mut result);
        }
    }

    #[test]
    fn test_get_zero_root_poseidon() {
        let tree = MerkleTree::<TEST_MAX_DEPTH, 30, Poseidon>::new().unwrap();
        assert_eq!(tree.get_last_root(), Poseidon::ZEROS[TEST_MAX_DEPTH - 1]);

        for i in 0..TEST_MAX_DEPTH {
            assert_eq!(tree.filled_subtrees.0[i], Poseidon::ZEROS[i]);
        }
    }

    #[test]
    fn test_insert_poseidon() {
        let mut tree = MerkleTree::<TEST_MAX_DEPTH, 30, Poseidon>::new().unwrap();
        assert_eq!(tree.get_last_root(), Poseidon::ZEROS[TEST_MAX_DEPTH - 1]);

        tree.insert([4; 32]).unwrap();

        assert!(tree.is_known_root(Poseidon::ZEROS[TEST_MAX_DEPTH - 1]));
        assert!(!tree.is_known_root(Poseidon::ZEROS[4]));

        assert_ne!(tree.get_last_root(), Poseidon::ZEROS[TEST_MAX_DEPTH - 1]);
    }

    #[test]
    fn test_tree_indexes_poseidon() {
        let mut tree = MerkleTree::<TEST_MAX_DEPTH, 30, Poseidon>::new().unwrap();

        for i in 0..2usize.pow(TEST_MAX_DEPTH as u32) {
            let index = tree.insert([i as u8; 32]).unwrap();
            assert_eq!(i, index);
            assert_eq!(i + 1, tree.next_index as usize);
        }
    }

    #[test]
    fn test_error_when_tree_is_full_poseidon() {
        let mut tree = MerkleTree::<TEST_MAX_DEPTH, 30, Poseidon>::new().unwrap();

        for i in 0..2usize.pow(TEST_MAX_DEPTH as u32) {
            tree.insert([i as u8; 32]).unwrap();
        }

        let err = tree.insert([6; 32]);

        assert_eq!(err, Err(MerkleTreeError::MerkleTreeIsFull));
    }

    #[test]
    fn test_error_when_tree_depth_too_long_poseidon() {
        const MAX_DEPTH_PLUS_1: usize = MAX_DEPTH + 1;

        let tree = MerkleTree::<MAX_DEPTH_PLUS_1, 30, Poseidon>::new();

        assert_eq!(tree, Err(MerkleTreeError::DepthTooLong));
    }

    #[test]
    fn test_error_when_tree_depth_is_0_poseidon() {
        let tree = MerkleTree::<0, 30, Poseidon>::new();

        assert_eq!(tree, Err(MerkleTreeError::DepthIsZero));
    }

    #[test]
    fn test_is_known_root_poseidon() {
        let mut tree = MerkleTree::<TEST_MAX_DEPTH, 30, Poseidon>::new().unwrap();

        let mut known_roots = vec![Poseidon::ZEROS[TEST_MAX_DEPTH - 1]];

        for i in 0..6 {
            tree.insert([i as u8 * 2; 32]).unwrap();
            let known_root = tree.get_last_root();

            known_roots.push(known_root);
        }

        for root in &known_roots {
            assert!(tree.is_known_root(*root));
        }
    }

    #[test]
    fn test_roots_field_poseidon() {
        let mut tree = MerkleTree::<TEST_MAX_DEPTH, 30, Poseidon>::new().unwrap();

        let mut roots = vec![Poseidon::ZEROS[TEST_MAX_DEPTH - 1]; 30];

        for i in 0..TEST_MAX_DEPTH {
            tree.insert([i as u8 * 3; 32]).unwrap();
            let root = tree.get_last_root();
            let index = tree.current_root_index;

            roots[index as usize] = root;
        }

        assert_eq!(&tree.roots.0[..], &roots[..]);
    }

    #[test]
    fn test_check_tree_zeros_correctness_poseidon() {
        let mut tree = MerkleTree::<TEST_MAX_DEPTH, 30, Poseidon>::new().unwrap();
        for _i in 0..2u64.pow(TEST_MAX_DEPTH as u32) {
            tree.insert(Poseidon::ZEROS[0]).unwrap();
        }

        for i in 0..TEST_MAX_DEPTH {
            assert_eq!(tree.filled_subtrees.0[i], Poseidon::ZEROS[i]);
        }
    }

    #[test]
    fn test_check_zeros_correctness_poseidon() {
        let mut result: [u8; 32] = Default::default();
        Blake2x256::hash(b"slushie", &mut result);
        let result = Poseidon::bytes_to_u64(result);

        let mut result = BlsScalar::from_raw(result);

        for i in 0..MAX_DEPTH {
            assert_eq!(Poseidon::scalar_to_bytes(result), Poseidon::ZEROS[i]);
            result = dusk_poseidon::sponge::hash(&[result, result]);
        }
    }
}
