use hex_literal::hex;
use ink_env::hash::{Blake2x256, CryptoHash};
use ink_prelude::vec::Vec;
use ink_storage::traits::{PackedLayout, SpreadLayout, StorageLayout};

/// Merkle tree history size
pub const ROOT_HISTORY_SIZE: u64 = 30;

/// Merkle tree maximum depth
pub const MAX_DEPTH: usize = 20;

///Merkle tree with history for storing commitments in it
#[derive(scale::Encode, scale::Decode, PackedLayout, SpreadLayout, PartialEq)]
#[cfg_attr(feature = "std", derive(Debug, StorageLayout))]
pub(crate) struct MerkleTree<const DEPTH: usize> {
    ///Current root index in the history
    pub current_root_index: u64,
    /// Next leaf index
    pub next_index: u64,
    ///Hashes last filled subtrees on every level
    pub filled_subtrees: Vec<[u8; 32]>,
    /// Merkle tree roots history
    pub roots: Vec<[u8; 32]>,
}

impl<const DEPTH: usize> MerkleTree<DEPTH> {
    ///Create merkle tree
    pub fn new() -> Result<Self, MerkleTreeError> {
        if DEPTH > MAX_DEPTH {
            return Err(MerkleTreeError::DepthTooLong);
        }

        if DEPTH == 0 {
            return Err(MerkleTreeError::DepthIsZero);
        }

        let mut roots = Vec::with_capacity(ROOT_HISTORY_SIZE as usize);
        roots.push(ZEROS[DEPTH - 1]);

        let mut filled_subtrees = Vec::with_capacity(DEPTH);
        filled_subtrees.extend_from_slice(&ZEROS[0..DEPTH]);

        Ok(Self {
            current_root_index: 0,
            next_index: 0,
            filled_subtrees,
            roots,
        })
    }

    /// Get last root hash
    pub fn get_last_root(&self) -> [u8; 32] {
        self.roots[self.current_root_index as usize]
    }

    /// Check existing provided root in roots history
    pub fn is_known_root(&self, root: [u8; 32]) -> bool {
        if root == [0; 32] {
            return false;
        }

        for i in 0..ROOT_HISTORY_SIZE {
            let current_index =
                ((ROOT_HISTORY_SIZE + self.current_root_index - i) % ROOT_HISTORY_SIZE) as usize;

            if root == self.roots.get(current_index).copied().unwrap_or([0; 32]) {
                return true;
            }
        }

        false
    }

    ///Insert leaf in the merkle tree
    pub fn insert(&mut self, leaf: [u8; 32]) -> Result<usize, MerkleTreeError> {
        let next_index = self.next_index as usize;

        if self.next_index == 2u64.pow(DEPTH as u32) {
            return Err(MerkleTreeError::MerkleTreeIsFull);
        }

        let mut current_index = next_index;
        let mut current_hash = leaf;

        for i in 0..DEPTH {
            let left;
            let right;

            if current_index % 2 == 0 {
                right = ZEROS[i];
                left = current_hash;

                if self.filled_subtrees.get(i).is_some() {
                    self.filled_subtrees[i] = current_hash;
                } else {
                    self.filled_subtrees.push(current_hash);
                };
            } else {
                left = self.filled_subtrees[i];
                right = current_hash;
            }

            current_hash = Self::hash_left_right(left, right);
            current_index /= 2;
        }

        self.current_root_index = (self.current_root_index + 1) % ROOT_HISTORY_SIZE;

        if self.roots.get(self.current_root_index as usize).is_some() {
            self.roots[self.current_root_index as usize] = current_hash;
        } else {
            self.roots.push(current_hash);
        };

        self.next_index += 1;

        Ok(next_index)
    }

    /// Calculate hash for provided left and right subtrees
    fn hash_left_right(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
        let mut result = [0; 32];
        Blake2x256::hash(&[left, right].concat(), &mut result);

        result
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

///Array with zero elements(every leaf is [0;32]) for a MerkleTree with Blake2x256
const ZEROS: [[u8; 32]; 20] = [
    hex!("0000000000000000000000000000000000000000000000000000000000000000"),
    hex!("0EB923B0CBD24DF54401D998531FEEAD35A47A99F4DEED205DE4AF81120F9761"),
    hex!("85C09AF929492A871E4FAE32D9D5C36E352471CD659BCDB61DE08F1722ACC3B1"),
    hex!("B22DF1A126B5BA4E33C16FD6157507610E55FFCE20DAE7AC44CAE168A463612A"),
    hex!("209155A276CA3C2417E3876971DD587DD64ED9FCB8EF1FD6E7589EF4255C967F"),
    hex!("6F7889DDD723CE6131FF105F416726118E1CF771B81265253B5C59AA6F87C24C"),
    hex!("6659A5716ACBAAA36B9F81157F9687E0CE9E9851218164900443DE7287F85FAD"),
    hex!("0F6E4E768A8FECBFD286712CA7C4DE283082448CCCBB71DB1D47E93F5327677E"),
    hex!("66C4270C625B9E96B934B3F56D9301C44C823D08B342B2CD95EE24519397C14A"),
    hex!("3DA3596117E16FFE6091C17736590AC20A3CA9DCFCD24EA5EECE12D51206F38E"),
    hex!("FE4EDE8D20B3EF44983B3D70529CCA052065F30CF155DA98F33096F61E6F627B"),
    hex!("C77F5D52CCC512B186AB8533CF2D8129DD927E78D013EE8A1B3A842EE9CA5EE1"),
    hex!("674A4A9A64830B69D84541C46E50DE1090B8D3498B4B65820603D0B933F9B01F"),
    hex!("4C3E98BCAE305BF73E4861A6707F6F074AE3E6C9F7DE8DB2832ACE4386F35B33"),
    hex!("76E19E692D91BB8522CC5A03AA6BA3EE2D8DA51C0E7286ED785DFCDFC213ED45"),
    hex!("A76AE9FA1E56382AC756DADD963493523B8B41120FC1F987B639F70C5658A72A"),
    hex!("B7660DF21E8A12DA4485FAAB8D13765885F0FFE50D083138F82C517E1D656CFE"),
    hex!("6B014A0CA5D179A10DFABDFA33E944040D7BB52880EA83B7D8A3185DAEA44854"),
    hex!("3CE680D5CE538F3777A78492A8BDFCF550A9F2390CA4BB9E4917D7BD67542B65"),
    hex!("3C2A1ECE2DE84AED35551877D16D685CBB1C3093B1BBE4520BE7FA6AC2955B23"),
];

#[cfg(any(feature = "std", tests))]
mod tests {
    use super::*;

    #[test]
    fn test_get_zero_root() {
        let tree = MerkleTree::<7>::new().unwrap();
        assert_eq!(tree.get_last_root(), ZEROS[6]);

        for i in 0..7 {
            assert_eq!(tree.filled_subtrees[i], ZEROS[i]);
        }
    }

    #[test]
    fn test_insert() {
        let mut tree = MerkleTree::<10>::new().unwrap();
        assert_eq!(tree.get_last_root(), ZEROS[9]);

        tree.insert([4; 32]).unwrap();

        assert!(tree.is_known_root(ZEROS[9]));
        assert!(!tree.is_known_root(ZEROS[4]));

        assert_ne!(tree.get_last_root(), ZEROS[9]);
    }

    #[test]
    fn test_tree_indexes() {
        let mut tree = MerkleTree::<2>::new().unwrap();

        for i in 0..4usize {
            let index = tree.insert([i as u8; 32]).unwrap();
            assert_eq!(i, index);
            assert_eq!(i + 1, tree.next_index as usize);
        }
    }

    #[test]
    fn test_error_when_tree_is_full() {
        let mut tree = MerkleTree::<3>::new().unwrap();

        for i in 0..2usize.pow(3) {
            tree.insert([i as u8 + 1; 32]).unwrap();
        }

        let err = tree.insert([6; 32]);

        assert_eq!(err, Err(MerkleTreeError::MerkleTreeIsFull));
    }

    #[test]
    fn test_error_when_tree_depth_too_long() {
        let tree = MerkleTree::<21>::new();

        assert_eq!(tree, Err(MerkleTreeError::DepthTooLong));
    }

    #[test]
    fn test_error_when_tree_depth_is_0() {
        let tree = MerkleTree::<0>::new();

        assert_eq!(tree, Err(MerkleTreeError::DepthIsZero));
    }

    #[test]
    fn test_is_known_root() {
        let mut tree = MerkleTree::<10>::new().unwrap();

        let mut known_roots = vec![ZEROS[9]];

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
        let mut tree = MerkleTree::<6>::new().unwrap();

        let mut roots = vec![ZEROS[5]];

        for i in 0..10 {
            tree.insert([i as u8 * 3; 32]).unwrap();
            let root = tree.get_last_root();

            roots.push(root);
        }

        assert_eq!(tree.roots, roots);
    }

    #[ignore]
    #[test]
    fn test_check_zeros_correctness() {
        let mut tree = MerkleTree::<MAX_DEPTH>::new().unwrap();
        for _i in 0..2u64.pow(MAX_DEPTH as u32) {
            tree.insert([0; 32]).unwrap();
        }

        for i in 0..MAX_DEPTH {
            assert_eq!(tree.filled_subtrees[i], ZEROS[i]);
        }
    }
}
