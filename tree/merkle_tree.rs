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
        if DEPTH > MAX_DEPTH || DEPTH == 0 {
            return Err(MerkleTreeError::DepthTooLong);
        }

        let mut roots = Vec::with_capacity(ROOT_HISTORY_SIZE as usize);
        roots.push(ZEROS[DEPTH - 1]);

        let mut filled_subtrees = Vec::with_capacity(DEPTH);
        filled_subtrees.extend_from_slice(&ZEROS[0..DEPTH + 1]);

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

        let mut i = self.current_root_index;

        loop {
            if root == self.roots.get(i as usize).copied().unwrap_or([0; 32]) {
                return true;
            }
            if i == 0 {
                i = ROOT_HISTORY_SIZE;
            }
            i -= 1;
            if i == self.current_root_index {
                break;
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
}

///Array with zero elements for a MerkleTree with Blake2x256
const ZEROS: [[u8; 32]; 21] = [
    [
        137, 235, 13, 106, 138, 105, 29, 174, 44, 209, 94, 208, 54, 153, 49, 206, 10, 148, 158,
        202, 250, 92, 63, 147, 248, 18, 24, 51, 100, 110, 21, 195,
    ],
    [
        104, 168, 125, 50, 87, 8, 160, 41, 67, 148, 125, 45, 203, 108, 96, 86, 17, 230, 85, 13,
        194, 93, 167, 225, 221, 12, 48, 84, 247, 118, 182, 25,
    ],
    [
        192, 223, 2, 191, 176, 220, 242, 58, 89, 162, 142, 237, 180, 91, 160, 213, 253, 242, 227,
        119, 219, 125, 35, 22, 151, 22, 91, 213, 82, 80, 188, 152,
    ],
    [
        184, 186, 123, 41, 140, 111, 6, 81, 201, 118, 249, 207, 237, 221, 84, 34, 41, 223, 166,
        157, 162, 201, 222, 22, 145, 44, 25, 167, 128, 33, 117, 27,
    ],
    [
        1, 236, 226, 122, 103, 174, 6, 29, 247, 94, 30, 219, 142, 189, 238, 169, 231, 9, 110, 223,
        47, 158, 205, 189, 66, 44, 248, 134, 197, 117, 176, 17,
    ],
    [
        70, 202, 219, 182, 158, 77, 112, 110, 237, 181, 14, 135, 46, 158, 99, 12, 92, 101, 166,
        248, 229, 138, 193, 98, 7, 239, 198, 130, 19, 18, 118, 221,
    ],
    [
        24, 48, 173, 238, 12, 111, 99, 177, 62, 51, 75, 95, 245, 87, 114, 228, 69, 248, 198, 140,
        154, 40, 209, 251, 117, 223, 203, 201, 95, 65, 104, 124,
    ],
    [
        145, 50, 171, 247, 213, 223, 250, 108, 74, 236, 114, 141, 189, 93, 247, 31, 48, 188, 35,
        130, 148, 104, 73, 185, 26, 35, 114, 164, 121, 73, 129, 126,
    ],
    [
        179, 190, 156, 95, 120, 9, 200, 160, 72, 139, 214, 45, 228, 178, 135, 133, 112, 141, 252,
        225, 194, 20, 146, 109, 166, 41, 249, 154, 221, 14, 150, 61,
    ],
    [
        254, 211, 89, 65, 11, 53, 128, 150, 100, 131, 252, 145, 42, 96, 67, 39, 33, 242, 115, 221,
        221, 99, 88, 115, 34, 46, 250, 86, 65, 225, 113, 249,
    ],
    [
        40, 22, 41, 223, 104, 18, 214, 28, 115, 127, 73, 29, 0, 147, 134, 37, 222, 38, 217, 223,
        145, 30, 51, 140, 139, 161, 22, 83, 150, 16, 205, 234,
    ],
    [
        29, 253, 52, 127, 34, 77, 215, 37, 193, 54, 12, 203, 249, 66, 175, 49, 136, 161, 108, 68,
        53, 131, 118, 65, 126, 133, 53, 253, 185, 167, 4, 222,
    ],
    [
        136, 107, 100, 7, 46, 55, 3, 189, 46, 20, 121, 230, 95, 116, 208, 74, 125, 77, 20, 168, 43,
        241, 156, 229, 113, 215, 49, 26, 246, 0, 63, 146,
    ],
    [
        92, 236, 141, 144, 118, 224, 56, 35, 79, 239, 156, 198, 97, 84, 140, 254, 123, 119, 215, 3,
        51, 159, 135, 223, 121, 49, 227, 18, 27, 44, 228, 51,
    ],
    [
        104, 240, 237, 187, 40, 32, 172, 44, 101, 248, 89, 132, 151, 45, 3, 120, 173, 184, 171, 36,
        91, 208, 160, 222, 233, 61, 227, 242, 4, 53, 17, 81,
    ],
    [
        231, 144, 155, 95, 101, 88, 175, 252, 45, 37, 111, 129, 101, 119, 178, 122, 8, 81, 103,
        252, 81, 194, 207, 192, 5, 77, 80, 159, 110, 191, 197, 231,
    ],
    [
        58, 137, 120, 1, 121, 23, 245, 68, 56, 28, 211, 177, 9, 34, 59, 93, 173, 68, 153, 66, 116,
        81, 17, 150, 251, 254, 248, 39, 141, 17, 238, 77,
    ],
    [
        14, 196, 76, 17, 4, 200, 205, 157, 111, 41, 65, 158, 225, 28, 19, 122, 205, 248, 109, 186,
        68, 192, 170, 238, 73, 157, 62, 26, 42, 79, 23, 67,
    ],
    [
        245, 94, 4, 255, 39, 60, 137, 109, 38, 229, 48, 29, 141, 221, 67, 227, 213, 210, 103, 125,
        31, 32, 123, 248, 127, 77, 207, 71, 122, 98, 78, 184,
    ],
    [
        236, 161, 173, 196, 152, 147, 25, 230, 20, 133, 146, 69, 154, 88, 190, 236, 178, 114, 28,
        175, 92, 71, 138, 67, 59, 106, 144, 200, 82, 208, 43, 202,
    ],
    [
        26, 145, 160, 95, 202, 13, 6, 84, 125, 139, 164, 159, 151, 95, 86, 251, 143, 229, 126, 30,
        231, 78, 106, 82, 45, 194, 44, 254, 191, 134, 134, 193,
    ],
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
