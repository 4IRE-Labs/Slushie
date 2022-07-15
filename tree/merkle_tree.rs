use hex_literal::hex;
use ink_env::hash::{Blake2x256, CryptoHash};
use ink_primitives::KeyPtr;
use ink_storage::traits::{ExtKeyPtr, PackedLayout, SpreadLayout, StorageLayout};

/// Merkle tree maximum depth
pub const MAX_DEPTH: usize = 32;

///Merkle tree with history for storing commitments in it
#[derive(scale::Encode, scale::Decode, PackedLayout, SpreadLayout, PartialEq)]
#[cfg_attr(feature = "std", derive(Debug, StorageLayout))]
pub(crate) struct MerkleTree<const DEPTH: usize, const ROOT_HISTORY_SIZE: usize> {
    ///Current root index in the history
    pub current_root_index: u64,
    /// Next leaf index
    pub next_index: u64,
    ///Hashes last filled subtrees on every level
    pub filled_subtrees: Array<[u8; 32], DEPTH>,
    /// Merkle tree roots history
    pub roots: Array<[u8; 32], ROOT_HISTORY_SIZE>,
}

impl<const DEPTH: usize, const ROOT_HISTORY_SIZE: usize> MerkleTree<DEPTH, ROOT_HISTORY_SIZE> {
    ///Create merkle tree
    pub fn new() -> Result<Self, MerkleTreeError> {
        if DEPTH > MAX_DEPTH {
            return Err(MerkleTreeError::DepthTooLong);
        }

        if DEPTH == 0 {
            return Err(MerkleTreeError::DepthIsZero);
        }

        let roots = Array([ZEROS[DEPTH - 1]; ROOT_HISTORY_SIZE]);

        let mut filled_subtrees: Array<[u8; 32], DEPTH> = Default::default();
        filled_subtrees.0.copy_from_slice(&ZEROS[0..DEPTH]);

        Ok(Self {
            current_root_index: 0,
            next_index: 0,
            filled_subtrees,
            roots,
        })
    }

    /// Get last root hash
    pub fn get_last_root(&self) -> [u8; 32] {
        self.roots.0[self.current_root_index as usize]
    }

    /// Check existing provided root in roots history
    pub fn is_known_root(&self, root: [u8; 32]) -> bool {
        if root == [0; 32] {
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
    pub fn insert(&mut self, leaf: [u8; 32]) -> Result<usize, MerkleTreeError> {
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
                right = ZEROS[i];
                left = current_hash;

                self.filled_subtrees.0[i] = current_hash;
            } else {
                left = self.filled_subtrees.0[i];
                right = current_hash;
            }

            current_hash = Self::hash_left_right(left, right);
            current_index /= 2;
        }

        self.current_root_index = (self.current_root_index + 1) % root_history_size_u64;

        self.roots.0[self.current_root_index as usize] = current_hash;

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

#[derive(scale::Encode, scale::Decode, PackedLayout, SpreadLayout, PartialEq)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct Array<T: Default + Clone + Copy, const N: usize>([T; N]);

#[cfg(feature = "std")]
use ink_metadata::layout::{ArrayLayout, Layout, LayoutKey};

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

///Array with zero elements(every leaf is blake2x256("slushie")) for a MerkleTree with Blake2x256
const ZEROS: [[u8; 32]; 32] = [
    hex!("DF26FF86CD6E61248972E4587A1676FF2DE793D9D39BA77D8623B3CF98097964"), //=blake2x256("slushie")
    hex!("08A1F07AA709C548AB2FF9E131D592AD5F51AE98A422EB7DD4EC4BB5851224F7"),
    hex!("7FFD603771A2F3081DA519DD801BA92155FE3D0AEE2414F2D5F5A50A85905A9D"),
    hex!("AC6B640D0248376B1853EFF9D6EF755589EDAD57C89B418D2E769F0878714A6A"),
    hex!("3BB8C18776E7262665D755341C34D1BFFF8A47A4CBA32B00587A118C3949C333"),
    hex!("2B56D350CAA77C271671BAC2926C63318C808F826038AE9528061160919CDB66"),
    hex!("F4E29395681B76B9CCB43BBA7A25A6E579AEA997719C45CB67B59BEB29998767"),
    hex!("37DD0B2E55B8DCB8599F6F07A98D664AB65AA7FDE1DC0A10C5C34F6D6B8DDB29"),
    hex!("084A95D2144039C0D30E55AC852123F381AEADE943A67BA407556BF4108A6E28"),
    hex!("4C40869E7648D141C0F566404A7FB7CC5A7ADE25F618BA57E01A7DCF6ACCB4B7"),
    hex!("98EEFD72911C6D53CCD185D4B1112ACC473C09D2629CE54E29802DC51D6E248E"),
    hex!("2D8200DE6D7B7B8713251983CC6607F564C318EF0142CE248F8604B268A03435"),
    hex!("C76DD3166E3CB3C6F5710C7342EF808BECE631107D247041ABDD6E90EFF00093"),
    hex!("548E07F911927EFEA1690308BAE15482146A846DBE3A0615ABEE4D000385FCF1"),
    hex!("59A40D5B3CC23C49E9B39898DA03E93D3FADE7F21CABDB4158DF3A8E16BF2770"),
    hex!("F35EE3968504FBE69D3F3AD50EC462BDF89B4D52FBF20FFCA03A2386A02A6C93"),
    hex!("3BF9B77569D6DADF938D8A8D2655EECEB25A1AEA8CE8A8966BE75089F575814E"),
    hex!("4C085D252A8A74A8D421C02F6D88A0DA09F97A08704BC2211883D66692B2D3F5"),
    hex!("CB9EAC104C0233AC559518A1FF4B6ACC82CDB6898EB96C92E6BD156542817F26"),
    hex!("0D9781719606274A7112738574248DB77549935E07A89F8DEC8AE0D8BF74EEED"),
    hex!("6D55AC6517C59DC452FF2EFB0FAC5EC744E5486D129F3FDEDF675FB8B6E39DB7"),
    hex!("65E5AC035957EB54E4A10A21E80684652221E4C6A3015A0F6FE45FB6E6E12757"),
    hex!("AE33C85AB0D4DDC7371E1E56B7FF988761AD512EA22694387D12758A35F47F1E"),
    hex!("391CA0F22B37FF113E68360BCB7F7642A85A9BC48DD0CDBB295D3AE44BAE08FD"),
    hex!("847F01F4FB6FF5D8CE6C1984ECC08D4B9C3240AE780A60C893FEAC4220C55598"),
    hex!("DC390096531C2B643AB506EFC0BB8470DF74B25BCA24CAF36CC7DF73AE4FDE19"),
    hex!("38BC78A550172C2274C562422790D9F326CE3EB5998C0A1CB2C4455147970BA7"),
    hex!("419772135A10641AAFE5570CBC804FC76C0828D37B25663A0112BD5D049E15F6"),
    hex!("719340CC69722407872C2B19BE3504703EF1C78DB8EA17725957894A2E956441"),
    hex!("9B8D1843441D8974232866695C62672CBCE4ABA28073A33747B146E2DECA13EB"),
    hex!("FBF8667A0CECF72A92D07A4E5F26C13BB4555F4454E6BD1EBE9FB7F661C6C427"),
    hex!("C1868E018222455A946E804B70C9929AFBAE56A2CAB9F7722EDCF26039CFA0FE"),
];

#[cfg(any(feature = "std", tests))]
mod tests {
    use super::*;

    #[test]
    fn test_get_zero_root() {
        let tree = MerkleTree::<7, 30>::new().unwrap();
        assert_eq!(tree.get_last_root(), ZEROS[6]);

        for i in 0..7 {
            assert_eq!(tree.filled_subtrees.0[i], ZEROS[i]);
        }
    }

    #[test]
    fn test_insert() {
        let mut tree = MerkleTree::<10, 30>::new().unwrap();
        assert_eq!(tree.get_last_root(), ZEROS[9]);

        tree.insert([4; 32]).unwrap();

        assert!(tree.is_known_root(ZEROS[9]));
        assert!(!tree.is_known_root(ZEROS[4]));

        assert_ne!(tree.get_last_root(), ZEROS[9]);
    }

    #[test]
    fn test_tree_indexes() {
        let mut tree = MerkleTree::<2, 30>::new().unwrap();

        for i in 0..4usize {
            let index = tree.insert([i as u8; 32]).unwrap();
            assert_eq!(i, index);
            assert_eq!(i + 1, tree.next_index as usize);
        }
    }

    #[test]
    fn test_error_when_tree_is_full() {
        let mut tree = MerkleTree::<3, 30>::new().unwrap();

        for i in 0..2usize.pow(3) {
            tree.insert([i as u8 + 1; 32]).unwrap();
        }

        let err = tree.insert([6; 32]);

        assert_eq!(err, Err(MerkleTreeError::MerkleTreeIsFull));
    }

    #[test]
    fn test_error_when_tree_depth_too_long() {
        const MAX_DEPTH_PLUS_1: usize = MAX_DEPTH + 1;

        let tree = MerkleTree::<MAX_DEPTH_PLUS_1, 30>::new();

        assert_eq!(tree, Err(MerkleTreeError::DepthTooLong));
    }

    #[test]
    fn test_error_when_tree_depth_is_0() {
        let tree = MerkleTree::<0, 30>::new();

        assert_eq!(tree, Err(MerkleTreeError::DepthIsZero));
    }

    #[test]
    fn test_is_known_root() {
        let mut tree = MerkleTree::<10, 30>::new().unwrap();

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
        let mut tree = MerkleTree::<6, 30>::new().unwrap();

        let mut roots = vec![ZEROS[5]; 30];

        for i in 0..10 {
            tree.insert([i as u8 * 3; 32]).unwrap();
            let root = tree.get_last_root();
            let index = tree.current_root_index;

            roots[index as usize] = root;
        }

        assert_eq!(&tree.roots.0[..], &roots[..]);
    }

    #[ignore]
    #[test]
    fn test_check_tree_zeros_correctness() {
        let mut tree = MerkleTree::<MAX_DEPTH, 30>::new().unwrap();
        for _i in 0..2u64.pow(MAX_DEPTH as u32) {
            tree.insert(ZEROS[0]).unwrap();
        }

        for i in 0..MAX_DEPTH {
            assert_eq!(tree.filled_subtrees.0[i], ZEROS[i]);
        }
    }

    #[test]
    fn test_check_zeros_correctness() {
        let mut result: [u8; 32] = Default::default();
        Blake2x256::hash(b"slushie", &mut result);

        for i in 0..MAX_DEPTH {
            assert_eq!(result, ZEROS[i]);

            Blake2x256::hash(&[result, result].concat(), &mut result);
        }
    }
}
