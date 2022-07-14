use dusk_bls12_381::BlsScalar;
use hex_literal::hex;
use ink_env::hash::{Blake2x256, CryptoHash, HashOutput};
use ink_storage::traits::{PackedLayout, SpreadLayout, StorageLayout};

use super::merkle_tree::MAX_DEPTH;

#[derive(scale::Encode, scale::Decode, PackedLayout, SpreadLayout, PartialEq)]
#[cfg_attr(feature = "std", derive(Debug, ink_storage::traits::StorageLayout))]
pub struct Blake;

impl MerkleTreeHasher for Blake {
    type Output = <Blake2x256 as HashOutput>::Type;

    fn hash_left_right(left: Self::Output, right: Self::Output) -> Self::Output {
        let mut result = Self::Output::default();

        Blake2x256::hash(&[left, right].concat(), &mut result);
        result
    }

    ///Array with zero elements(every leaf is blake2x256("slushie")) for a MerkleTree with Blake2x256
    const ZEROS: [Self::Output; MAX_DEPTH] = [
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
}

///Trait which require implementation hash for subtrees, MAX_DEPTH zero elements, and hash output
#[cfg(feature = "std")]
pub trait MerkleTreeHasher:
    scale::Encode + scale::Decode + PackedLayout + SpreadLayout + StorageLayout
{
    type Output: 'static
        + scale::Encode
        + scale::Decode
        + PackedLayout
        + SpreadLayout
        + StorageLayout
        + scale_info::TypeInfo
        + Clone
        + Copy
        + PartialEq
        + Default;

    ///Array with zero elements for a MerkleTree
    const ZEROS: [Self::Output; MAX_DEPTH];

    /// Calculate hash for provided left and right subtrees
    fn hash_left_right(left: Self::Output, right: Self::Output) -> Self::Output;
}

///Trait which require implementation hash for subtrees, MAX_DEPTH zero elements, and hash output
#[cfg(not(feature = "std"))]
pub trait MerkleTreeHasher: scale::Encode + scale::Decode + PackedLayout + SpreadLayout {
    type Output: scale::Encode
        + scale::Decode
        + PackedLayout
        + SpreadLayout
        + Clone
        + Copy
        + PartialEq
        + Default;

    ///Array with zero elements for a MerkleTree
    const ZEROS: [Self::Output; MAX_DEPTH];

    /// Calculate hash for provided left and right subtrees
    fn hash_left_right(left: Self::Output, right: Self::Output) -> Self::Output;
}
