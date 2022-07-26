use dusk_bls12_381::BlsScalar;
use hex_literal::hex;
use ink_env::hash::{Blake2x256, CryptoHash, HashOutput};
#[cfg(feature = "std")]
use ink_storage::traits::StorageLayout;
use ink_storage::traits::{PackedLayout, SpreadAllocate, SpreadLayout};

use super::merkle_tree::MAX_DEPTH;

#[derive(scale::Encode, scale::Decode, PackedLayout, SpreadAllocate, SpreadLayout, PartialEq)]
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

#[derive(scale::Encode, scale::Decode, PackedLayout, SpreadAllocate, SpreadLayout, PartialEq)]
#[cfg_attr(feature = "std", derive(Debug, ink_storage::traits::StorageLayout))]
pub struct Poseidon;

impl Poseidon {
    pub fn bytes_to_scalar(bytes: [u8; 32]) -> BlsScalar {
        BlsScalar(Self::bytes_to_u64(bytes))
    }

    pub fn scalar_to_bytes(scalar: BlsScalar) -> [u8; 32] {
        Self::u64_to_bytes(*scalar.internal_repr())
    }

    pub fn bytes_to_u64(bytes: [u8; 32]) -> [u64; 4] {
        let mut result = [0; 4];

        for i in 0..result.len() {
            let bytes_8 = bytes.split_at(i * 8).1.split_at(8).0;
            let bytes_array = <&[u8; 8]>::try_from(bytes_8).unwrap();
            result[i] = u64::from_be_bytes(*bytes_array);
        }

        result
    }

    pub fn u64_to_bytes(array: [u64; 4]) -> [u8; 32] {
        let mut result = [0; 32];

        for i in 0..array.len() {
            let bytes_array = array[i].to_be_bytes();
            for j in 0..bytes_array.len() {
                result[i * 8 + j] = bytes_array[j];
            }
        }

        result
    }
}

impl MerkleTreeHasher for Poseidon {
    type Output = [u8; 32];

    fn hash_left_right(left: Self::Output, right: Self::Output) -> Self::Output {
        let left = Self::bytes_to_scalar(left);
        let right = Self::bytes_to_scalar(right);
        let result = dusk_poseidon::sponge::hash(&[left, right]);

        Self::scalar_to_bytes(result)
    }

    ///Array with zero elements(every leaf is scalar::from(blake2x256("slushie"))) for a MerkleTree with Poseidon
    const ZEROS: [Self::Output; MAX_DEPTH] = [
        hex!("21022C8B84947BF9FB67A7EB96CC2240F9DB61466F91697B5139DC623AF1DE85"), //=scalar::from(blake2x256("slushie"))
        hex!("1422626DF22F8FDC85D3F1B54B05DAE703D545326D957C05089191C39D34CB74"),
        hex!("49681A7A73430F6251AFDD15A75BCE6B654CEFBF135739E82D451CEA3865A559"),
        hex!("B064D992455BDA196F47BC6B4D36B71A86299BE34A2D51A70A084972C662D78B"),
        hex!("C5B40F97F84D55334F6566C7D78BA46C9C7F623938591F8C1730FFDE11FDA225"),
        hex!("6F68D352499DBE56A9BBA41023327181A27FC4FCC04E5F4841DAA0E9CD21647A"),
        hex!("0482AF1A656009C31B97B43D919CE3DB0FF1A7E35154C13344C6D881F6A34B3A"),
        hex!("E74E7718926E7814800CE74AEBAD2F4FAC9B0E36D52A906A12A8523CEDB175CF"),
        hex!("9CEEAE8D02E4BAACB683DD876CEA6BB2090FDB6C8F91E3256BB50081AC842494"),
        hex!("A3148FD26DA5AA4BD9CE6484679AC6692D26293943D7CB4C592E2C2A002CBB32"),
        hex!("FA41AEF6B38F07981464CB959500A79437F3B16640574D86530AD28CB45D9CB4"),
        hex!("C007CB795A06FD087A9CB764A37A470E20FA493E7CC4869565F352083E4856ED"),
        hex!("047536BBDCF7BDB49FCECF4257CA91CAA4E0BF374F6215426A7A208889440D88"),
        hex!("0E018C4423C72490EF260A3B38A47E962CB99EE73656CEC858923736ABBF4C6B"),
        hex!("DC5D958453BAF7E8C1F310DFB5C1A7D9364C26CAFBBD5A8A42D867630A191F13"),
        hex!("E365C8B5D776EE7ECADF0AAEE5B0C722E6273678D64385EC1DDE8892450CF447"),
        hex!("E7BFA1243CF6A51CBC9A2F8EAE19B1538A8B0CE15A9760FC4B8EBC5EEB58A40A"),
        hex!("B967413831B9E0CEEBE456AF8F667CC169165BA4A2EA44F1163EE2AEC3744E4C"),
        hex!("55E1254B4300D2CA77039FC7F9FEF6A2FBC0A3C5BBE57CC77274AC510B12A97B"),
        hex!("4CE946E968A0B477960EEF24AAFE0997350BA8F168BA2E4A546773556BDD1458"),
        hex!("AF46E0DABD1E139A87B1AFFAE87B0D28209BD5712CC1D4DA6398395744A87B45"),
        hex!("593580A84AE5912B2FFD9BABD8CEE11F17B66D9CE7C1743733FA633423FA5AFB"),
        hex!("BB8057DB741BF28321F0A0EDD8AE7E2F40AB2E6E22D89AE6165B985269BB04C9"),
        hex!("076E93606D5383FA24132637B055CFF34BF95BD8948C82B304BCC8E0D365EBC7"),
        hex!("18EA3A54F8D38DD9D9BE5C1423FEBE2BC4E65C6D0D72CD8D19988395AFAA0CFF"),
        hex!("EBEFC00D8B4918E4CEFE497556A25E2EBB4EFEA741B3590C3D6DB6AE0CC266AC"),
        hex!("547A9B9BFAF519469DC6B4D13067BB0003DFEF9294D7F5216935AAAD298EAB7C"),
        hex!("6737CAE2AC201A97714B82E2F19FB94E536B3D1F3139F7B0023385FDB02DD066"),
        hex!("7ACDDC0315B0ED9371AAFC3266BAF2BC3CC4DEB70C3877E21DBBF27A75E7F133"),
        hex!("ED01A2D9F594724F79376CC17AFB98CD401F111D68470F4853B8C7F16107487C"),
        hex!("F59DAEA5ACF08003B87046B00426AA10452B728974B1B8F71C688D76FF45ED44"),
        hex!("9D6CB6CB9E55EC9F00A0508C9E80E7691D8137FD838C352F4D03DD658E88CFE9"),
    ];
}

///Trait which require implementation hash for subtrees, MAX_DEPTH zero elements, and hash output
#[cfg(feature = "std")]
pub trait MerkleTreeHasher:
    scale::Encode + scale::Decode + PackedLayout + SpreadAllocate + SpreadLayout + StorageLayout
{
    type Output: 'static
        + scale::Encode
        + scale::Decode
        + PackedLayout
        + SpreadAllocate
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
pub trait MerkleTreeHasher:
    scale::Encode + scale::Decode + PackedLayout + SpreadAllocate + SpreadLayout
{
    type Output: scale::Encode
        + scale::Decode
        + PackedLayout
        + SpreadAllocate
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
