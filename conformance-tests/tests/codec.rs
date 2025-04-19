//! JAM Codec conformance tests
mod codec {
    use rjam_block::types::{
        block::{Block, BlockHeader},
        extrinsics::{
            assurances::AssurancesXt, disputes::DisputesXt, guarantees::GuaranteesXt,
            preimages::PreimagesXt, tickets::TicketsXt, Extrinsics,
        },
    };
    use rjam_codec::{JamDecode, JamEncode};
    use rjam_common::workloads::{
        RefinementContext, WorkDigest, WorkItem, WorkPackage, WorkReport,
    };
    use rjam_conformance_tests::asn_types::common::*;
    use serde::{de::DeserializeOwned, Serialize};
    use std::{
        fmt::Debug,
        fs,
        fs::File,
        io,
        io::Read,
        path::{Path, PathBuf},
    };

    const PATH_PREFIX: &str = "jamtestvectors-polkajam/codec/data";

    pub fn load_bin_file(path: &Path) -> io::Result<Vec<u8>> {
        let mut file = File::open(path)?;
        let mut buffer = vec![];
        file.read_to_end(&mut buffer)?;
        Ok(buffer)
    }

    pub fn load_json_file<AsnType>(path: &Path) -> Result<AsnType, ()>
    where
        AsnType: Serialize + DeserializeOwned,
    {
        let full_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path);
        let json_str = fs::read_to_string(&full_path).expect("Failed to read test vector file");
        let test_type = serde_json::from_str(&json_str).expect("Failed to parse JSON");
        Ok(test_type)
    }

    pub fn test_encode_decode<RjamType, AsnType>(filename: &str)
    where
        RjamType: JamEncode + JamDecode + From<AsnType> + Debug + PartialEq + Eq,
        AsnType: Serialize + DeserializeOwned + From<RjamType>,
    {
        let json_path = PathBuf::from(PATH_PREFIX).join(format!("{}.json", filename));
        let asn_type: AsnType =
            load_json_file(&json_path).expect("Failed to load .json test vector.");
        let rjam_type = RjamType::from(asn_type);
        let rjam_type_encoded = rjam_type.encode().expect("Failed to encode.");

        let bin_path = PathBuf::from(PATH_PREFIX).join(format!("{}.bin", filename));
        let asn_type_encoded = load_bin_file(&bin_path).expect("Failed to load .bin test vector.");

        // Test encoding
        println!(
            ">>> RJAM type encoded: (length: {} bytes) {:?}",
            &rjam_type_encoded.len(),
            hex::encode(&rjam_type_encoded)
        );

        println!(
            "\n>>> ASN type encoded: (length: {} bytes) {:?}",
            &asn_type_encoded.len(),
            hex::encode(&asn_type_encoded)
        );
        assert_eq!(rjam_type_encoded, asn_type_encoded);

        // Test decoding
        let rjam_type_decoded = RjamType::decode(&mut asn_type_encoded.as_slice()).unwrap();
        assert_eq!(rjam_type_decoded, rjam_type);
    }

    macro_rules! generate_codec_tests {
        ($($name:ident: ($path:expr, $t: ty, $u: ty),)*) => {
            $(
                #[test]
                fn $name() {
                    test_encode_decode::<$t, $u>($path)
                }
            )*
        }
    }

    generate_codec_tests! {
        assurances_extrinsic: ("assurances_extrinsic", AssurancesXt, AsnAssurancesXt),
        block: ("block", Block, AsnBlock),
        disputes_extrinsic: ("disputes_extrinsic", DisputesXt, AsnDisputesXt),
        extrinsic: ("extrinsic", Extrinsics, AsnExtrinsic),
        guarantees_extrinsic: ("guarantees_extrinsic", GuaranteesXt, AsnGuaranteesXt),
        header_0: ("header_0", BlockHeader, AsnHeader),
        header_1: ("header_1", BlockHeader, AsnHeader),
        preimages_extrinsic: ("preimages_extrinsic", PreimagesXt, AsnPreimagesXt),
        refine_context: ("refine_context", RefinementContext, AsnRefineContext),
        tickets_extrinsic: ("tickets_extrinsic", TicketsXt, AsnTicketsXt),
        work_item: ("work_item", WorkItem, AsnWorkItem),
        work_package: ("work_package", WorkPackage, AsnWorkPackage),
        work_report: ("work_report", WorkReport, AsnWorkReport),
        work_digest_0: ("work_result_0", WorkDigest, AsnWorkDigest),
        work_digest_1: ("work_result_1", WorkDigest, AsnWorkDigest),
    }
}
