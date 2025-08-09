//! JAM Codec integration tests
#![allow(unused_imports)]
mod codec {
    use fr_asn_types::common::*;
    use fr_block::types::{
        block::{Block, BlockHeader},
        extrinsics::{
            assurances::AssurancesXt, disputes::DisputesXt, guarantees::GuaranteesXt,
            preimages::PreimagesXt, tickets::TicketsXt, Extrinsics,
        },
    };
    use fr_codec::prelude::*;
    use fr_common::{
        utils::serde::FileLoader,
        workloads::{RefinementContext, WorkDigest, WorkItem, WorkPackage, WorkReport},
    };
    use serde::{de::DeserializeOwned, Serialize};
    use std::{fmt::Debug, path::PathBuf};

    const PATH_PREFIX: &str = "jamtestvectors-polkajam/codec/tiny";

    pub fn test_encode_decode<FastRollType, AsnType>(filename: &str)
    where
        FastRollType: JamEncode + JamDecode + From<AsnType> + Debug + PartialEq + Eq,
        AsnType: Serialize + DeserializeOwned + From<FastRollType>,
    {
        let json_path = PathBuf::from(PATH_PREFIX).join(format!("{filename}.json"));
        let full_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(json_path);
        let asn_type: AsnType = FileLoader::load_from_json_file(&full_path);
        let fr_type = FastRollType::from(asn_type);
        let fr_type_encoded = fr_type.encode().expect("Failed to encode.");

        let bin_path = PathBuf::from(PATH_PREFIX).join(format!("{filename}.bin"));
        let asn_type_encoded =
            FileLoader::load_from_bin_file(&bin_path).expect("Failed to load .bin test vector.");

        // Test encoding
        println!(
            ">>> FastRoll type encoded: (length: {} bytes) {:?}",
            &fr_type_encoded.len(),
            hex::encode(&fr_type_encoded)
        );

        println!(
            "\n>>> ASN type encoded: (length: {} bytes) {:?}",
            &asn_type_encoded.len(),
            hex::encode(&asn_type_encoded)
        );
        assert_eq!(fr_type_encoded, asn_type_encoded);

        // Test decoding
        let fr_type_decoded = FastRollType::decode(&mut asn_type_encoded.as_slice()).unwrap();
        assert_eq!(fr_type_decoded, fr_type);
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

    // FIXME: temporarily skipped due to Codec definition mismatches (GP v0.7.0)
    generate_codec_tests! {
        assurances_extrinsic: ("assurances_extrinsic", AssurancesXt, AsnAssurancesXt),
        // block: ("block", Block, AsnBlock),
        disputes_extrinsic: ("disputes_extrinsic", DisputesXt, AsnDisputesXt),
        // extrinsic: ("extrinsic", Extrinsics, AsnExtrinsic),
        // guarantees_extrinsic: ("guarantees_extrinsic", GuaranteesXt, AsnGuaranteesXt),
        // header_0: ("header_0", BlockHeader, AsnHeader),
        // header_1: ("header_1", BlockHeader, AsnHeader),
        preimages_extrinsic: ("preimages_extrinsic", PreimagesXt, AsnPreimagesXt),
        refine_context: ("refine_context", RefinementContext, AsnRefineContext),
        tickets_extrinsic: ("tickets_extrinsic", TicketsXt, AsnTicketsXt),
        // work_item: ("work_item", WorkItem, AsnWorkItem),
        // work_package: ("work_package", WorkPackage, AsnWorkPackage),
        // work_report: ("work_report", WorkReport, AsnWorkReport),
        // work_digest_0: ("work_result_0", WorkDigest, AsnWorkDigest),
        // work_digest_1: ("work_result_1", WorkDigest, AsnWorkDigest),
    }
}
