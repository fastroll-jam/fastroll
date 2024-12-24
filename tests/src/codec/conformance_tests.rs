//! JAM Codec conformance tests

#[cfg(test)]
mod tests {
    use crate::asn_types::{
        AsnAssurancesExtrinsic, AsnBlock, AsnDisputesExtrinsic, AsnExtrinsic,
        AsnGuaranteesExtrinsic, AsnHeader, AsnPreimageLookupsExtrinsic, AsnTicketsExtrinsic,
        AsnWorkItem, AsnWorkPackage, AsnWorkReport, RefineContext, WorkResult,
    };
    use rjam_codec::{JamDecode, JamEncode};
    use rjam_types::{
        block::{header::BlockHeader, Block},
        common::workloads::{RefinementContext, WorkItem, WorkItemResult, WorkPackage, WorkReport},
        extrinsics::{
            assurances::AssurancesExtrinsic, disputes::DisputesExtrinsic,
            guarantees::GuaranteesExtrinsic, preimages::PreimageLookupsExtrinsic,
            tickets::TicketsExtrinsic, Extrinsics,
        },
    };
    use serde::{de::DeserializeOwned, Serialize};
    use std::{
        fmt::Debug,
        fs,
        fs::File,
        io,
        io::Read,
        path::{Path, PathBuf},
    };

    const PATH_PREFIX: &str = "jamtestvectors/codec/data";

    #[allow(dead_code)]
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

    pub fn test_round_trip<RjamType, AsnType>(filename: &str)
    where
        RjamType: JamEncode + JamDecode + From<AsnType> + Debug,
        AsnType: Serialize + DeserializeOwned, // TODO: + From<RjamType>,
    {
        let json_path = PathBuf::from(PATH_PREFIX).join(format!("{}.json", filename));
        let asn_type: AsnType =
            load_json_file(&json_path).expect("Failed to load .json test vector.");
        let rjam_type: RjamType = RjamType::from(asn_type);
        let rjam_type_encoded = rjam_type.encode().expect("Failed to encode.");

        let bin_path = PathBuf::from(PATH_PREFIX).join(format!("{}.bin", filename));
        let asn_type_encoded = load_bin_file(&bin_path).expect("Failed to load .bin test vector.");

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

        // TODO: test deserialization
    }

    macro_rules! generate_codec_tests {
        ($($name:ident: ($path:expr, $t: ty, $u: ty),)*) => {
            $(
                #[test]
                fn $name() {
                    test_round_trip::<$t, $u>($path)
                }
            )*
        }
    }

    generate_codec_tests! {
        assurances_extrinsic: ("assurances_extrinsic", AssurancesExtrinsic, AsnAssurancesExtrinsic),
        block: ("block", Block, AsnBlock),
        disputes_extrinsic: ("disputes_extrinsic", DisputesExtrinsic, AsnDisputesExtrinsic),
        extrinsic: ("extrinsic", Extrinsics, AsnExtrinsic),
        guarantees_extrinsic: ("guarantees_extrinsic", GuaranteesExtrinsic, AsnGuaranteesExtrinsic),
        header_0: ("header_0", BlockHeader, AsnHeader),
        header_1: ("header_1", BlockHeader, AsnHeader),
        preimages_extrinsic: ("preimages_extrinsic", PreimageLookupsExtrinsic, AsnPreimageLookupsExtrinsic),
        refine_context: ("refine_context", RefinementContext, RefineContext),
        tickets_extrinsic: ("tickets_extrinsic", TicketsExtrinsic, AsnTicketsExtrinsic),
        work_item: ("work_item", WorkItem, AsnWorkItem),
        work_package: ("work_package", WorkPackage, AsnWorkPackage),
        work_report: ("work_report", WorkReport, AsnWorkReport),
        work_result_0: ("work_result_0", WorkItemResult, WorkResult),
        work_result_1: ("work_result_1", WorkItemResult, WorkResult),
    }
}
