//! JAM Codec conformance tests

#[cfg(test)]
mod tests {
    use crate::codec::asn_types::{AsnDisputesExtrinsic, WorkResult};
    use rjam_codec::JamEncode;
    use rjam_types::{common::workloads::WorkItemResult, extrinsics::disputes::DisputesExtrinsic};
    use serde::{de::DeserializeOwned, Serialize};
    use std::{
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

    pub fn load_json_file<T>(path: &Path) -> Result<T, ()>
    where
        T: Serialize + DeserializeOwned,
    {
        let full_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path);
        let json_str = fs::read_to_string(&full_path).expect("Failed to read test vector file");
        let test_type = serde_json::from_str(&json_str).expect("Failed to parse JSON");
        Ok(test_type)
    }

    #[test]
    fn test_ser_disputes_extrinsic() {
        let json_filename = "disputes_extrinsic.json";
        let json_path = PathBuf::from(PATH_PREFIX).join(json_filename);

        let asn_type: AsnDisputesExtrinsic =
            load_json_file(&json_path).expect("Failed to load test vector.");

        let rjam_type: DisputesExtrinsic = DisputesExtrinsic::from(asn_type);
        let rjam_type_encoded = rjam_type.encode().unwrap();

        let bin_filename = "disputes_extrinsic.bin";
        let bin_path = PathBuf::from(PATH_PREFIX).join(bin_filename);

        let asn_type_encoded = load_bin_file(&bin_path).unwrap();

        println!(
            ">>> RJAM type encoded: (length: {} bytes) {:?}",
            hex::encode(&rjam_type_encoded).len(),
            hex::encode(&rjam_type_encoded)
        );

        println!(
            "\n>>> ASN type encoded: (length: {} bytes) {:?}",
            hex::encode(&asn_type_encoded).len(),
            hex::encode(&asn_type_encoded)
        );
    }

    #[test]
    fn test_ser_work_result_0() {
        let json_filename = "work_result_0.json";
        let json_path = PathBuf::from(PATH_PREFIX).join(json_filename);

        let asn_type: WorkResult = load_json_file(&json_path).expect("Failed to load test vector.");

        let rjam_type: WorkItemResult = WorkItemResult::from(asn_type);
        let rjam_type_encoded = rjam_type.encode().unwrap();

        let bin_filename = "work_result_0.bin";
        let bin_path = PathBuf::from(PATH_PREFIX).join(bin_filename);

        let asn_type_encoded = load_bin_file(&bin_path).unwrap();

        println!(
            ">>> RJAM type encoded: (length: {} bytes) {:?}",
            hex::encode(&rjam_type_encoded).len(),
            hex::encode(&rjam_type_encoded)
        );

        println!(
            "\n>>> ASN type encoded: (length: {} bytes) {:?}",
            hex::encode(&asn_type_encoded).len(),
            hex::encode(&asn_type_encoded)
        );
    }
}
