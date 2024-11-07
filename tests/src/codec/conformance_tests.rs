//! JAM Codec conformance tests

#[cfg(test)]
mod tests {
    use crate::codec::asn_types::AsnDisputesExtrinsic;
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
        let filename = "disputes_extrinsic.json";
        let path = PathBuf::from(PATH_PREFIX).join(filename);

        let asn_type: AsnDisputesExtrinsic =
            load_json_file(&path).expect("Failed to load test vector.");

        println!(">>> ASN type: {:?}", asn_type);
    }
}
