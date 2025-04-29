use serde::{de::DeserializeOwned, Serialize};
use std::{
    fs,
    fs::File,
    io,
    io::Read,
    path::{Path, PathBuf},
};

pub struct AsnTypeLoader;
impl AsnTypeLoader {
    pub fn load_from_bin_file(path: &Path) -> io::Result<Vec<u8>> {
        let mut file = File::open(path)?;
        let mut buffer = vec![];
        file.read_to_end(&mut buffer)?;
        Ok(buffer)
    }

    pub fn load_from_json_file<AsnType>(path: &Path) -> AsnType
    where
        AsnType: Serialize + DeserializeOwned,
    {
        let full_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path);
        let json_str = fs::read_to_string(&full_path).expect("Failed to read test vector file");
        serde_json::from_str(&json_str).expect("Failed to parse JSON")
    }
}
