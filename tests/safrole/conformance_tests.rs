use serde::{Deserialize, Serialize};
use std::fs;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::safrole::asn_types::Testcase;

    #[test]
    fn test_safrole_conformance() {
        let json_str = fs::read_to_string(
            "../jamtestvectors/safrole/tiny/enact-epoch-change-with-no-tickets-4.json",
        )
        .expect("Failed to read test vector file");
        let test_case: Testcase = serde_json::from_str(&json_str).expect("Failed to parse JSON");
        // println!(">>> Test case: {:?}", test_case);
    }
}
