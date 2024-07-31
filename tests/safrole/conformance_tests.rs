// TODO: conversion between ASN types representation and types in the actual implementation
#[cfg(test)]
mod tests {
    use crate::safrole::asn_types::Testcase;
    use rjam::crypto::generate_ring_root;
    use std::fs;

    #[test]
    fn test_safrole_conformance() {
        let json_str = fs::read_to_string(
            "../jamtestvectors/safrole/tiny/enact-epoch-change-with-no-tickets-4.json",
        )
        .expect("Failed to read test vector file");
        let test_case: Testcase = serde_json::from_str(&json_str).expect("Failed to parse JSON");
        // let post_gamma_k = test_case.post_state.gamma_k;
        // let post_gamma_z = test_case.post_state.gamma_z;
        //
        // let result_gamma_z = generate_ring_root(&(post_gamma_k.try_into().unwrap())).unwrap();
        // assert_eq!(post_gamma_z, result_gamma_z);
    }
}
