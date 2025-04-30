use rjam_block::types::block::Block;
use rjam_conformance_tests::{
    asn_types::common::{validators_data_to_validator_set, AsnBlock, AsnValidatorsData},
    utils::AsnTypeLoader,
};
use rjam_crypto::types::ValidatorKeySet;
use rjam_state::{
    test_utils::SimpleStates,
    types::{ActiveSet, SafroleState},
};
use std::path::PathBuf;

pub fn load_genesis_block_from_file() -> Block {
    let json_path = PathBuf::from("src/genesis-data/genesis_block.json");
    let full_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(json_path);
    let asn_block: AsnBlock = AsnTypeLoader::load_from_json_file(&full_path);
    asn_block.into()
}

fn load_genesis_validator_set_from_file() -> ValidatorKeySet {
    let json_path = PathBuf::from("src/genesis-data/genesis_active_set.json");
    let full_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(json_path);
    let asn_validators_data: AsnValidatorsData = AsnTypeLoader::load_from_json_file(&full_path);
    validators_data_to_validator_set(&asn_validators_data)
}

pub fn genesis_simple_state() -> SimpleStates {
    let genesis_validator_set = load_genesis_validator_set_from_file();
    SimpleStates {
        active_set: ActiveSet(genesis_validator_set.clone()),
        safrole: SafroleState {
            pending_set: genesis_validator_set,
            ..Default::default()
        },
        ..Default::default()
    }
}
