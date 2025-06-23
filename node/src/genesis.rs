use fr_asn_types::{
    types::common::{validators_data_to_validator_set, AsnBlock, AsnValidatorsData},
    utils::AsnTypeLoader,
};
use fr_block::types::block::Block;
use fr_common::{ByteEncodable, EntropyHash};
use fr_crypto::types::ValidatorKeySet;
use fr_state::{
    test_utils::SimpleStates,
    types::{generate_fallback_keys, ActiveSet, SafroleState, SlotSealers, StagingSet},
};
use std::path::PathBuf;

pub fn load_genesis_block_from_file() -> Block {
    let json_path = PathBuf::from("src/genesis-data/genesis_block.json");
    let full_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(json_path);
    let asn_block: AsnBlock = AsnTypeLoader::load_from_json_file(&full_path);
    asn_block.into()
}

fn load_genesis_validator_set_from_file() -> ValidatorKeySet {
    let json_path = PathBuf::from("src/genesis-data/genesis_validator_set.json");
    let full_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(json_path);
    let asn_validators_data: AsnValidatorsData = AsnTypeLoader::load_from_json_file(&full_path);
    validators_data_to_validator_set(&asn_validators_data)
}

pub fn genesis_simple_state() -> SimpleStates {
    let genesis_validator_set = load_genesis_validator_set_from_file();
    let genesis_entropy_2 = EntropyHash::default();
    let genesis_fallback_keys =
        generate_fallback_keys(&genesis_validator_set, &genesis_entropy_2).unwrap();
    tracing::debug!("🔑 genesis fallback keys");
    for key in genesis_fallback_keys.iter() {
        tracing::debug!("0x{}", key.to_hex());
    }
    SimpleStates {
        active_set: ActiveSet(genesis_validator_set.clone()),
        staging_set: StagingSet(genesis_validator_set.clone()),
        safrole: SafroleState {
            pending_set: genesis_validator_set,
            slot_sealers: SlotSealers::BandersnatchPubKeys(genesis_fallback_keys),
            ..Default::default()
        },
        ..Default::default()
    }
}
