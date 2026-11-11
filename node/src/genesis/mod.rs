pub(crate) mod serde_types;

use crate::genesis::serde_types::{
    block::GenesisBlockHeader, validator_keys::GenesisValidatorKeySet,
};
use fr_block::types::block::Block;
use fr_common::{ByteEncodable, EntropyHash};
use fr_crypto::types::{ValidatorKey, ValidatorKeySet, ValidatorKeys};
use fr_state::{
    state_utils::SimpleStates,
    types::{
        generate_fallback_keys, ActiveSet, EpochValidatorStats, OnChainStatistics, PastSet,
        SafroleState, SlotSealers, StagingSet, ValidatorStats,
    },
};

#[cfg(feature = "tiny")]
const GENESIS_BLOCK: &str = include_str!("data/tiny/genesis_block_header.json");
#[cfg(not(feature = "tiny"))]
const GENESIS_BLOCK: &str = include_str!("data/full/genesis_block_header.json");

#[cfg(feature = "tiny")]
const GENESIS_VALIDATOR_SET: &str = include_str!("data/tiny/genesis_validator_set.json");
#[cfg(not(feature = "tiny"))]
const GENESIS_VALIDATOR_SET: &str = include_str!("data/full/genesis_validator_set.json");

pub fn load_genesis_block() -> Block {
    let genesis_block_header: GenesisBlockHeader =
        serde_json::from_str(GENESIS_BLOCK).expect("Failed to parse genesis block JSON file");
    Block::from(genesis_block_header)
}

pub fn load_genesis_validator_set() -> ValidatorKeySet {
    let genesis_validator_set: GenesisValidatorKeySet = serde_json::from_str(GENESIS_VALIDATOR_SET)
        .expect("Failed to parse genesis validator set JSON file");
    ValidatorKeySet::from(genesis_validator_set)
}

pub fn genesis_simple_state() -> SimpleStates {
    let genesis_validator_set = load_genesis_validator_set();
    let genesis_entropy_2 = EntropyHash::default();
    let genesis_fallback_keys =
        generate_fallback_keys(&genesis_validator_set, &genesis_entropy_2).unwrap();
    tracing::debug!("🔑 genesis fallback keys");
    for key in genesis_fallback_keys.iter() {
        tracing::debug!("0x{}", key.to_hex());
    }
    // `λ` and `π` at genesis hold one zeroed entry per genesis validator.
    let genesis_validator_count = genesis_validator_set.len();
    let genesis_past_set =
        ValidatorKeys::try_from(vec![ValidatorKey::default(); genesis_validator_count])
            .expect("Genesis validator set fits in a validator key set");
    let genesis_epoch_validator_stats = EpochValidatorStats::zeroed(genesis_validator_count)
        .expect("Genesis validator set fits in validator statistics");
    let genesis_validator_stats = ValidatorStats {
        curr: genesis_epoch_validator_stats.clone(),
        prev: genesis_epoch_validator_stats,
    };
    SimpleStates {
        active_set: ActiveSet(genesis_validator_set.clone()),
        staging_set: StagingSet(genesis_validator_set.clone()),
        past_set: PastSet(ValidatorKeySet(genesis_past_set)),
        onchain_statistics: OnChainStatistics {
            validator_stats: genesis_validator_stats,
            ..Default::default()
        },
        safrole: SafroleState {
            pending_set: genesis_validator_set,
            slot_sealers: SlotSealers::BandersnatchPubKeys(genesis_fallback_keys),
            ..Default::default()
        },
        ..Default::default()
    }
}
