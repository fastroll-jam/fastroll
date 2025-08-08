use fr_block::types::{
    block::{
        Block, BlockHeader, BlockHeaderData, BlockSeal, EpochMarker, EpochMarkerValidatorKey,
        VrfSig,
    },
    extrinsics::Extrinsics,
};
use fr_common::{BlockHeaderHash, EntropyHash, StateRoot, TimeslotIndex, ValidatorIndex, XtHash};
use fr_limited_vec::FixedVec;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
struct EpochMarkerSerde {
    entropy: EntropyHash,
    tickets_entropy: EntropyHash,
    validators: Vec<EpochMarkerValidatorKey>,
}

impl From<EpochMarkerSerde> for EpochMarker {
    fn from(value: EpochMarkerSerde) -> Self {
        Self {
            entropy: value.entropy,
            tickets_entropy: value.tickets_entropy,
            validators: FixedVec::try_from(value.validators).expect("Invalid validators key count"),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct GenesisBlockHeader {
    parent: BlockHeaderHash,
    parent_state_root: StateRoot,
    extrinsic_hash: XtHash,
    slot: TimeslotIndex,
    epoch_mark: Option<EpochMarkerSerde>,
    author_index: ValidatorIndex,
    entropy_source: VrfSig,
    seal: BlockSeal,
}

impl From<GenesisBlockHeader> for Block {
    fn from(genesis: GenesisBlockHeader) -> Self {
        Self {
            header: BlockHeader {
                data: BlockHeaderData {
                    parent_hash: genesis.parent,
                    prior_state_root: genesis.parent_state_root,
                    extrinsic_hash: genesis.extrinsic_hash,
                    timeslot_index: genesis.slot,
                    epoch_marker: genesis.epoch_mark.map(EpochMarker::from),
                    winning_tickets_marker: None,
                    author_index: genesis.author_index,
                    vrf_signature: genesis.entropy_source,
                    offenders_marker: Vec::new(),
                },
                block_seal: genesis.seal,
            },
            extrinsics: Extrinsics::default(), // no extrinsic in the genesis block
        }
    }
}
