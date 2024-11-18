use crate::extrinsics::{
    assurances::AssurancesExtrinsic, disputes::DisputesExtrinsic, guarantees::GuaranteesExtrinsic,
    preimages::PreimageLookupsExtrinsic, tickets::TicketsExtrinsic,
};
use rjam_codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput};
use thiserror::Error;

pub mod assurances;
pub mod disputes;
pub mod guarantees;
pub mod preimages;
pub mod tickets;

#[derive(Debug, Error)]
pub enum ExtrinsicsError {
    #[error("Credential for the validator index already exists")]
    DuplicateValidatorIndex,
    #[error("Invalid number of credentials. Must have either 2 or 3 credentials")]
    InvalidCredentialCount,
}

/// Struct used for Extrinsics serialization
#[derive(Debug, JamEncode, JamDecode)]
pub struct Extrinsics {
    pub tickets: TicketsExtrinsic,
    pub preimage_lookups: PreimageLookupsExtrinsic,
    pub guarantees: GuaranteesExtrinsic,
    pub assurances: AssurancesExtrinsic,
    pub disputes: DisputesExtrinsic,
}
