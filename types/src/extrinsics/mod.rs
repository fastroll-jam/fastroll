use crate::extrinsics::{
    assurances::AssurancesXt, disputes::DisputesXt, guarantees::GuaranteesXt,
    preimages::PreimagesXt, tickets::TicketsXt,
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
#[derive(Debug, PartialEq, Eq, JamEncode, JamDecode)]
pub struct Extrinsics {
    pub tickets: TicketsXt,
    pub preimage_lookups: PreimagesXt,
    pub guarantees: GuaranteesXt,
    pub assurances: AssurancesXt,
    pub disputes: DisputesXt,
}
