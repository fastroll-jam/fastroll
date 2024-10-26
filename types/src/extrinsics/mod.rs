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
    tickets_extrinsic: TicketsExtrinsic,                  // E_T
    guarantees_extrinsic: GuaranteesExtrinsic,            // E_G
    assurances_extrinsic: AssurancesExtrinsic,            // E_A
    preimage_lookups_extrinsic: PreimageLookupsExtrinsic, // E_P
    disputes_extrinsic: DisputesExtrinsic,                // E_V
}
