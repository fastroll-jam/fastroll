use crate::{
    common::workloads::WorkReportError,
    extrinsics::{
        assurances::AssurancesXt, disputes::DisputesXt, guarantees::GuaranteesXt,
        preimages::PreimagesXt, tickets::TicketsXt,
    },
};
use rjam_codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput};
use rjam_common::Hash32;
use rjam_crypto::{hash, Blake2b256, CryptoError};
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
    #[error("WorkReportError: {0}")]
    WorkReportError(#[from] WorkReportError),
    #[error("JamCodecError: {0}")]
    JamCodecError(#[from] JamCodecError),
    #[error("CryptoError: {0}")]
    CryptoError(#[from] CryptoError),
}

#[derive(Clone, Ord, PartialOrd, PartialEq, Eq)]
pub enum XtType {
    Ticket,
    Guarantee,
    Assurance,
    PreimageLookup,
    Verdict,
    Culprit,
    Fault,
}

pub trait XtEntry: JamEncode + JamDecode {
    const XT_TYPE: XtType;

    fn hash(&self) -> Result<Hash32, ExtrinsicsError> {
        Ok(hash::<Blake2b256>(&self.encode()?)?)
    }
}

/// Struct used for Extrinsics serialization
#[derive(Debug, Clone, Default, PartialEq, Eq, JamEncode, JamDecode)]
pub struct Extrinsics {
    pub tickets: TicketsXt,
    pub preimage_lookups: PreimagesXt,
    pub guarantees: GuaranteesXt,
    pub assurances: AssurancesXt,
    pub disputes: DisputesXt,
}
