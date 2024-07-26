use crate::{
    codec::JamCodecError,
    state::components::{
        authorizer::{AuthorizerPool, AuthorizerQueue},
        disputes::DisputesState,
        entropy::EntropyAccumulator,
        histories::BlockHistories,
        privileged_services::PrivilegedServices,
        reports::PendingReports,
        safrole::SafroleState,
        services::ServiceAccounts,
        timeslot::Timeslot,
        validator_statistics::ValidatorStats,
        validators::{ActiveValidatorSet, PastValidatorSet, StagingValidatorSet},
    },
    trie::utils::MerklizationError,
};
use std::{
    error::Error,
    fmt,
    fmt::{Display, Formatter},
};

#[derive(Debug)]
pub enum GlobalStateError {
    MerklizationError(MerklizationError),
    JamCodecError(JamCodecError),
    Other(String), // generic error type
}

pub(crate) struct GlobalState {
    pub(crate) recent_timeslot: Timeslot,                  // tau
    pub(crate) safrole_state: SafroleState,                // gamma
    pub(crate) staging_validator_set: StagingValidatorSet, // iota
    pub(crate) active_validator_set: ActiveValidatorSet,   // kappa
    pub(crate) past_validator_set: PastValidatorSet,       // lambda
    pub(crate) entropy_accumulator: EntropyAccumulator,    // eta
    pub(crate) service_accounts: ServiceAccounts,          // sigma
    pub(crate) privileged_services: PrivilegedServices,    // chi
    pub(crate) pending_reports: PendingReports,            // rho
    pub(crate) authorizer_pool: AuthorizerPool,            // alpha
    pub(crate) authorizer_queue: AuthorizerQueue,          // phi
    pub(crate) block_histories: BlockHistories, // beta; Vec<BlockHistoryEntry> length up to `H = 8`.
    pub(crate) disputes: DisputesState,         // psi
    pub(crate) validator_statistics: ValidatorStats, // pi
}

impl Display for GlobalStateError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            GlobalStateError::MerklizationError(e) => write!(f, "Merklization error: {}", e),
            GlobalStateError::JamCodecError(e) => write!(f, "JamCodec error: {}", e),
            GlobalStateError::Other(e) => write!(f, "error: {}", e),
        }
    }
}

impl Error for GlobalStateError {}

impl From<MerklizationError> for GlobalStateError {
    fn from(error: MerklizationError) -> Self {
        GlobalStateError::MerklizationError(error)
    }
}

impl From<JamCodecError> for GlobalStateError {
    fn from(error: JamCodecError) -> Self {
        GlobalStateError::JamCodecError(error)
    }
}
