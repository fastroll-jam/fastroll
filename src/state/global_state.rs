use crate::{
    codec::JamCodecError,
    common::{Hash32, ValidatorKey, CORE_COUNT, VALIDATOR_COUNT},
    state::components::{
        block_history::BlockHistoryEntry,
        pending_reports::PendingReport, privileged_services::PrivilegedServicesState,
        safrole::SafroleState, service_accounts::ServiceAccountState,
        validator_statistics::ValidatorStatEntry, verdicts::VerdictsState,
    },
    trie::utils::MerklizationError,
};
use std::{
    collections::BTreeMap,
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

pub(crate) type Timeslot = u32;
pub(crate) type ValidatorSet = [ValidatorKey; VALIDATOR_COUNT];
pub(crate) type EntropyAccumulator = [Hash32; 4];
pub(crate) type ServiceAccounts = BTreeMap<u32, ServiceAccountState>;
pub(crate) type PendingReports = [Option<PendingReport>; CORE_COUNT];
pub(crate) type AuthorizerPool = [Vec<Hash32>; CORE_COUNT]; // Vec<Hash32> length up to `O = 8`
pub(crate) type AuthorizerQueue = [[Hash32; 80]; CORE_COUNT];
pub(crate) type BlockHistories = Vec<BlockHistoryEntry>;
pub(crate) type ValidatorStats = [[ValidatorStatEntry; VALIDATOR_COUNT]; 2];

pub(crate) struct GlobalState {
    pub(crate) recent_timeslot: u32,                         // tau
    pub(crate) safrole_state: SafroleState,                  // gamma
    pub(crate) staging_validator_set: ValidatorSet,          // iota
    pub(crate) active_validator_set: ValidatorSet,           // kappa
    pub(crate) past_validator_set: ValidatorSet,             // lambda
    pub(crate) entropy_accumulator: EntropyAccumulator,      // eta
    pub(crate) service_accounts: ServiceAccounts,            // sigma
    pub(crate) privileged_services: PrivilegedServicesState, // chi
    pub(crate) pending_reports: PendingReports,              // rho
    pub(crate) authorizer_pool: AuthorizerPool,        // alpha
    pub(crate) authorizer_queue: AuthorizerQueue,            // phi
    pub(crate) block_history: BlockHistories, // beta; Vec<BlockHistoryEntry> length up to `H = 8`.
    pub(crate) verdicts: VerdictsState,       // psi
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
