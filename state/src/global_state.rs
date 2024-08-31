use crate::trie::utils::MerklizationError;
use jam_codec::JamCodecError;
use jam_crypto::utils::CryptoError;
use jam_db::manager::KVDBError;
use jam_types::state::{
    authorizer::{AuthorizerPool, AuthorizerQueue},
    disputes::DisputesState,
    entropy::EntropyAccumulator,
    histories::BlockHistories,
    privileged::PrivilegedServices,
    reports::PendingReports,
    safrole::SafroleState,
    services::ServiceAccounts,
    statistics::ValidatorStats,
    timeslot::Timeslot,
    validators::{ActiveValidatorSet, PastValidatorSet, StagingValidatorSet},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum GlobalStateError {
    #[error("Merklization error: {0}")]
    MerklizationError(#[from] MerklizationError),
    #[error("JAM codec error: {0}")]
    JamCodecError(#[from] JamCodecError),
    #[error("KVDB error: {0}")]
    KVDBError(#[from] KVDBError),
    #[error("Crypto error: {0}")]
    CryptoError(#[from] CryptoError),
    #[error("{0}")]
    Other(String),
}
pub struct GlobalState {
    pub recent_timeslot: Timeslot,                  // tau
    pub safrole_state: SafroleState,                // gamma
    pub staging_validator_set: StagingValidatorSet, // iota
    pub active_validator_set: ActiveValidatorSet,   // kappa
    pub past_validator_set: PastValidatorSet,       // lambda
    pub entropy_accumulator: EntropyAccumulator,    // eta
    pub service_accounts: ServiceAccounts,          // sigma
    pub privileged_services: PrivilegedServices,    // chi
    pub pending_reports: PendingReports,            // rho
    pub authorizer_pool: AuthorizerPool,            // alpha
    pub authorizer_queue: AuthorizerQueue,          // phi
    pub block_histories: BlockHistories, // beta; Vec<BlockHistoryEntry> length up to `H = 8`.
    pub disputes: DisputesState,         // psi
    pub validator_statistics: ValidatorStats, // pi
}
