use crate::{
    codec::JamCodecError,
    crypto::utils::CryptoError,
    state::components::{
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
    },
    trie::utils::MerklizationError,
};
use std::fmt::Display;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum GlobalStateError {
    #[error("Merklization error: {0}")]
    MerklizationError(#[from] MerklizationError),
    #[error("JAM codec error: {0}")]
    JamCodecError(#[from] JamCodecError),
    #[error("Crypto error: {0}")]
    CryptoError(#[from] CryptoError),
    #[error("{0}")]
    Other(String),
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
