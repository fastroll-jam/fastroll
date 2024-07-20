use crate::{
    common::{Hash32, ValidatorKey, CORE_COUNT, VALIDATOR_COUNT},
    state::{
        authorization::AuthorizationPool, block_history::BlockHistoryEntry,
        pending_reports::PendingReports, privileged_services::PrivilegedServicesState,
        safrole::SafroleState, service_accounts::ServiceAccountState,
        validator_statistics::ValidatorStatEntry, verdicts::VerdictsState,
    },
};
use std::collections::BTreeMap;

pub(crate) struct GlobalState {
    pub(crate) recent_timeslot: u32,        // tau
    pub(crate) safrole_state: SafroleState, // gamma
    pub(crate) staging_validator_set: [ValidatorKey; VALIDATOR_COUNT], // iota
    pub(crate) active_validator_set: [ValidatorKey; VALIDATOR_COUNT], // kappa
    pub(crate) past_validator_set: [ValidatorKey; VALIDATOR_COUNT], // lambda
    pub(crate) entropy_accumulator: [Hash32; 4], // eta
    pub(crate) service_accounts: BTreeMap<u32, ServiceAccountState>, // sigma
    pub(crate) privileged_services: PrivilegedServicesState, // chi
    pub(crate) pending_reports: PendingReports, // rho
    pub(crate) authorization_pool: AuthorizationPool, // alpha
    pub(crate) authorization_queue: [[Hash32; 80]; CORE_COUNT], // phi
    pub(crate) block_history: Vec<BlockHistoryEntry>, // beta; Vec<BlockHistoryEntry> length up to `H = 8`.
    pub(crate) verdicts: VerdictsState,               // psi
    pub(crate) validator_statistics: [[ValidatorStatEntry; VALIDATOR_COUNT]; 2], // pi
}
