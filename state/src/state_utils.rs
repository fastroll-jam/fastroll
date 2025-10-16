use crate::{
    error::StateManagerError,
    manager::StateManager,
    types::{
        privileges::PrivilegedServices, AccountLookupsEntry, AccountMetadata,
        AccountPreimagesEntry, AccountStorageEntry, AccumulateHistory, AccumulateQueue, ActiveSet,
        AuthPool, AuthQueue, BlockHistory, DisputesState, EpochEntropy, LastAccumulateOutputs,
        OnChainStatistics, PastSet, PendingReports, SafroleState, StagingSet, Timeslot,
    },
};
use fr_codec::prelude::*;
use fr_common::{
    ByteArray, Hash32, LookupsKey, Octets, PreimagesKey, ServiceId, StateKey, StorageKey,
    STATE_KEY_SIZE,
};
use fr_crypto::{hash, Blake2b256};
use std::{error::Error, fmt::Debug};

/// Represents global state types with simple fixed state keys
pub trait SimpleStateComponent: StateComponent {
    const STATE_KEY_CONSTANT: StateKeyConstant;
}

/// Represents global state types associated with account state with dynamically-derived state keys
pub trait AccountStateComponent: StateComponent {}

pub trait StateComponent: Clone + Debug + Default + PartialEq + Eq + JamEncode + JamDecode {
    fn from_entry_type(entry_type: &StateEntryType) -> Option<&Self>;

    fn from_entry_type_mut(entry_type: &mut StateEntryType) -> Option<&mut Self>;

    fn into_entry_type(self) -> StateEntryType;
}

#[macro_export]
macro_rules! impl_simple_state_component {
    ($state_type:ty, $type_name:ident) => {
        impl StateComponent for $state_type {
            fn from_entry_type(entry_type: &StateEntryType) -> Option<&Self> {
                if let StateEntryType::$type_name(ref entry) = entry_type {
                    Some(entry)
                } else {
                    None
                }
            }

            fn from_entry_type_mut(entry_type: &mut StateEntryType) -> Option<&mut Self> {
                if let StateEntryType::$type_name(ref mut entry) = entry_type {
                    Some(entry)
                } else {
                    None
                }
            }

            fn into_entry_type(self) -> StateEntryType {
                StateEntryType::$type_name(self)
            }
        }

        impl SimpleStateComponent for $state_type {
            const STATE_KEY_CONSTANT: StateKeyConstant = StateKeyConstant::$type_name;
        }
    };
}

#[macro_export]
macro_rules! impl_account_state_component {
    ($state_type:ty, $type_name:ident) => {
        impl StateComponent for $state_type {
            fn from_entry_type(entry_type: &StateEntryType) -> Option<&Self> {
                if let StateEntryType::$type_name(ref entry) = entry_type {
                    Some(entry)
                } else {
                    None
                }
            }

            fn from_entry_type_mut(entry_type: &mut StateEntryType) -> Option<&mut Self> {
                if let StateEntryType::$type_name(ref mut entry) = entry_type {
                    Some(entry)
                } else {
                    None
                }
            }

            fn into_entry_type(self) -> StateEntryType {
                StateEntryType::$type_name(self)
            }
        }

        impl AccountStateComponent for $state_type {}
    };
}

/// State entry types that are merklized into the global state `σ`.
#[derive(Debug, Clone)]
pub enum StateEntryType {
    /// `α`: The authorizer pool.
    AuthPool(AuthPool),
    /// `φ`: The authorizer queue
    AuthQueue(AuthQueue),
    /// `β`: The recent block history.
    BlockHistory(BlockHistory),
    /// `γ`: The Safrole state.
    SafroleState(SafroleState),
    /// `ψ`: The disputes state.
    DisputesState(DisputesState),
    /// `η`: The epoch entropy.
    EpochEntropy(EpochEntropy),
    /// `ι`: The staging validator set.
    StagingSet(StagingSet),
    /// `κ`: The active validator set.
    ActiveSet(ActiveSet),
    /// `λ`: The past validator set.
    PastSet(PastSet),
    /// `ρ`: The pending reports.
    PendingReports(PendingReports),
    /// `τ`: The timeslot index.
    Timeslot(Timeslot),
    /// `χ`: The privileged services.
    PrivilegedServices(PrivilegedServices),
    /// `π`: The on-chain statistics.
    OnChainStatistics(OnChainStatistics),
    /// `ω`: The accumulate ready-queue.
    AccumulateQueue(AccumulateQueue),
    /// `ξ`: The accumulate history.
    AccumulateHistory(AccumulateHistory),
    /// `θ`: The accumulation output pairs of the most recent block.
    LastAccumulateOutputs(LastAccumulateOutputs),
    /// `δ` (partial): The service accounts.
    AccountMetadata(AccountMetadata),
    /// The account storage entries (values of `δ_s`).
    AccountStorageEntry(AccountStorageEntry),
    /// The account lookups entries (values of `δ_l`).
    AccountLookupsEntry(AccountLookupsEntry),
    /// The account preimages entries (values of `δ_p`).
    AccountPreimagesEntry(AccountPreimagesEntry),
    /// Test-only type.
    Raw(Octets),
}

impl JamEncode for StateEntryType {
    fn size_hint(&self) -> usize {
        match self {
            StateEntryType::AuthPool(inner) => inner.size_hint(),
            StateEntryType::AuthQueue(inner) => inner.size_hint(),
            StateEntryType::BlockHistory(inner) => inner.size_hint(),
            StateEntryType::SafroleState(inner) => inner.size_hint(),
            StateEntryType::DisputesState(inner) => inner.size_hint(),
            StateEntryType::EpochEntropy(inner) => inner.size_hint(),
            StateEntryType::StagingSet(inner) => inner.size_hint(),
            StateEntryType::ActiveSet(inner) => inner.size_hint(),
            StateEntryType::PastSet(inner) => inner.size_hint(),
            StateEntryType::PendingReports(inner) => inner.size_hint(),
            StateEntryType::Timeslot(inner) => inner.size_hint(),
            StateEntryType::PrivilegedServices(inner) => inner.size_hint(),
            StateEntryType::OnChainStatistics(inner) => inner.size_hint(),
            StateEntryType::AccumulateQueue(inner) => inner.size_hint(),
            StateEntryType::AccumulateHistory(inner) => inner.size_hint(),
            StateEntryType::LastAccumulateOutputs(inner) => inner.size_hint(),
            StateEntryType::AccountMetadata(inner) => inner.size_hint(),
            StateEntryType::AccountStorageEntry(inner) => inner.size_hint(),
            StateEntryType::AccountLookupsEntry(inner) => inner.size_hint(),
            StateEntryType::AccountPreimagesEntry(inner) => inner.size_hint(),
            StateEntryType::Raw(inner) => inner.len(),
        }
    }

    fn encode_to<T: JamOutput>(&self, dest: &mut T) -> Result<(), JamCodecError> {
        match self {
            StateEntryType::AuthPool(inner) => inner.encode_to(dest)?,
            StateEntryType::AuthQueue(inner) => inner.encode_to(dest)?,
            StateEntryType::BlockHistory(inner) => inner.encode_to(dest)?,
            StateEntryType::SafroleState(inner) => inner.encode_to(dest)?,
            StateEntryType::DisputesState(inner) => inner.encode_to(dest)?,
            StateEntryType::EpochEntropy(inner) => inner.encode_to(dest)?,
            StateEntryType::StagingSet(inner) => inner.encode_to(dest)?,
            StateEntryType::ActiveSet(inner) => inner.encode_to(dest)?,
            StateEntryType::PastSet(inner) => inner.encode_to(dest)?,
            StateEntryType::PendingReports(inner) => inner.encode_to(dest)?,
            StateEntryType::Timeslot(inner) => inner.encode_to(dest)?,
            StateEntryType::PrivilegedServices(inner) => inner.encode_to(dest)?,
            StateEntryType::OnChainStatistics(inner) => inner.encode_to(dest)?,
            StateEntryType::AccumulateQueue(inner) => inner.encode_to(dest)?,
            StateEntryType::AccumulateHistory(inner) => inner.encode_to(dest)?,
            StateEntryType::LastAccumulateOutputs(inner) => inner.encode_to(dest)?,
            StateEntryType::AccountMetadata(inner) => inner.encode_to(dest)?,
            StateEntryType::AccountStorageEntry(inner) => inner.encode_to(dest)?,
            StateEntryType::AccountLookupsEntry(inner) => inner.encode_to(dest)?,
            StateEntryType::AccountPreimagesEntry(inner) => inner.encode_to(dest)?,
            StateEntryType::Raw(inner) => inner.encode_to_fixed(dest, inner.len())?,
        }
        Ok(())
    }
}

/// Index of each state component used for state-key (Merkle path) construction
#[repr(u8)]
pub enum StateKeyConstant {
    AuthPool = 1,               // α
    AuthQueue = 2,              // φ
    BlockHistory = 3,           // β
    SafroleState = 4,           // γ
    DisputesState = 5,          // ψ
    EpochEntropy = 6,           // η
    StagingSet = 7,             // ι
    ActiveSet = 8,              // κ
    PastSet = 9,                // λ
    PendingReports = 10,        // ρ
    Timeslot = 11,              // τ
    PrivilegedServices = 12,    // χ
    OnChainStatistics = 13,     // π
    AccumulateQueue = 14,       // ω
    AccumulateHistory = 15,     // ξ
    LastAccumulateOutputs = 16, // θ
    AccountMetadata = 255,      // δ (partial)
}

impl From<StateKeyConstant> for u8 {
    fn from(state_key: StateKeyConstant) -> Self {
        state_key as u8
    }
}

impl TryFrom<u8> for StateKeyConstant {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        let state_key_constant = match value {
            1 => StateKeyConstant::AuthPool,
            2 => StateKeyConstant::AuthQueue,
            3 => StateKeyConstant::BlockHistory,
            4 => StateKeyConstant::SafroleState,
            5 => StateKeyConstant::DisputesState,
            6 => StateKeyConstant::EpochEntropy,
            7 => StateKeyConstant::StagingSet,
            8 => StateKeyConstant::ActiveSet,
            9 => StateKeyConstant::PastSet,
            10 => StateKeyConstant::PendingReports,
            11 => StateKeyConstant::Timeslot,
            12 => StateKeyConstant::PrivilegedServices,
            13 => StateKeyConstant::OnChainStatistics,
            14 => StateKeyConstant::AccumulateQueue,
            15 => StateKeyConstant::AccumulateHistory,
            16 => StateKeyConstant::LastAccumulateOutputs,
            255 => StateKeyConstant::AccountMetadata,
            _ => return Err("Invalid state key constant"),
        };
        Ok(state_key_constant)
    }
}

/// Collection of simple state components for easy initialization for genesis.
#[derive(Default)]
pub struct SimpleStates {
    pub auth_pool: AuthPool,
    pub auth_queue: AuthQueue,
    pub block_history: BlockHistory,
    pub safrole: SafroleState,
    pub disputes: DisputesState,
    pub entropy: EpochEntropy,
    pub staging_set: StagingSet,
    pub active_set: ActiveSet,
    pub past_set: PastSet,
    pub reports: PendingReports,
    pub timeslot: Timeslot,
    pub privileges: PrivilegedServices,
    pub onchain_statistics: OnChainStatistics,
    pub accumulate_queue: AccumulateQueue,
    pub accumulate_history: AccumulateHistory,
    pub last_accumulate_outputs: LastAccumulateOutputs,
}

/// Adds state entry values into the global state for genesis or for test initializations.
pub async fn add_all_simple_state_entries(
    state_manager: &StateManager,
    genesis_simple_states: Option<SimpleStates>,
) -> Result<(), Box<dyn Error>> {
    let ss = genesis_simple_states.unwrap_or_default();
    state_manager.add_auth_pool(ss.auth_pool).await?;
    state_manager.add_auth_queue(ss.auth_queue).await?;
    state_manager.add_block_history(ss.block_history).await?;
    state_manager.add_safrole(ss.safrole).await?;
    state_manager.add_disputes(ss.disputes).await?;
    state_manager.add_epoch_entropy(ss.entropy).await?;
    state_manager.add_staging_set(ss.staging_set).await?;
    state_manager.add_active_set(ss.active_set).await?;
    state_manager.add_past_set(ss.past_set).await?;
    state_manager.add_pending_reports(ss.reports).await?;
    state_manager.add_timeslot(ss.timeslot).await?;
    state_manager.add_privileged_services(ss.privileges).await?;
    state_manager
        .add_onchain_statistics(ss.onchain_statistics)
        .await?;
    state_manager
        .add_accumulate_queue(ss.accumulate_queue)
        .await?;
    state_manager
        .add_accumulate_history(ss.accumulate_history)
        .await?;
    state_manager
        .add_last_accumulate_outputs(ss.last_accumulate_outputs)
        .await?;
    Ok(())
}

#[inline(always)]
const fn construct_state_key(i: u8) -> StateKey {
    let mut key = [0u8; STATE_KEY_SIZE];
    key[0] = i;
    ByteArray(key)
}

pub const STATE_KEYS: [StateKey; 16] = [
    construct_state_key(StateKeyConstant::AuthPool as u8),
    construct_state_key(StateKeyConstant::AuthQueue as u8),
    construct_state_key(StateKeyConstant::BlockHistory as u8),
    construct_state_key(StateKeyConstant::SafroleState as u8),
    construct_state_key(StateKeyConstant::DisputesState as u8),
    construct_state_key(StateKeyConstant::EpochEntropy as u8),
    construct_state_key(StateKeyConstant::StagingSet as u8),
    construct_state_key(StateKeyConstant::ActiveSet as u8),
    construct_state_key(StateKeyConstant::PastSet as u8),
    construct_state_key(StateKeyConstant::PendingReports as u8),
    construct_state_key(StateKeyConstant::Timeslot as u8),
    construct_state_key(StateKeyConstant::PrivilegedServices as u8),
    construct_state_key(StateKeyConstant::OnChainStatistics as u8),
    construct_state_key(StateKeyConstant::AccumulateQueue as u8),
    construct_state_key(StateKeyConstant::AccumulateHistory as u8),
    construct_state_key(StateKeyConstant::LastAccumulateOutputs as u8),
];

#[inline(always)]
pub fn get_simple_state_key(key: StateKeyConstant) -> StateKey {
    STATE_KEYS[key as usize - 1].clone()
}

pub fn get_account_metadata_state_key(s: ServiceId) -> Result<StateKey, StateManagerError> {
    let mut key = StateKey::default();
    key[0] = StateKeyConstant::AccountMetadata as u8;
    let encoded = s.encode_fixed(4)?;
    key[1] = encoded[0];
    key[3] = encoded[1];
    key[5] = encoded[2];
    key[7] = encoded[3];
    Ok(key)
}

fn construct_storage_state_key(s: ServiceId, h: &[u8]) -> Result<StateKey, StateManagerError> {
    let mut key = StateKey::default();
    let encoded = s.encode_fixed(4)?;
    let storage_key_component_hash: Hash32 = hash::<Blake2b256>(h).unwrap_or_else(|e| {
        tracing::error!(
            "Failed to hash storage key component. Using an empty hash value instead: {e}"
        );
        Hash32::default()
    });
    for i in 0..4 {
        key[i * 2] = encoded[i]; // 0, 2, 4, 6
        key[i * 2 + 1] = storage_key_component_hash[i]; // 1, 3, 5, 7
    }
    key[8..31].copy_from_slice(&storage_key_component_hash[4..27]);
    Ok(key)
}

pub fn get_account_storage_state_key(
    s: ServiceId,
    storage_key: &StorageKey,
) -> Result<StateKey, StateManagerError> {
    let mut key_with_prefix = Vec::with_capacity(4 + storage_key.len());
    key_with_prefix.extend(u32::MAX.to_le_bytes());
    key_with_prefix.extend(storage_key.clone().into_vec());
    construct_storage_state_key(s, key_with_prefix.as_slice())
}

pub fn get_account_preimage_state_key(
    s: ServiceId,
    preimage_key: &PreimagesKey,
) -> Result<StateKey, StateManagerError> {
    let mut key_with_prefix = ByteArray::<36>::default();
    key_with_prefix[0..4].copy_from_slice(&(u32::MAX - 1).to_le_bytes());
    key_with_prefix[4..].copy_from_slice(preimage_key.as_slice());
    construct_storage_state_key(s, key_with_prefix.as_slice())
}

pub fn get_account_lookups_state_key(
    s: ServiceId,
    lookups_key: &LookupsKey,
) -> Result<StateKey, StateManagerError> {
    let (h, l) = lookups_key;
    let mut key_with_prefix = ByteArray::<36>::default();
    key_with_prefix[0..4].copy_from_slice(&l.to_le_bytes());
    key_with_prefix[4..].copy_from_slice(h.as_slice());
    construct_storage_state_key(s, key_with_prefix.as_slice())
}
