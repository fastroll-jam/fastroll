use crate::state::*;
use rjam_codec::{JamCodecError, JamDecode, JamEncode, JamEncodeFixed, JamOutput};
use rjam_common::{Address, ByteArray, Hash32, HASH32_EMPTY, HASH_SIZE};
use rjam_crypto::{hash, Blake2b256, CryptoError};
use std::fmt::Debug;

/// Represents global state types with simple fixed state keys
pub trait SimpleStateComponent: StateComponent {
    const STATE_KEY_CONSTANT: StateKeyConstant;
}

/// Represents global state types associated with account state with dynamically-derived state keys
pub trait AccountStateComponent: StateComponent {}

pub trait StateComponent: Clone + Debug + Default + PartialEq + Eq + JamDecode {
    fn from_entry_type(entry: &StateEntryType) -> Option<&Self>;

    fn from_entry_type_mut(entry: &mut StateEntryType) -> Option<&mut Self>;

    fn into_entry_type(self) -> StateEntryType;
}

#[macro_export]
macro_rules! impl_simple_state_component {
    ($state_type:ty, $type_name:ident) => {
        impl StateComponent for $state_type {
            fn from_entry_type(entry: &StateEntryType) -> Option<&Self> {
                if let StateEntryType::$type_name(ref entry) = entry {
                    Some(entry)
                } else {
                    None
                }
            }

            fn from_entry_type_mut(entry: &mut StateEntryType) -> Option<&mut Self> {
                if let StateEntryType::$type_name(ref mut entry) = entry {
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
            fn from_entry_type(entry: &StateEntryType) -> Option<&Self> {
                if let StateEntryType::$type_name(ref entry) = entry {
                    Some(entry)
                } else {
                    None
                }
            }

            fn from_entry_type_mut(entry: &mut StateEntryType) -> Option<&mut Self> {
                if let StateEntryType::$type_name(ref mut entry) = entry {
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

#[derive(Debug, Clone)]
pub enum StateEntryType {
    AuthPool(AuthPool),                     // alpha
    AuthQueue(AuthQueue),                   // phi
    BlockHistory(BlockHistory),             // beta
    SafroleState(SafroleState),             // gamma
    DisputesState(DisputesState),           // psi
    EntropyAccumulator(EntropyAccumulator), // eta
    StagingSet(StagingSet),                 // iota
    ActiveSet(ActiveSet),                   // kappa
    PastSet(PastSet),                       // lambda
    PendingReports(PendingReports),         // rho
    Timeslot(Timeslot),                     // tau
    PrivilegedServices(PrivilegedServices), // chi
    ValidatorStats(ValidatorStats),         // pi
    AccumulateQueue(AccumulateQueue),       // theta
    AccumulateHistory(AccumulateHistory),   // xi
    AccountMetadata(AccountMetadata),       // sigma (partial)
    AccountStorageEntry(AccountStorageEntry),
    AccountLookupsEntry(AccountLookupsEntry),
    AccountPreimagesEntry(AccountPreimagesEntry),
}

impl JamEncode for StateEntryType {
    fn size_hint(&self) -> usize {
        match self {
            StateEntryType::AuthPool(inner) => inner.size_hint(),
            StateEntryType::AuthQueue(inner) => inner.size_hint(),
            StateEntryType::BlockHistory(inner) => inner.size_hint(),
            StateEntryType::SafroleState(inner) => inner.size_hint(),
            StateEntryType::DisputesState(inner) => inner.size_hint(),
            StateEntryType::EntropyAccumulator(inner) => inner.size_hint(),
            StateEntryType::StagingSet(inner) => inner.size_hint(),
            StateEntryType::ActiveSet(inner) => inner.size_hint(),
            StateEntryType::PastSet(inner) => inner.size_hint(),
            StateEntryType::PendingReports(inner) => inner.size_hint(),
            StateEntryType::Timeslot(inner) => inner.size_hint(),
            StateEntryType::PrivilegedServices(inner) => inner.size_hint(),
            StateEntryType::ValidatorStats(inner) => inner.size_hint(),
            StateEntryType::AccumulateQueue(inner) => inner.size_hint(),
            StateEntryType::AccumulateHistory(inner) => inner.size_hint(),
            StateEntryType::AccountMetadata(inner) => inner.size_hint(),
            StateEntryType::AccountStorageEntry(inner) => inner.size_hint(),
            StateEntryType::AccountLookupsEntry(inner) => inner.size_hint(),
            StateEntryType::AccountPreimagesEntry(inner) => inner.size_hint(),
        }
    }

    fn encode_to<T: JamOutput>(&self, dest: &mut T) -> Result<(), JamCodecError> {
        match self {
            StateEntryType::AuthPool(inner) => inner.encode_to(dest)?,
            StateEntryType::AuthQueue(inner) => inner.encode_to(dest)?,
            StateEntryType::BlockHistory(inner) => inner.encode_to(dest)?,
            StateEntryType::SafroleState(inner) => inner.encode_to(dest)?,
            StateEntryType::DisputesState(inner) => inner.encode_to(dest)?,
            StateEntryType::EntropyAccumulator(inner) => inner.encode_to(dest)?,
            StateEntryType::StagingSet(inner) => inner.encode_to(dest)?,
            StateEntryType::ActiveSet(inner) => inner.encode_to(dest)?,
            StateEntryType::PastSet(inner) => inner.encode_to(dest)?,
            StateEntryType::PendingReports(inner) => inner.encode_to(dest)?,
            StateEntryType::Timeslot(inner) => inner.encode_to(dest)?,
            StateEntryType::PrivilegedServices(inner) => inner.encode_to(dest)?,
            StateEntryType::ValidatorStats(inner) => inner.encode_to(dest)?,
            StateEntryType::AccumulateQueue(inner) => inner.encode_to(dest)?,
            StateEntryType::AccumulateHistory(inner) => inner.encode_to(dest)?,
            StateEntryType::AccountMetadata(inner) => inner.encode_to(dest)?,
            StateEntryType::AccountStorageEntry(inner) => inner.encode_to(dest)?,
            StateEntryType::AccountLookupsEntry(inner) => inner.encode_to(dest)?,
            StateEntryType::AccountPreimagesEntry(inner) => inner.encode_to(dest)?,
        }
        Ok(())
    }
}

/// Index of each state component used for state-key (Merkle path) construction
#[repr(u8)]
pub enum StateKeyConstant {
    AuthPool = 1,            // alpha
    AuthQueue = 2,           // phi
    BlockHistory = 3,        // beta
    SafroleState = 4,        // gamma
    DisputesState = 5,       // psi
    EntropyAccumulator = 6,  // eta
    StagingSet = 7,          // iota
    ActiveSet = 8,           // kappa
    PastSet = 9,             // lambda
    PendingReports = 10,     // rho
    Timeslot = 11,           // tau
    PrivilegedServices = 12, // chi
    ValidatorStats = 13,     // pi
    AccumulateQueue = 14,    // theta
    AccumulateHistory = 15,  // xi
    AccountMetadata = 255,   // sigma (partial)
}

impl From<StateKeyConstant> for u8 {
    fn from(state_key: StateKeyConstant) -> Self {
        state_key as u8
    }
}

const fn construct_state_key(i: u8) -> Hash32 {
    let mut key = [0u8; HASH_SIZE];
    key[0] = i;
    ByteArray(key)
}

pub const STATE_KEYS: [Hash32; 15] = [
    construct_state_key(StateKeyConstant::AuthPool as u8),
    construct_state_key(StateKeyConstant::AuthQueue as u8),
    construct_state_key(StateKeyConstant::BlockHistory as u8),
    construct_state_key(StateKeyConstant::SafroleState as u8),
    construct_state_key(StateKeyConstant::DisputesState as u8),
    construct_state_key(StateKeyConstant::EntropyAccumulator as u8),
    construct_state_key(StateKeyConstant::StagingSet as u8),
    construct_state_key(StateKeyConstant::ActiveSet as u8),
    construct_state_key(StateKeyConstant::PastSet as u8),
    construct_state_key(StateKeyConstant::PendingReports as u8),
    construct_state_key(StateKeyConstant::Timeslot as u8),
    construct_state_key(StateKeyConstant::PrivilegedServices as u8),
    construct_state_key(StateKeyConstant::ValidatorStats as u8),
    construct_state_key(StateKeyConstant::AccumulateQueue as u8),
    construct_state_key(StateKeyConstant::AccumulateHistory as u8),
];

pub const fn get_simple_state_key(key: StateKeyConstant) -> Hash32 {
    STATE_KEYS[key as usize - 1]
}

pub fn get_account_metadata_state_key(s: Address) -> Hash32 {
    let mut key = HASH32_EMPTY;
    key[0] = StateKeyConstant::AccountMetadata as u8;
    let encoded = s
        .encode_fixed(4)
        .expect("encoding u32 should always be successful");
    key[1] = encoded[0];
    key[3] = encoded[1];
    key[5] = encoded[2];
    key[7] = encoded[3];
    key
}

fn construct_storage_state_key(s: Address, h: &[u8]) -> Hash32 {
    let mut key = HASH32_EMPTY;
    let s_bytes = s.to_be_bytes();
    for i in 0..4 {
        key[i * 2] = s_bytes[i]; // 0, 2, 4, 6
        key[i * 2 + 1] = h[i]; // 1, 3, 5, 7
    }
    key[8..32].copy_from_slice(&h[4..28]);

    key
}

pub fn get_account_storage_state_key(s: Address, key: &Hash32) -> Hash32 {
    let mut key_with_prefix = Vec::with_capacity(HASH_SIZE);
    key_with_prefix[0..4].copy_from_slice(
        &u32::MAX
            .encode_fixed(4)
            .expect("encoding u32 should always be successful"),
    );
    key_with_prefix[4..].copy_from_slice(&key[0..28]);
    construct_storage_state_key(s, &key_with_prefix)
}

pub fn get_account_preimage_state_key(s: Address, key: &Hash32) -> Hash32 {
    let mut key_with_prefix = Vec::with_capacity(HASH_SIZE);
    key_with_prefix[0..4].copy_from_slice(
        &(u32::MAX - 1)
            .encode_fixed(4)
            .expect("encoding u32 should always be successful"),
    );
    key_with_prefix[4..].copy_from_slice(&key[1..29]);
    construct_storage_state_key(s, &key_with_prefix)
}

pub fn get_account_lookups_state_key(
    s: Address,
    h: &Hash32,
    l: u32,
) -> Result<Hash32, CryptoError> {
    let mut key_with_prefix = Vec::with_capacity(HASH_SIZE);
    key_with_prefix[0..4].copy_from_slice(
        &l.encode_fixed(4)
            .expect("encoding u32 should always be successful"),
    );
    let hash_slice = &hash::<Blake2b256>(h.as_slice())?[2..30];
    key_with_prefix[4..].copy_from_slice(hash_slice);

    Ok(construct_storage_state_key(s, &key_with_prefix))
}
