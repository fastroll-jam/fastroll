use crate::state::*;
use rjam_codec::{JamCodecError, JamDecode, JamEncodeFixed};
use rjam_common::{Address, ByteArray, Hash32, HASH32_EMPTY, HASH_SIZE};
use rjam_crypto::octets_to_hash32;

pub trait StateComponent: Clone + JamDecode {
    const STATE_KEY_CONSTANT: StateKeyConstant;

    fn from_entry_type(entry: &StateEntryType) -> Option<&Self>;

    fn from_entry_type_mut(entry: &mut StateEntryType) -> Option<&mut Self>;

    fn into_entry_type(self) -> StateEntryType;
}

#[macro_export]
macro_rules! impl_state_component {
    ($state_type:ty, $type_name:ident) => {
        impl StateComponent for $state_type {
            const STATE_KEY_CONSTANT: StateKeyConstant = StateKeyConstant::$type_name;

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
    };
}

#[derive(Clone)]
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

pub fn get_account_metadata_state_key(i: StateKeyConstant, s: Address) -> Hash32 {
    let mut key = HASH32_EMPTY;
    key[0] = i.into();
    key[1..5].copy_from_slice(&s.to_be_bytes());
    key
}

pub fn get_account_storage_state_key(s: Address, h: &Hash32) -> Hash32 {
    let mut key = HASH32_EMPTY;
    let s_bytes = s.to_be_bytes();
    for i in 0..4 {
        key[i * 2] = s_bytes[i]; // 0, 2, 4, 6
        key[i * 2 + 1] = h[i]; // 1, 3, 5, 7
    }
    key[8..32].copy_from_slice(&h[4..28]);

    key
}

pub fn get_account_lookups_state_key(
    s: Address,
    h: &Hash32,
    l: u32,
) -> Result<Hash32, JamCodecError> {
    let mut lookups_key_encoded = vec![];
    l.encode_to_fixed(&mut lookups_key_encoded, 4)?;
    lookups_key_encoded.extend(not_hash_slice(h).to_vec());

    Ok(get_account_storage_state_key(
        s,
        octets_to_hash32(&lookups_key_encoded).as_ref().unwrap(),
    ))
}

/// Applies logical NOT operation on a Hash32 type
fn not_hash_slice(h: &Hash32) -> [u8; 28] {
    let mut result = [0u8; 28];
    for (i, &byte) in h[4..].iter().enumerate() {
        result[i] = !byte;
    }
    result
}
