use fr_codec::prelude::*;
use fr_common::{ServiceId, StateKey};
use fr_state::{
    state_utils::{get_account_metadata_state_key, StateKeyConstant, STATE_KEYS},
    types::{
        AccountMetadata, AccumulateHistory, AccumulateQueue, ActiveSet, AuthPool, AuthQueue,
        BlockHistory, DisputesState, EpochEntropy, LastAccumulateOutputs, OnChainStatistics,
        PastSet, PendingReports, PrivilegedServices, SafroleState, StagingSet, Timeslot,
    },
};
use std::fmt::Display;

/// Prints a state entry decoded as the state component or account metadata its state key belongs to.
/// A service item entry `C(s, h)` prints as raw octets, since its key holds only a hash of the item key.
/// A value that fails to decode, e.g. one encoded by a later GP rule, also prints as raw octets.
pub(crate) fn display_state_entry(state_key: &StateKey, val_encoded: &[u8]) {
    let Some(state_key_constant) = find_state_key_constant(state_key) else {
        println!(
            "Storage Entry: state_key=0x{}, val=0x{}",
            hex::encode(state_key),
            hex::encode(val_encoded)
        );
        return;
    };
    let decoded = match state_key_constant {
        StateKeyConstant::AuthPool => decode_to_string::<AuthPool>(val_encoded),
        StateKeyConstant::AuthQueue => decode_to_string::<AuthQueue>(val_encoded),
        StateKeyConstant::BlockHistory => decode_to_string::<BlockHistory>(val_encoded),
        StateKeyConstant::SafroleState => decode_to_string::<SafroleState>(val_encoded),
        StateKeyConstant::DisputesState => decode_to_string::<DisputesState>(val_encoded),
        StateKeyConstant::EpochEntropy => decode_to_string::<EpochEntropy>(val_encoded),
        StateKeyConstant::StagingSet => decode_to_string::<StagingSet>(val_encoded),
        StateKeyConstant::ActiveSet => decode_to_string::<ActiveSet>(val_encoded),
        StateKeyConstant::PastSet => decode_to_string::<PastSet>(val_encoded),
        StateKeyConstant::PendingReports => decode_to_string::<PendingReports>(val_encoded),
        StateKeyConstant::Timeslot => {
            Timeslot::decode(&mut &val_encoded[..]).map(|timeslot| format!("{timeslot:?}"))
        }
        StateKeyConstant::PrivilegedServices => decode_to_string::<PrivilegedServices>(val_encoded),
        StateKeyConstant::OnChainStatistics => decode_to_string::<OnChainStatistics>(val_encoded),
        StateKeyConstant::AccumulateQueue => decode_to_string::<AccumulateQueue>(val_encoded),
        StateKeyConstant::AccumulateHistory => decode_to_string::<AccumulateHistory>(val_encoded),
        StateKeyConstant::LastAccumulateOutputs => {
            decode_to_string::<LastAccumulateOutputs>(val_encoded)
        }
        StateKeyConstant::AccountMetadata => {
            decode_to_string::<AccountMetadata>(val_encoded).map(|metadata| {
                let service_id = read_account_metadata_service_id(state_key);
                format!("Service Id: {service_id}\n{metadata}")
            })
        }
    };
    match decoded {
        Ok(decoded) => println!("{decoded}"),
        Err(e) => println!(
            "Undecodable Entry ({e}): state_key=0x{}, val=0x{}",
            hex::encode(state_key),
            hex::encode(val_encoded)
        ),
    }
}

/// Finds the constant of a state component key `C(i)` or an account metadata key `C(255, s)` by matching the whole key.
/// Returns `None` for a service item key `C(s, h)`, whose first octet is the lowest octet of `s` and may equal any constant.
fn find_state_key_constant(state_key: &StateKey) -> Option<StateKeyConstant> {
    let is_account_metadata_key =
        get_account_metadata_state_key(read_account_metadata_service_id(state_key))
            .is_ok_and(|account_metadata_key| account_metadata_key == *state_key);
    if !STATE_KEYS.contains(state_key) && !is_account_metadata_key {
        return None;
    }
    StateKeyConstant::try_from(state_key[0]).ok()
}

/// Reads the service id `s` of an account metadata key `C(255, s)` from its octets 1, 3, 5 and 7 (0-based).
fn read_account_metadata_service_id(state_key: &StateKey) -> ServiceId {
    ServiceId::from_le_bytes([state_key[1], state_key[3], state_key[5], state_key[7]])
}

/// Decodes a state value and formats it for display.
fn decode_to_string<T: JamDecode + Display>(
    mut val_encoded: &[u8],
) -> Result<String, JamCodecError> {
    T::decode(&mut val_encoded).map(|decoded| decoded.to_string())
}
