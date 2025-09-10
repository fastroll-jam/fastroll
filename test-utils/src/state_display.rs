use fr_codec::prelude::*;
use fr_common::ServiceId;
use fr_state::types::{
    AccountMetadata, AccumulateHistory, AccumulateQueue, ActiveSet, AuthPool, AuthQueue,
    BlockHistory, DisputesState, EpochEntropy, LastAccumulateOutputs, OnChainStatistics, PastSet,
    PendingReports, PrivilegedServices, SafroleState, StagingSet, Timeslot,
};

pub(crate) fn display_state_entry(key_encoded: &[u8], mut val_encoded: &[u8]) {
    let first_byte = key_encoded[0];
    match first_byte {
        1 => {
            let decoded = AuthPool::decode(&mut val_encoded).unwrap();
            println!("{decoded}");
        }
        2 => {
            let decoded = AuthQueue::decode(&mut val_encoded).unwrap();
            println!("{decoded:?}");
        }
        3 => {
            let decoded = BlockHistory::decode(&mut val_encoded).unwrap();
            println!("{decoded:?}");
        }
        4 => {
            let decoded = SafroleState::decode(&mut val_encoded).unwrap();
            println!("{decoded}");
        }
        5 => {
            let decoded = DisputesState::decode(&mut val_encoded).unwrap();
            println!("{decoded:?}");
        }
        6 => {
            let decoded = EpochEntropy::decode(&mut val_encoded).unwrap();
            println!("{decoded}");
        }
        7 => {
            let decoded = StagingSet::decode(&mut val_encoded).unwrap();
            println!("{decoded}");
        }
        8 => {
            let decoded = ActiveSet::decode(&mut val_encoded).unwrap();
            println!("{decoded}");
        }
        9 => {
            let decoded = PastSet::decode(&mut val_encoded).unwrap();
            println!("{decoded}");
        }
        10 => {
            let decoded = PendingReports::decode(&mut val_encoded).unwrap();
            println!("{decoded}");
        }
        11 => {
            let decoded = Timeslot::decode(&mut val_encoded).unwrap();
            println!("{decoded:?}");
        }
        12 => {
            let decoded = PrivilegedServices::decode(&mut val_encoded).unwrap();
            println!("{decoded:?}");
        }
        13 => {
            let decoded = OnChainStatistics::decode(&mut val_encoded).unwrap();
            println!("{decoded:?}");
        }
        14 => {
            let decoded = AccumulateQueue::decode(&mut val_encoded).unwrap();
            println!("{decoded:?}");
        }
        15 => {
            let decoded = AccumulateHistory::decode(&mut val_encoded).unwrap();
            println!("{decoded:?}");
        }
        16 => {
            let decoded = LastAccumulateOutputs::decode(&mut val_encoded).unwrap();
            println!("{decoded:?}");
        }
        255 => {
            let mut service_id_buf = Vec::with_capacity(4);
            service_id_buf.push(key_encoded[1]);
            service_id_buf.push(key_encoded[3]);
            service_id_buf.push(key_encoded[5]);
            service_id_buf.push(key_encoded[7]);
            let service_id = ServiceId::decode_fixed(&mut service_id_buf.as_slice(), 4).unwrap();
            println!("Service Id: {service_id}");
            let decoded = AccountMetadata::decode(&mut val_encoded).unwrap();
            println!("{decoded:?}");
        }
        _ => {
            println!("Storage entry: {}", hex::encode(&val_encoded));
        }
    }
}
