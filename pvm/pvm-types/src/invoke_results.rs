use fr_common::{Hash32, ServiceId, UnsignedGas};
use std::collections::BTreeSet;

pub type AccumulationOutputHash = Hash32;

pub type AccumulationOutputPairs = BTreeSet<AccumulationOutputPair>;

pub type AccumulationGasPairs = Vec<AccumulationGasPair>;

#[derive(Debug, PartialOrd, Ord, PartialEq, Eq)]
pub struct AccumulationOutputPair {
    pub service: ServiceId,
    pub output_hash: AccumulationOutputHash,
}

#[derive(Debug)]
pub struct AccumulationGasPair {
    pub service: ServiceId,
    pub gas: UnsignedGas,
}
