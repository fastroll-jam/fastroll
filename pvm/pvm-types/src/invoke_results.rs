use fr_codec::prelude::*;
use fr_common::{Hash32, ServiceId, UnsignedGas};
use std::{
    collections::BTreeSet,
    fmt::{Display, Formatter},
};

pub type AccumulationOutputHash = Hash32;

pub type AccumulationGasPairs = Vec<AccumulationGasPair>;

#[derive(Debug)]
pub struct AccumulationGasPair {
    pub service: ServiceId,
    pub gas: UnsignedGas,
}

#[derive(Clone, Debug, PartialOrd, Ord, PartialEq, Eq)]
pub struct AccumulationOutputPair {
    pub service: ServiceId,
    pub output_hash: AccumulationOutputHash,
}

impl Display for AccumulationOutputPair {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "service={}, hash={}", self.service, self.output_hash)
    }
}

impl JamEncode for AccumulationOutputPair {
    fn size_hint(&self) -> usize {
        4 + 32
    }

    fn encode_to<T: JamOutput>(&self, dest: &mut T) -> Result<(), JamCodecError> {
        self.service.encode_to_fixed(dest, 4)?;
        self.output_hash.encode_to(dest)?;
        Ok(())
    }
}

impl JamDecode for AccumulationOutputPair {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError>
    where
        Self: Sized,
    {
        Ok(Self {
            service: ServiceId::decode_fixed(input, 4)?,
            output_hash: AccumulationOutputHash::decode(input)?,
        })
    }
}

#[derive(Default)]
pub struct AccumulationOutputPairs(pub BTreeSet<AccumulationOutputPair>);
