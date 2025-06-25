use fr_codec::prelude::*;
use fr_common::{AccumulateRoot, Hash32, ServiceId, UnsignedGas};
use fr_crypto::Keccak256;
use fr_merkle::well_balanced_tree::WellBalancedMerkleTree;
use std::collections::BTreeSet;

pub type AccumulationOutputHash = Hash32;

pub type AccumulationGasPairs = Vec<AccumulationGasPair>;

#[derive(Default)]
pub struct AccumulationOutputPairs(pub BTreeSet<AccumulationOutputPair>);

// TODO: Remove this method after updating accumulate STF tests (duplicate: `LastAccumulateOutputs` impl)
impl AccumulationOutputPairs {
    /// Generates a commitment to `AccumulationOutputPairs` using a simple binary merkle tree.
    /// Used for producing the BEEFY commitment after accumulation.
    pub fn accumulate_root(self) -> AccumulateRoot {
        // Note: `AccumulationOutputPairs` is already ordered by service id.
        let ordered_encoded_results = self
            .0
            .into_iter()
            .map(|pair| {
                let mut buf = Vec::with_capacity(36);
                pair.service
                    .encode_to_fixed(&mut buf, 4)
                    .expect("Should not fail");
                pair.output_hash
                    .encode_to(&mut buf)
                    .expect("Should not fail");
                buf
            })
            .collect::<Vec<_>>();
        WellBalancedMerkleTree::<Keccak256>::compute_root(&ordered_encoded_results).unwrap()
    }
}

#[derive(Clone, Debug, PartialOrd, Ord, PartialEq, Eq)]
pub struct AccumulationOutputPair {
    pub service: ServiceId,
    pub output_hash: AccumulationOutputHash,
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

#[derive(Debug)]
pub struct AccumulationGasPair {
    pub service: ServiceId,
    pub gas: UnsignedGas,
}
