use crate::{
    codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput},
    common::{Hash32, HASH32_DEFAULT},
    crypto::utils::blake2b_256,
    impl_jam_codec_for_newtype,
    state::{
        components::timeslot::Timeslot,
        transition::{Transition, TransitionError},
    },
};
use std::fmt::{Display, Formatter};

#[derive(Copy, Clone)]
pub struct EntropyAccumulator(pub [Hash32; 4]);
impl_jam_codec_for_newtype!(EntropyAccumulator, [Hash32; 4]);

impl Display for EntropyAccumulator {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Entropy Accumulator: {{")?;
        for (i, entropy) in self.0.iter().enumerate() {
            writeln!(f, "    entropy #{i}: {}", hex::encode(entropy))?;
        }

        write!(f, "}}")
    }
}

impl Default for EntropyAccumulator {
    fn default() -> Self {
        Self([HASH32_DEFAULT; 4])
    }
}

impl EntropyAccumulator {
    /// Entropy value of the current epoch, accumulated with VRF signatures from each block header
    pub fn current(&self) -> Hash32 {
        self.0[0]
    }

    /// The first historical epoch entropy
    pub fn first_history(&self) -> Hash32 {
        self.0[1]
    }

    /// The second historical epoch entropy
    pub fn second_history(&self) -> Hash32 {
        self.0[2]
    }

    /// The third historical epoch entropy
    pub fn third_history(&self) -> Hash32 {
        self.0[3]
    }
}

#[derive(Clone, Debug)]
pub struct EntropyAccumulatorContext {
    pub timeslot: Timeslot,
    pub is_new_epoch: bool,
    pub entropy_hash: Hash32, // `Y` hash of H_v; new incoming entropy hash from the header
}

impl Transition for EntropyAccumulator {
    type Context = EntropyAccumulatorContext;

    fn to_next(&mut self, ctx: &Self::Context) -> Result<(), TransitionError>
    where
        Self: Sized,
    {
        if ctx.is_new_epoch {
            // Rotate entropy histories at the beginning of a new epoch
            // [e0, e1, e2, e3] => [_, e0, e1, e2]; the new e0 will be calculated and inserted below
            self.0.copy_within(0..3, 1);
        }

        // Accumulate the entropy for the current epoch
        let current_accumulator_hash = self.0[0];
        let mut hash_combined = [0u8; 64];
        hash_combined[..32].copy_from_slice(&current_accumulator_hash[..]);
        hash_combined[32..].copy_from_slice(&ctx.entropy_hash[..]);
        self.0[0] = blake2b_256(&hash_combined[..])?;

        Ok(())
    }
}
