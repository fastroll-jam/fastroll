use crate::{
    codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput},
    common::Hash32,
    impl_jam_codec_for_newtype,
    transition::{Transition, TransitionContext, TransitionError},
};
use std::fmt::{Display, Formatter};

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

impl Transition for EntropyAccumulator {
    fn next(self, context: &TransitionContext) -> Result<Self, TransitionError>
    where
        Self: Sized,
    {
        todo!()
    }
}
