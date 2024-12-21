use crate::{
    impl_state_component,
    state_utils::{StateComponent, StateEntryType, StateKeyConstant},
};
use rjam_codec::{
    impl_jam_codec_for_newtype, JamCodecError, JamDecode, JamEncode, JamInput, JamOutput,
};
use rjam_common::{Hash32, HASH32_EMPTY};
use std::fmt::{Display, Formatter};

#[derive(Clone)]
pub struct EntropyAccumulator(pub [Hash32; 4]);
impl_jam_codec_for_newtype!(EntropyAccumulator, [Hash32; 4]);
impl_state_component!(EntropyAccumulator, EntropyAccumulator);

impl Display for EntropyAccumulator {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Entropy Accumulator: {{")?;
        for (i, entropy) in self.0.iter().enumerate() {
            writeln!(f, "\tentropy #{i}: {}", entropy.encode_hex())?;
        }

        write!(f, "}}")
    }
}

impl Default for EntropyAccumulator {
    fn default() -> Self {
        Self([HASH32_EMPTY; 4])
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
