use crate::{
    impl_simple_state_component,
    state_utils::{SimpleStateComponent, StateComponent, StateEntryType, StateKeyConstant},
};
use rjam_codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput};
use rjam_common::Hash32;
use std::fmt::{Display, Formatter};

/// The per-epoch entropy accumulator and its historical values.
///
/// Represents `η` of the GP.
#[derive(Clone, Debug, Default, PartialEq, Eq, JamEncode, JamDecode)]
pub struct EpochEntropy(pub [Hash32; 4]);
impl_simple_state_component!(EpochEntropy, EpochEntropy);

impl Display for EpochEntropy {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Epoch Entropy: {{")?;
        for (i, entropy) in self.0.iter().enumerate() {
            writeln!(f, "\tentropy #{i}: {}", entropy.encode_hex())?;
        }

        write!(f, "}}")
    }
}

impl EpochEntropy {
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
