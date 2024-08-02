use crate::{
    codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput},
    common::{BandersnatchSignature, Hash32, HASH32_DEFAULT},
    crypto::utils::{blake2b_256, entropy_hash_ietf_vrf},
    impl_jam_codec_for_newtype,
    state::components::timeslot::Timeslot,
    transition::{SlotType, Transition, TransitionError},
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

pub struct EntropyAccumulatorContext {
    timeslot: Timeslot,
    slot_type: SlotType,
    header_vrf_signature: BandersnatchSignature, // H_v
}

impl Transition for EntropyAccumulator {
    type Context = EntropyAccumulatorContext;

    fn next(&mut self, ctx: &Self::Context) -> Result<(), TransitionError>
    where
        Self: Sized,
    {
        let current_accumulator_hash = self.0[0].clone();
        let header_vrf_entropy_hash = entropy_hash_ietf_vrf(&ctx.header_vrf_signature);
        let mut hash_combined = [0u8; 64];
        hash_combined[..32].copy_from_slice(&current_accumulator_hash);
        hash_combined[32..].copy_from_slice(&header_vrf_entropy_hash);
        self.0[0] = blake2b_256(&hash_combined[..])?;
        Ok(())
    }
}
