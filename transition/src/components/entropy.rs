use crate::{Transition, TransitionError};
use rjam_common::Hash32;
use rjam_crypto::utils::blake2b_256;
use rjam_types::state::{entropy::EntropyAccumulator, timeslot::Timeslot};
use std::fmt::Display;

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
