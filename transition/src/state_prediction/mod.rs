//! Collection of methods to predict posterior state even before STFs.
use fr_state::types::Timeslot;

pub mod entropy;
pub mod slot_sealers;
pub mod validator_sets;

pub(crate) fn epoch_progressed(prior_timeslot: &Timeslot, new_timeslot: &Timeslot) -> bool {
    prior_timeslot.epoch() < new_timeslot.epoch()
}
