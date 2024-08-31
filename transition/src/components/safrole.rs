use crate::{Transition, TransitionError};
use ark_ec_vrfs::prelude::ark_serialize::CanonicalDeserialize;
use jam_common::{
    sorted_limited_tickets::SortedLimitedTickets, Ticket, EPOCH_LENGTH,
    TICKET_SUBMISSION_DEADLINE_SLOT,
};
use jam_crypto::{generate_ring_root, vrf::RingVrfSignature};
use jam_types::{
    extrinsics::tickets::TicketExtrinsicEntry,
    state::{
        entropy::EntropyAccumulator,
        safrole::{generate_fallback_keys, outside_in_vec, SafroleState, SlotSealerType},
        timeslot::Timeslot,
        validators::{ActiveValidatorSet, StagingValidatorSet},
    },
};
use std::fmt::Display;

fn ticket_extrinsics_to_new_tickets(ticket_extrinsics: &[TicketExtrinsicEntry]) -> Vec<Ticket> {
    ticket_extrinsics
        .iter()
        .map(|ticket| {
            let vrf_output_hash =
                RingVrfSignature::deserialize_compressed(&ticket.ticket_proof[..])
                    .unwrap()
                    .output_hash();
            Ticket {
                id: vrf_output_hash,
                attempt: ticket.entry_index, // Assuming entry_index is compatible with u8
            }
        })
        .collect()
}

pub struct SafroleStateContext {
    pub timeslot: Timeslot,
    pub is_new_epoch: bool,
    pub tickets: Vec<TicketExtrinsicEntry>,
    pub current_staging_set: StagingValidatorSet,
    pub post_active_set: ActiveValidatorSet,
    pub post_entropy: EntropyAccumulator,
}

impl Transition for SafroleState {
    type Context = SafroleStateContext;

    fn to_next(&mut self, ctx: &Self::Context) -> Result<(), TransitionError>
    where
        Self: Sized,
    {
        let entropy = ctx.post_entropy.second_history(); // eta_2

        //
        // Per-epoch operations
        //

        if ctx.is_new_epoch {
            // The fallback mode triggers when the slot phase hasn't reached the ticket submission
            // deadline or the ticket accumulator is not yet full.
            // TODO: check how the "slot_phase" is derived (calculated from timeslot or from a separate index)
            // FIXME: should refer to "previous" slot phase
            let is_fallback = ((ctx.timeslot.slot_phase() as usize)
                < TICKET_SUBMISSION_DEADLINE_SLOT)
                || !self.ticket_accumulator.is_full();

            // Update Safrole pending set into Global state staging set
            self.pending_validator_set = ctx.current_staging_set.0;

            // Update the ring root with the updated pending set ring
            self.ring_root = generate_ring_root(&self.pending_validator_set)?;

            // Update slot sealer sequence
            if is_fallback {
                let active_validator_set = ctx.post_active_set.0; // kappa

                self.slot_sealers = SlotSealerType::BandersnatchPubKeys(Box::new(
                    generate_fallback_keys(&active_validator_set, entropy)?,
                ))
            } else {
                let ticket_accumulator_outside_in: [Ticket; EPOCH_LENGTH] =
                    outside_in_vec(self.ticket_accumulator.clone().into_vec())
                        .try_into()
                        .unwrap();

                self.slot_sealers =
                    SlotSealerType::Tickets(Box::new(ticket_accumulator_outside_in));
            }

            // Reset the ticket accumulator
            self.ticket_accumulator = SortedLimitedTickets::new();
        }

        //
        // Per-slot operations
        //

        // let ticket_extrinsics: Vec<TicketExtrinsicEntry> = get_ticket_extrinsics(ctx.timeslot);
        let ticket_extrinsics = &ctx.tickets;

        // Check if the ticket extrinsics are ordered by ticket id
        for window in ticket_extrinsics.windows(2) {
            if let [prev, curr] = window {
                if prev > curr {
                    return Err(TransitionError::TicketsNotOrdered);
                }
            }
        }

        // TODO: Verify the ring VRF proof of each ticket extrinsic

        // Construct "new tickets" from Tickets Extrinsics
        let new_tickets = ticket_extrinsics_to_new_tickets(ticket_extrinsics);

        // Check if the ticket accumulator contains the new ticket entry
        // If not, accumulate the new ticket entry into the accumulator
        for ticket in new_tickets {
            if self.ticket_accumulator.contains(&ticket) {
                return Err(TransitionError::DuplicateTicket);
            }
            self.ticket_accumulator.add(ticket);
        }

        Ok(())
    }
}
