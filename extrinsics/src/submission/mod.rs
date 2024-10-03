// // TODO: add networking layer to communicate with peer JAM validators via `JAMSNP` protocol
// // TODO: add trait for generic representation of extrinsic submission behaviours (e.g. construct, submit)
//
// use rjam_common::{BandersnatchRingVrfProof, X_T};
// use rjam_crypto::{validator_set_to_ring, vrf::Prover};
// use rjam_state::state_retriever::StateRetriever;
// use rjam_types::extrinsics::tickets::TicketExtrinsicEntry;
//
// pub(crate) fn submit_ticket_extrinsic(retriever: &StateRetriever) {
//     let prover_idx: usize = 0; // FIXME: proper indexing required for validator identity
//
//     let safrole_state = retriever.get_safrole_state().unwrap(); // TODO: state caching if needed / Error handling
//     let pending_set = safrole_state.pending_set;
//
//     let ring = validator_set_to_ring(&pending_set).unwrap(); // the ring should be valid validators of the next epoch
//     let prover = Prover::new(ring, prover_idx);
//
//     let entropy_state = retriever.get_entropy_accumulator().unwrap();
//     let entropy_2 = entropy_state.0[2]; // TODO: get the posterior state if entropy state has been updated
//
//     let entry_index = 0u8; // TODO: proper handling (0 or 1)
//
//     let message = &[]; // Generating ticket proof; no signing message needed here
//     let context_vec = [X_T.as_bytes(), &entropy_2[..], &[entry_index]].concat();
//     let context: &[u8] = &context_vec;
//
//     let ring_vrf_proof: BandersnatchRingVrfProof = prover
//         .ring_vrf_sign(context, message)
//         .try_into()
//         .expect("Proof length mismatch");
//
//     let ticket_extrinsic = TicketExtrinsicEntry {
//         entry_index,
//         ticket_proof: ring_vrf_proof,
//     };
//
//     // TODO: propagate the extrinsic via JAMSNP protocol
//     // TODO: add submitted extrinsic to the ExtrinsicsPool
//
//     // TODO: tickets should be always ordered by the hash value of the ticket proof (ticket id)
// }
