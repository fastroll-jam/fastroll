use crate::types::extrinsics::{XtEntry, XtType};
use fr_codec::prelude::*;
use fr_common::{Hash32, X_T};
use fr_crypto::{traits::VrfSignature, types::*, vrf::bandersnatch_vrf::RingVrfProver};
use std::{cmp::Ordering, fmt::Display, ops::Deref};

/// Represents a sequence of validators' ticket proofs for block authoring privileges.
#[derive(Debug, Clone, Default, PartialEq, Eq, JamEncode, JamDecode)]
pub struct TicketsXt {
    pub items: Vec<TicketsXtEntry>,
}

impl Deref for TicketsXt {
    type Target = Vec<TicketsXtEntry>;

    fn deref(&self) -> &Self::Target {
        &self.items
    }
}

impl Display for TicketsXt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TicketsXt [")?;
        for item in self.items.iter() {
            write!(f, "{item}, ")?;
        }
        write!(f, "]")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, JamEncode, JamDecode)]
pub struct TicketsXtEntry {
    /// `r`: The ticket entry index, either 0 or 1.
    pub entry_index: u8,
    /// `p`: The ticket identifier (note: different from `Ticket` which contains hash of the proof as a ticket id)
    pub ticket_proof: BandersnatchRingVrfSig,
}

impl Display for TicketsXtEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "TicketsXtEntry {{ entry_index: {}, ticket_proof_hash: {} }}",
            self.entry_index,
            self.ticket_proof.output_hash(),
        )
    }
}

impl XtEntry for TicketsXtEntry {
    const XT_TYPE: XtType = XtType::Ticket;
}

impl PartialOrd for TicketsXtEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TicketsXtEntry {
    // Compare the ticket extrinsics by the hash of the ticket proofs, which is not explicitly
    // represented by the `TicketsXtEntry`.
    fn cmp(&self, other: &Self) -> Ordering {
        let self_hash = self.ticket_proof.output_hash();
        let other_hash = other.ticket_proof.output_hash();
        self_hash.cmp(&other_hash)
    }
}

impl TicketsXtEntry {
    pub fn new(prover: &RingVrfProver, entry_index: u8, entropy_2: &Hash32) -> Self {
        let mut context = Vec::with_capacity(X_T.len() + entropy_2.len() + 1);
        context.extend_from_slice(X_T);
        context.extend_from_slice(entropy_2.as_slice());
        context.push(entry_index);

        let message = vec![]; // no message for ticket vrf signature
        let ticket_proof = prover.sign_ring_vrf(&context, &message);

        Self {
            entry_index,
            ticket_proof,
        }
    }
}
