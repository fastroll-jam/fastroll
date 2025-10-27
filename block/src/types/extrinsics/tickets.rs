use crate::types::extrinsics::{XtEntry, XtType};
use fr_codec::prelude::*;
use fr_common::{EntropyHash, X_T};
use fr_crypto::{
    error::CryptoError, traits::VrfSignature, types::*, vrf::bandersnatch_vrf::RingVrfProver,
};
use std::{fmt::Display, ops::Deref};

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
    /// `e`: The ticket entry index, either 0 or 1.
    pub entry_index: u8,
    /// `p`: The ticket identifier (note: different from `Ticket` which contains hash of the proof as a ticket id)
    pub ticket_proof: BandersnatchRingVrfSig,
}

impl Display for TicketsXtEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.ticket_proof.output_hash() {
            Ok(output_hash) => write!(
                f,
                "TicketsXtEntry {{ entry_index: {}, ticket_proof_hash: {} }}",
                self.entry_index, output_hash
            ),
            Err(_) => write!(
                f,
                "TicketsXtEntry {{ entry_index: {}, ticket_proof_hash: INVALID }}",
                self.entry_index,
            ),
        }
    }
}

impl XtEntry for TicketsXtEntry {
    const XT_TYPE: XtType = XtType::Ticket;
}

impl TicketsXtEntry {
    pub fn new(
        prover: &RingVrfProver,
        entry_index: u8,
        entropy_2: &EntropyHash,
    ) -> Result<Self, CryptoError> {
        let context = [X_T, entropy_2.as_slice(), &[entry_index]].concat();
        let message = vec![]; // no message for ticket vrf signature
        let ticket_proof = prover.sign_ring_vrf(&context, &message)?;

        Ok(Self {
            entry_index,
            ticket_proof,
        })
    }
}
