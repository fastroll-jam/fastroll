use crate::extrinsics::{
    assurances::AssuranceExtrinsicEntry, disputes::DisputesExtrinsic,
    guarantees::GuaranteesExtrinsicEntry, preimages::PreimageLookupExtrinsicEntry,
    tickets::TicketExtrinsicEntry,
};
use rjam_codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput};

pub mod assurances;
pub mod disputes;
pub mod guarantees;
pub mod preimages;
pub mod tickets;

pub(crate) type TicketsExtrinsic = Vec<TicketExtrinsicEntry>;
pub(crate) type GuaranteesExtrinsic = Vec<GuaranteesExtrinsicEntry>;
pub(crate) type AssurancesExtrinsic = Vec<AssuranceExtrinsicEntry>; // length up to VALIDATOR_COUNT
pub(crate) type PreimageLookupsExtrinsic = Vec<PreimageLookupExtrinsicEntry>;

// Struct used for Extrinsics serialization
#[derive(Debug, JamEncode, JamDecode)]
pub struct Extrinsics {
    tickets_extrinsic: TicketsExtrinsic,                  // E_T
    guarantees_extrinsic: GuaranteesExtrinsic,            // E_G
    assurances_extrinsic: AssurancesExtrinsic,            // E_A
    preimage_lookups_extrinsic: PreimageLookupsExtrinsic, // E_P
    disputes_extrinsic: DisputesExtrinsic,                // E_V
}
