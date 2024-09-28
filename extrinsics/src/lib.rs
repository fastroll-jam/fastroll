pub mod extrinsics_pool;
pub mod manager;
pub mod submission;

use rjam_codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput};
use rjam_types::extrinsics::{
    assurances::AssuranceExtrinsicEntry, disputes::DisputesExtrinsic,
    guarantees::GuaranteeExtrinsicEntry, preimages::PreimageLookupExtrinsicEntry,
    tickets::TicketExtrinsicEntry,
};

pub(crate) type TicketsExtrinsic = Vec<TicketExtrinsicEntry>;
pub(crate) type GuaranteesExtrinsic = Vec<GuaranteeExtrinsicEntry>;
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
