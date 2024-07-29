use crate::{
    codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput},
    extrinsics::components::{
        assurances::AssuranceExtrinsicEntry, disputes::DisputesExtrinsic,
        guarantees::GuaranteeExtrinsicEntry, preimages::PreimageLookupExtrinsicEntry,
        tickets::TicketExtrinsicEntry,
    },
};

pub(crate) mod components;
pub(crate) mod extrinsics_pool;

type TicketsExtrinsic = Vec<TicketExtrinsicEntry>;
type GuaranteesExtrinsic = Vec<GuaranteeExtrinsicEntry>;
type AssurancesExtrinsic = Vec<AssuranceExtrinsicEntry>; // length up to VALIDATOR_COUNT
type PreimageLookupsExtrinsic = Vec<PreimageLookupExtrinsicEntry>;

pub struct Extrinsics {
    tickets_extrinsic: TicketsExtrinsic,                  // E_T
    guarantees_extrinsic: GuaranteesExtrinsic,            // E_G
    assurances_extrinsic: AssurancesExtrinsic,            // E_A
    preimage_lookups_extrinsic: PreimageLookupsExtrinsic, // E_P
    disputes_extrinsic: DisputesExtrinsic,                // E_V
}

impl JamEncode for Extrinsics {
    fn size_hint(&self) -> usize {
        self.tickets_extrinsic.size_hint()
            + self.disputes_extrinsic.size_hint()
            + self.preimage_lookups_extrinsic.size_hint()
            + self.assurances_extrinsic.size_hint()
            + self.guarantees_extrinsic.size_hint()
    }

    fn encode_to<W: JamOutput>(&self, dest: &mut W) -> Result<(), JamCodecError> {
        self.tickets_extrinsic.encode_to(dest)?;
        self.disputes_extrinsic.encode_to(dest)?;
        self.preimage_lookups_extrinsic.encode_to(dest)?;
        self.assurances_extrinsic.encode_to(dest)?;
        self.guarantees_extrinsic.encode_to(dest)?;
        Ok(())
    }
}

impl JamDecode for Extrinsics {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError> {
        Ok(Self {
            tickets_extrinsic: TicketsExtrinsic::decode(input)?,
            disputes_extrinsic: DisputesExtrinsic::decode(input)?,
            preimage_lookups_extrinsic: PreimageLookupsExtrinsic::decode(input)?,
            assurances_extrinsic: AssurancesExtrinsic::decode(input)?,
            guarantees_extrinsic: GuaranteesExtrinsic::decode(input)?,
        })
    }
}
