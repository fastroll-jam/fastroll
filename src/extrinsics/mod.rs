use crate::{
    codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput},
    extrinsics::{
        assurances::AssuranceExtrinsicEntry, guarantees::GuaranteeExtrinsicEntry,
        preimages::PreimageLookupExtrinsicEntry, tickets::TicketExtrinsicEntry,
        verdicts::VerdictsExtrinsic,
    },
};

mod assurances;
mod guarantees;
mod preimages;
mod tickets;
mod verdicts;

type TicketsExtrinsic = Vec<TicketExtrinsicEntry>;
type GuaranteesExtrinsic = Vec<GuaranteeExtrinsicEntry>;
type AssurancesExtrinsic = Vec<AssuranceExtrinsicEntry>; // length up to VALIDATOR_COUNT
type PreimageLookupsExtrinsic = Vec<PreimageLookupExtrinsicEntry>;

pub struct Extrinsics {
    tickets_extrinsic: TicketsExtrinsic,                  // E_T
    guarantees_extrinsic: GuaranteesExtrinsic,            // E_G
    assurances_extrinsic: AssurancesExtrinsic,            // E_A
    preimage_lookups_extrinsic: PreimageLookupsExtrinsic, // E_P
    verdicts_extrinsic: VerdictsExtrinsic,                // E_V
}

impl JamEncode for Extrinsics {
    fn size_hint(&self) -> usize {
        self.tickets_extrinsic.size_hint()
            + self.verdicts_extrinsic.size_hint()
            + self.preimage_lookups_extrinsic.size_hint()
            + self.assurances_extrinsic.size_hint()
            + self.guarantees_extrinsic.size_hint()
    }

    fn encode_to<W: JamOutput>(&self, dest: &mut W) -> Result<(), JamCodecError> {
        self.tickets_extrinsic.encode_to(dest)?;
        self.verdicts_extrinsic.encode_to(dest)?;
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
            verdicts_extrinsic: VerdictsExtrinsic::decode(input)?,
            preimage_lookups_extrinsic: PreimageLookupsExtrinsic::decode(input)?,
            assurances_extrinsic: AssurancesExtrinsic::decode(input)?,
            guarantees_extrinsic: GuaranteesExtrinsic::decode(input)?,
        })
    }
}
