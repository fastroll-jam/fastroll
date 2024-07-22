use crate::{
    codec::utils::{
        decode_length_discriminated_field, encode_length_discriminated_field,
        size_hint_length_discriminated_field,
    },
    extrinsics::{
        assurances::AssuranceExtrinsicEntry, guarantees::GuaranteeExtrinsicEntry,
        preimages::PreimageLookupExtrinsicEntry, tickets::TicketExtrinsicEntry,
        verdicts::VerdictsExtrinsic,
    },
};
use parity_scale_codec::{Decode, Encode, Error, Input, Output};

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

impl Encode for Extrinsics {
    fn size_hint(&self) -> usize {
        size_hint_length_discriminated_field(&self.tickets_extrinsic)
            + self.verdicts_extrinsic.size_hint()
            + size_hint_length_discriminated_field(&self.preimage_lookups_extrinsic)
            + size_hint_length_discriminated_field(&self.assurances_extrinsic)
            + size_hint_length_discriminated_field(&self.guarantees_extrinsic)
    }

    fn encode_to<W: Output + ?Sized>(&self, dest: &mut W) {
        encode_length_discriminated_field(&self.tickets_extrinsic, dest);
        self.verdicts_extrinsic.encode_to(dest);
        encode_length_discriminated_field(&self.preimage_lookups_extrinsic, dest);
        encode_length_discriminated_field(&self.assurances_extrinsic, dest);
        encode_length_discriminated_field(&self.guarantees_extrinsic, dest);
    }
}

impl Decode for Extrinsics {
    fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
        Ok(Self {
            tickets_extrinsic: decode_length_discriminated_field(input)?,
            verdicts_extrinsic: VerdictsExtrinsic::decode(input)?,
            preimage_lookups_extrinsic: decode_length_discriminated_field(input)?,
            assurances_extrinsic: decode_length_discriminated_field(input)?,
            guarantees_extrinsic: decode_length_discriminated_field(input)?,
        })
    }
}
