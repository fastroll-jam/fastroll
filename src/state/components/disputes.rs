use crate::{
    codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput},
    common::{Ed25519PubKey, Hash32},
};

// TODO: these sets should always be sorted
pub(crate) struct DisputesState {
    good_set: Vec<Hash32>,          // psi_g; recording hash of correct work-reports
    bad_set: Vec<Hash32>,           // psi_b; recording hash of incorrect work-reports
    wonky_set: Vec<Hash32>,         // psi_w; recording hash of work-reports that cannot be judged
    punish_set: Vec<Ed25519PubKey>, // psi_p; recording Ed25519 public keys of validators which have misjudged.
}

impl JamEncode for DisputesState {
    fn size_hint(&self) -> usize {
        self.good_set.size_hint()
            + self.bad_set.size_hint()
            + self.wonky_set.size_hint()
            + self.punish_set.size_hint()
    }

    fn encode_to<W: JamOutput>(&self, dest: &mut W) -> Result<(), JamCodecError> {
        self.good_set.encode_to(dest)?;
        self.bad_set.encode_to(dest)?;
        self.wonky_set.encode_to(dest)?;
        self.punish_set.encode_to(dest)?;
        Ok(())
    }
}

impl JamDecode for DisputesState {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError> {
        Ok(Self {
            good_set: Vec::decode(input)?,
            bad_set: Vec::decode(input)?,
            wonky_set: Vec::decode(input)?,
            punish_set: Vec::decode(input)?,
        })
    }
}
