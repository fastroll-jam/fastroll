use crate::{
    codec::{
        JamCodecError, JamDecode, JamDecodeFixed, JamEncode, JamEncodeFixed, JamInput, JamOutput,
    },
    common::{Ed25519Signature, Hash32, CORE_COUNT},
};
use bit_vec::BitVec;

#[derive(Clone, Ord, PartialOrd, PartialEq, Eq)]
pub(crate) struct AssuranceExtrinsicEntry {
    anchor_parent_hash: Hash32,    // a
    assuring_cores_bitvec: BitVec, // f; `CORE_COUNT` bits fixed-length encoding without length discriminator
    validator_index: u16,          // v; N_V
    signature: Ed25519Signature,   // s
}

impl JamEncode for AssuranceExtrinsicEntry {
    fn size_hint(&self) -> usize {
        self.anchor_parent_hash.size_hint()
            + (self.assuring_cores_bitvec.len() + 7) / 8 // size hint for packed bits in bytes (fixed-length encoding)
            + self.validator_index.size_hint()
            + self.signature.size_hint()
    }

    fn encode_to<W: JamOutput>(&self, dest: &mut W) -> Result<(), JamCodecError> {
        self.anchor_parent_hash.encode_to(dest)?;
        self.assuring_cores_bitvec
            .encode_to_fixed(dest, CORE_COUNT)?;
        self.validator_index.encode_to(dest)?; // TODO: check if this should take the first 2 bytes only
        self.signature.encode_to(dest)?;
        Ok(())
    }
}

impl JamDecode for AssuranceExtrinsicEntry {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError> {
        Ok(Self {
            anchor_parent_hash: Hash32::decode(input)?,
            assuring_cores_bitvec: BitVec::decode_fixed(input, CORE_COUNT)?,
            validator_index: u16::decode(input)?,
            signature: Ed25519Signature::decode(input)?,
        })
    }
}
