use bit_vec::BitVec;
use rjam_codec::{
    JamCodecError, JamDecode, JamDecodeFixed, JamEncode, JamEncodeFixed, JamInput, JamOutput,
};
use rjam_common::{Ed25519Signature, Hash32, ValidatorIndex, CORE_COUNT};
use std::{cmp::Ordering, ops::Deref};

/// Represents a sequence of validator assurances regarding the availability of work-reports
/// on assigned cores.
#[derive(Debug, JamEncode, JamDecode)]
pub struct AssurancesExtrinsic {
    pub items: Vec<AssurancesExtrinsicEntry>,
}

impl Deref for AssurancesExtrinsic {
    type Target = Vec<AssurancesExtrinsicEntry>;

    fn deref(&self) -> &Self::Target {
        &self.items
    }
}

impl AssurancesExtrinsic {
    pub fn contains_assurance_for_validator(&self, validator_index: ValidatorIndex) -> bool {
        self.iter()
            .any(|entry| entry.validator_index == validator_index)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssurancesExtrinsicEntry {
    pub anchor_parent_hash: Hash32,      // a
    pub assuring_cores_bitvec: BitVec, // f; `CORE_COUNT` bits fixed-length encoding without length discriminator
    pub validator_index: ValidatorIndex, // v;
    pub signature: Ed25519Signature,   // s
}

impl PartialOrd for AssurancesExtrinsicEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AssurancesExtrinsicEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        self.validator_index.cmp(&other.validator_index)
    }
}

impl JamEncode for AssurancesExtrinsicEntry {
    fn size_hint(&self) -> usize {
        self.anchor_parent_hash.size_hint() + (CORE_COUNT + 7) / 8 + 2 + self.signature.size_hint()
    }

    fn encode_to<W: JamOutput>(&self, dest: &mut W) -> Result<(), JamCodecError> {
        self.anchor_parent_hash.encode_to(dest)?;
        self.assuring_cores_bitvec
            .encode_to_fixed(dest, CORE_COUNT)?;
        self.validator_index.encode_to_fixed(dest, 2)?;
        self.signature.encode_to(dest)?;
        Ok(())
    }
}

impl JamDecode for AssurancesExtrinsicEntry {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError> {
        Ok(Self {
            anchor_parent_hash: Hash32::decode(input)?,
            assuring_cores_bitvec: BitVec::decode_fixed(input, CORE_COUNT)?,
            validator_index: ValidatorIndex::decode_fixed(input, 2)?,
            signature: Ed25519Signature::decode(input)?,
        })
    }
}
