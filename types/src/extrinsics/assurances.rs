use crate::extrinsics::{XtEntry, XtType};
use bit_vec::BitVec;
use rjam_codec::{
    JamCodecError, JamDecode, JamDecodeFixed, JamEncode, JamEncodeFixed, JamInput, JamOutput,
};
use rjam_common::{
    CoreIndex, Ed25519Signature, Hash32, ValidatorIndex, CORE_COUNT, VALIDATORS_SUPER_MAJORITY,
};
use std::{cmp::Ordering, ops::Deref};

/// Represents a sequence of validator assurances regarding the availability of work-reports
/// on assigned cores.
#[derive(Debug, PartialEq, Eq, JamEncode, JamDecode)]
pub struct AssurancesXt {
    pub items: Vec<AssurancesXtEntry>,
}

impl Deref for AssurancesXt {
    type Target = Vec<AssurancesXtEntry>;

    fn deref(&self) -> &Self::Target {
        &self.items
    }
}

impl AssurancesXt {
    pub fn contains_assurance_for_validator(&self, validator_index: ValidatorIndex) -> bool {
        self.iter()
            .any(|entry| entry.validator_index == validator_index)
    }

    /// Aggregates core indices whose availability is assured by more than two-thirds of the
    /// total validators.
    pub fn available_core_indices(&self) -> Vec<CoreIndex> {
        let mut available_core_indices = vec![];
        let mut assurance_counts = vec![0; CORE_COUNT];

        for entry in self.iter() {
            for (i, bool) in entry.assuring_cores_bitvec.iter().enumerate() {
                if bool {
                    assurance_counts[i] += 1;
                }
            }
        }

        for (i, assurance_count) in assurance_counts.into_iter().enumerate() {
            if assurance_count >= (VALIDATORS_SUPER_MAJORITY as u32) {
                available_core_indices.push(i as CoreIndex);
            }
        }

        available_core_indices
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssurancesXtEntry {
    pub anchor_parent_hash: Hash32,      // a
    pub assuring_cores_bitvec: BitVec, // f; `CORE_COUNT` bits fixed-length encoding without length discriminator
    pub validator_index: ValidatorIndex, // v;
    pub signature: Ed25519Signature,   // s
}

impl XtEntry for AssurancesXtEntry {
    const XT_TYPE: XtType = XtType::Assurance;
}

impl PartialOrd for AssurancesXtEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AssurancesXtEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        self.validator_index.cmp(&other.validator_index)
    }
}

impl JamEncode for AssurancesXtEntry {
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

impl JamDecode for AssurancesXtEntry {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError> {
        Ok(Self {
            anchor_parent_hash: Hash32::decode(input)?,
            assuring_cores_bitvec: BitVec::decode_fixed(input, CORE_COUNT)?,
            validator_index: ValidatorIndex::decode_fixed(input, 2)?,
            signature: Ed25519Signature::decode(input)?,
        })
    }
}
