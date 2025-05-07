use crate::types::extrinsics::{XtEntry, XtType};
use bit_vec::BitVec;
use fr_codec::prelude::*;
use fr_common::{CoreIndex, Hash32, ValidatorIndex, CORE_COUNT, VALIDATORS_SUPER_MAJORITY};
use fr_crypto::types::*;
use std::{cmp::Ordering, ops::Deref};

/// The assurances extrinsic submitted by validators assuring the availability of work reports
/// on assigned cores.
#[derive(Debug, Clone, Default, PartialEq, Eq, JamEncode, JamDecode)]
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
        self.cores_assurances_counts()
            .into_iter()
            .enumerate()
            .filter(|(_, assurance_count)| *assurance_count >= VALIDATORS_SUPER_MAJORITY)
            .map(|(i, _)| i as CoreIndex)
            .collect()
    }

    /// Returns the number of assurances a core received within the collection of extrinsics.
    pub fn cores_assurances_counts(&self) -> Vec<usize> {
        self.iter().fold(vec![0; CORE_COUNT], |mut counts, entry| {
            entry
                .assuring_cores_bitvec
                .iter()
                .enumerate()
                .for_each(|(i, assured)| counts[i] += assured as usize);
            counts
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssurancesXtEntry {
    /// `a`: The parent block hash.
    pub anchor_parent_hash: Hash32,
    /// `f`: A bit sequence of length `CORE_COUNT` representing indices of cores this entry assures.
    pub assuring_cores_bitvec: BitVec,
    /// `v`: The validator index.
    pub validator_index: ValidatorIndex,
    /// `s`: The signature of the validator.
    pub signature: Ed25519Sig,
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
        self.anchor_parent_hash.size_hint()
            + CORE_COUNT.div_ceil(8)
            + 2
            + self.signature.size_hint()
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
            signature: Ed25519Sig::decode(input)?,
        })
    }
}
