use crate::{common::workloads::WorkReport, extrinsics::ExtrinsicsError};
use rjam_codec::{
    JamCodecError, JamDecode, JamDecodeFixed, JamEncode, JamEncodeFixed, JamInput, JamOutput,
};
use rjam_common::{Ed25519Signature, ValidatorIndex};
use std::{cmp::Ordering, ops::Deref};

pub type GuaranteesCredential = (ValidatorIndex, Ed25519Signature);

/// Represents a sequence of validator guarantees affirming the validity of a work report
/// to be processed on-chain.
#[derive(Debug, JamEncode, JamDecode)]
pub struct GuaranteesExtrinsic {
    pub items: Vec<GuaranteesExtrinsicEntry>,
}

impl Deref for GuaranteesExtrinsic {
    type Target = Vec<GuaranteesExtrinsicEntry>;

    fn deref(&self) -> &Self::Target {
        &self.items
    }
}

/// Extrinsic entry containing a work report guaranteed by specific validators called `Guarantors`.
///
/// Each block, three `Guarantors` are assigned per core to verify accuracy of the work and this
/// extrinsic entry carries guaranteeing signature from two or three of the `Guarantors`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuaranteesExtrinsicEntry {
    pub work_report: WorkReport,                // w
    pub timeslot_index: u32,                    // t
    pub credentials: Vec<GuaranteesCredential>, // a
}

impl PartialOrd for GuaranteesExtrinsicEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for GuaranteesExtrinsicEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        self.work_report.cmp(&other.work_report)
    }
}

impl JamEncode for GuaranteesExtrinsicEntry {
    fn size_hint(&self) -> usize {
        self.work_report.size_hint() + 4 + self.credentials.size_hint()
    }

    fn encode_to<T: JamOutput>(&self, dest: &mut T) -> Result<(), JamCodecError> {
        self.work_report.encode_to(dest)?;
        self.timeslot_index.encode_to_fixed(dest, 4)?;
        self.credentials.encode_to(dest)?;
        Ok(())
    }
}

impl JamDecode for GuaranteesExtrinsicEntry {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError>
    where
        Self: Sized,
    {
        Ok(Self {
            work_report: WorkReport::decode(input)?,
            timeslot_index: u32::decode_fixed(input, 4)?,
            credentials: Vec::<GuaranteesCredential>::decode(input)?,
        })
    }
}

impl GuaranteesExtrinsicEntry {
    pub fn new(work_report: WorkReport, timeslot_index: u32) -> Self {
        Self {
            work_report,
            timeslot_index,
            credentials: Vec::with_capacity(3),
        }
    }

    /// Add a new credential, or a `Guarantee` by a guarantor to the credentials vector while keeping
    /// the credentials ordered by validator index.
    pub fn add_credential(
        &mut self,
        validator_index: ValidatorIndex,
        signature: Ed25519Signature,
    ) -> Result<(), ExtrinsicsError> {
        if self.credentials.len() >= 3 {
            return Err(ExtrinsicsError::InvalidCredentialCount);
        }

        if self
            .credentials
            .iter()
            .any(|&(idx, _)| idx == validator_index)
        {
            return Err(ExtrinsicsError::DuplicateValidatorIndex);
        }

        self.credentials.push((validator_index, signature));

        // Sort the credentials by validator_index
        self.credentials.sort_by_key(|&(idx, _)| idx);

        Ok(())
    }

    pub fn credentials(&self) -> &Vec<GuaranteesCredential> {
        &self.credentials
    }
}
