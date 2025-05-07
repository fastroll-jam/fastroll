use crate::types::extrinsics::{ExtrinsicsError, XtEntry, XtType};
use fr_codec::prelude::*;
use fr_common::{workloads::work_report::WorkReport, ValidatorIndex};
use fr_crypto::{
    hash::{hash, Blake2b256},
    types::*,
};
use std::{cmp::Ordering, ops::Deref};

/// Represents a sequence of validator guarantees affirming the validity of a work report
/// to be processed on-chain.
#[derive(Debug, Clone, Default, PartialEq, Eq, JamEncode, JamDecode)]
pub struct GuaranteesXt {
    pub items: Vec<GuaranteesXtEntry>,
}

impl Deref for GuaranteesXt {
    type Target = Vec<GuaranteesXtEntry>;

    fn deref(&self) -> &Self::Target {
        &self.items
    }
}

impl GuaranteesXt {
    /// Extracts Ed25519 keys of `reporters`, who are the validators whose signatures are placed
    /// in the guarantees extrinsic credentials.
    ///
    /// This set is utilized for tracking validator activity statistics.
    pub fn extract_reporters(&self, validator_set: &ValidatorKeySet) -> Vec<Ed25519PubKey> {
        self.iter()
            .flat_map(|entry| {
                entry.credentials.iter().filter_map(|c| {
                    validator_set
                        .get_validator_ed25519_key(c.validator_index)
                        .cloned()
                }) // assuming already passed validations - TODO: revisit
            })
            .collect()
    }

    /// Extracts work reports from the extrinsic.
    ///
    /// This is used for aggregating all work reports that are introduced in the current guarantees
    /// extrinsic, and expected to be validated by `GuaranteesXtValidator`.
    pub fn extract_work_reports(&self) -> Vec<WorkReport> {
        self.iter().map(|entry| entry.work_report.clone()).collect()
    }

    pub fn encode_with_hashed_reports(&self) -> Result<Vec<u8>, ExtrinsicsError> {
        let mut buf = vec![];
        self.items.len().encode_to(&mut buf)?; // length discriminator
        for e in &self.items {
            e.encode_to(&mut buf)?;
        }
        Ok(buf)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct GuaranteesCredential {
    pub validator_index: ValidatorIndex, // v
    pub signature: Ed25519Sig,           // s
}

impl JamEncode for GuaranteesCredential {
    fn size_hint(&self) -> usize {
        2 + self.signature.size_hint()
    }

    fn encode_to<T: JamOutput>(&self, dest: &mut T) -> Result<(), JamCodecError> {
        self.validator_index.encode_to_fixed(dest, 2)?; // TODO: check - Not fixed encoding in GP
        self.signature.encode_to(dest)?;
        Ok(())
    }
}

impl JamDecode for GuaranteesCredential {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError>
    where
        Self: Sized,
    {
        Ok(Self {
            validator_index: ValidatorIndex::decode_fixed(input, 2)?,
            signature: Ed25519Sig::decode(input)?,
        })
    }
}

/// Extrinsic entry containing a work report guaranteed by specific validators called **Guarantors**.
///
/// Each block, three **Guarantors** are assigned per core to refine work packages into work reports
/// and guarantee correctness of the computation. The extrinsic entry carries signatures
/// signed by two or three of the **Guarantors**.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuaranteesXtEntry {
    /// `w`: The work report that is subject to the guarantee.
    pub work_report: WorkReport,
    /// `t`: The timeslot index used for determining timeout of the work report.
    pub timeslot_index: u32,
    /// `a`: The signatures of two or three of the **Guarantors**.
    pub credentials: Vec<GuaranteesCredential>,
}

impl XtEntry for GuaranteesXtEntry {
    const XT_TYPE: XtType = XtType::Guarantee;
}

impl PartialOrd for GuaranteesXtEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for GuaranteesXtEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        self.work_report.cmp(&other.work_report)
    }
}

impl JamEncode for GuaranteesXtEntry {
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

impl JamDecode for GuaranteesXtEntry {
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

impl GuaranteesXtEntry {
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
        signature: Ed25519Sig,
    ) -> Result<(), ExtrinsicsError> {
        if self.credentials.len() >= 3 {
            return Err(ExtrinsicsError::InvalidCredentialCount);
        }

        if self
            .credentials
            .iter()
            .any(|credential| credential.validator_index == validator_index)
        {
            return Err(ExtrinsicsError::DuplicateValidatorIndex);
        }

        self.credentials.push(GuaranteesCredential {
            validator_index,
            signature,
        });

        // Sort the credentials by validator_index
        self.credentials.sort();

        Ok(())
    }

    pub fn credentials(&self) -> &Vec<GuaranteesCredential> {
        &self.credentials
    }

    /// Used for calculating header extrinsics hash
    pub fn encode_with_hashed_report(&self) -> Result<Vec<u8>, ExtrinsicsError> {
        let mut buf = vec![];
        hash::<Blake2b256>(&self.work_report.encode()?)?.encode_to(&mut buf)?;
        self.timeslot_index.encode_to_fixed(&mut buf, 4)?;
        self.credentials.encode_to(&mut buf)?;

        Ok(buf)
    }
}
