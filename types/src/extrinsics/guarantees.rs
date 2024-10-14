use crate::extrinsics::ExtrinsicsError;
use rjam_codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput};
use rjam_common::{Ed25519Signature, WorkReport};

/// Extrinsic entry containing a work report guaranteed by specific validators called `Guarantors`.
///
/// Each block, three `Guarantors` are assigned per core to verify accuracy of the work and this
/// extrinsic entry carries guaranteeing signature from two or three of the `Guarantors`.
#[derive(Debug, Clone, PartialEq, Eq, JamEncode, JamDecode)]
pub struct GuaranteesExtrinsicEntry {
    work_report: WorkReport,                   // w
    timeslot: u32,                             // t
    credentials: Vec<(u16, Ed25519Signature)>, // a; length either 2 or 3
}

impl GuaranteesExtrinsicEntry {
    pub fn new(work_report: WorkReport, timeslot: u32) -> Self {
        Self {
            work_report,
            timeslot,
            credentials: Vec::with_capacity(3),
        }
    }

    /// Add a new credential, or a `Guarantee` by a guarantor to the credentials vector while keeping
    /// the credentials ordered by validator index.
    pub fn add_credential(
        &mut self,
        validator_index: u16,
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

    pub fn get_credentials(&self) -> &[(u16, Ed25519Signature)] {
        &self.credentials
    }
}
