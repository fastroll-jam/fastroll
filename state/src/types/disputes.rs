use crate::{
    impl_simple_state_component,
    state_utils::{SimpleStateComponent, StateComponent, StateEntryType, StateKeyConstant},
};
use fr_codec::prelude::*;
use fr_common::WorkReportHash;
use fr_crypto::types::*;
use std::fmt::{Display, Formatter};

/// A record of historical dispute verdicts and their associated offenders set.
///
/// Represents `ψ` of the GP.
#[derive(Clone, Debug, Default, PartialEq, Eq, JamEncode, JamDecode)]
pub struct DisputesState {
    /// `ψ_G`: Hash of correct work-reports.
    pub good_set: Vec<WorkReportHash>,
    /// `ψ_B`: Hash of incorrect work-reports.
    pub bad_set: Vec<WorkReportHash>,
    /// `ψ_W`: Hash of work-reports that cannot be judged.
    pub wonky_set: Vec<WorkReportHash>,
    /// `ψ_O`: Ed25519 public keys of validators who are offenders (culprits or faults).
    pub punish_set: Vec<Ed25519PubKey>,
}
impl_simple_state_component!(DisputesState, DisputesState);

impl Display for DisputesState {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "DisputesState {{")?;
        writeln!(f, "  good_set: [")?;
        for entry in self.good_set.iter() {
            writeln!(f, "    {entry},")?;
        }
        writeln!(f, "  ]")?;
        writeln!(f, "  bad_set: [")?;
        for entry in self.bad_set.iter() {
            writeln!(f, "    {entry},")?;
        }
        writeln!(f, "  ]")?;
        writeln!(f, "  wonky_set: [")?;
        for entry in self.wonky_set.iter() {
            writeln!(f, "    {entry},")?;
        }
        writeln!(f, "  ]")?;
        writeln!(f, "  punish_set: [")?;
        for entry in self.punish_set.iter() {
            writeln!(f, "    {},", entry.0)?;
        }
        writeln!(f, "  ]")?;
        write!(f, "}}")
    }
}

// The report hash sets take no duplicate check, since the GP keeps new verdicts disjoint from `ψ_G`, `ψ_B` and `ψ_W`.
impl DisputesState {
    pub fn get_punish_set(&self) -> &Vec<Ed25519PubKey> {
        &self.punish_set
    }

    pub fn sort_extend_good_set(&mut self, good_set: Vec<WorkReportHash>) {
        self.good_set.extend(good_set);
        self.good_set.sort()
    }

    pub fn sort_extend_bad_set(&mut self, bad_set: Vec<WorkReportHash>) {
        self.bad_set.extend(bad_set);
        self.bad_set.sort()
    }

    pub fn sort_extend_wonky_set(&mut self, wonky_set: Vec<WorkReportHash>) {
        self.wonky_set.extend(wonky_set);
        self.wonky_set.sort()
    }

    /// Adds the new offender keys to `ψ_O` as a set union, kept sorted.
    ///
    /// A key reported as both a culprit and a fault in one block appears twice in the offenders marker `H_O` but once in `ψ'_O`.
    pub fn sort_extend_punish_set(&mut self, punish_set: Vec<Ed25519PubKey>) {
        self.punish_set.extend(punish_set);
        self.punish_set.sort();
        self.punish_set.dedup();
    }

    pub fn get_all_report_hashes(&self) -> Vec<WorkReportHash> {
        self.good_set
            .iter()
            .chain(&self.bad_set)
            .chain(&self.wonky_set)
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fr_common::ByteArray;
    use std::error::Error;

    fn ed25519_key(byte: u8) -> Ed25519PubKey {
        Ed25519PubKey(ByteArray([byte; 32]))
    }

    #[test]
    fn test_sort_extend_punish_set_with_culprit_also_fault() -> Result<(), Box<dyn Error>> {
        let mut disputes = DisputesState {
            punish_set: vec![ed25519_key(2)],
            ..Default::default()
        };

        // Offenders marker `H_O` of culprit key 3 followed by fault keys 1 and 3
        let offenders_marker = vec![ed25519_key(3), ed25519_key(1), ed25519_key(3)];
        disputes.sort_extend_punish_set(offenders_marker);

        assert_eq!(
            disputes.punish_set,
            vec![ed25519_key(1), ed25519_key(2), ed25519_key(3)]
        );
        Ok(())
    }
}
