use crate::{
    impl_simple_state_component,
    state_utils::{SimpleStateComponent, StateComponent, StateEntryType, StateKeyConstant},
};
use fr_codec::prelude::*;
use fr_common::Hash32;
use fr_crypto::types::*;

/// A record of historical dispute verdicts and their associated offenders set.
///
/// Represents `ψ` of the GP.
#[derive(Clone, Debug, Default, PartialEq, Eq, JamEncode, JamDecode)]
pub struct DisputesState {
    /// `ψ_g`: Hash of correct work-reports.
    pub good_set: Vec<Hash32>,
    /// `ψ_b`: Hash of incorrect work-reports.
    pub bad_set: Vec<Hash32>,
    /// `ψ_w`: Hash of work-reports that cannot be judged.
    pub wonky_set: Vec<Hash32>,
    /// `ψ_o`: Ed25519 public keys of validators who are offenders (culprits or faults).
    pub punish_set: Vec<Ed25519PubKey>,
}
impl_simple_state_component!(DisputesState, DisputesState);

// Note: No duplication check is conducted here.
impl DisputesState {
    pub fn get_punish_set(&self) -> &Vec<Ed25519PubKey> {
        &self.punish_set
    }

    pub fn sort_extend_good_set(&mut self, good_set: Vec<Hash32>) {
        self.good_set.extend(good_set);
        self.good_set.sort()
    }

    pub fn sort_extend_bad_set(&mut self, bad_set: Vec<Hash32>) {
        self.bad_set.extend(bad_set);
        self.bad_set.sort()
    }

    pub fn sort_extend_wonky_set(&mut self, wonky_set: Vec<Hash32>) {
        self.wonky_set.extend(wonky_set);
        self.wonky_set.sort()
    }

    pub fn sort_extend_punish_set(&mut self, punish_set: Vec<Ed25519PubKey>) {
        self.punish_set.extend(punish_set);
        self.punish_set.sort();
    }

    pub fn get_all_report_hashes(&self) -> Vec<Hash32> {
        let mut all_reports = vec![];
        all_reports.extend(self.good_set.clone());
        all_reports.extend(self.bad_set.clone());
        all_reports.extend(self.wonky_set.clone());

        all_reports
    }
}
