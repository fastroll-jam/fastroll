use crate::{
    impl_simple_state_component,
    state_utils::{SimpleStateComponent, StateComponent, StateEntryType, StateKeyConstant},
};
use rjam_codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput};
use rjam_common::{Ed25519PubKey, Hash32};

#[derive(Clone, Default, JamEncode, JamDecode)]
pub struct DisputesState {
    pub good_set: Vec<Hash32>,          // psi_g; hash of correct work-reports
    pub bad_set: Vec<Hash32>,           // psi_b; hash of incorrect work-reports
    pub wonky_set: Vec<Hash32>,         // psi_w; hash of work-reports that cannot be judged
    pub punish_set: Vec<Ed25519PubKey>, // psi_o; Ed25519 public keys of validators which have misjudged.
}
impl_simple_state_component!(DisputesState, DisputesState);

// Note: No duplication check is conducted here.
impl DisputesState {
    pub fn get_punish_set(&self) -> &Vec<Ed25519PubKey> {
        &self.punish_set
    }

    pub fn sort_extend_good_set(&mut self, good_set: Vec<Ed25519PubKey>) {
        self.good_set.extend(good_set);
        self.good_set.sort()
    }

    pub fn sort_extend_bad_set(&mut self, bad_set: Vec<Ed25519PubKey>) {
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
