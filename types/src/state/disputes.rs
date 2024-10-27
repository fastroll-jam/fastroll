use rjam_codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput};
use rjam_common::{Ed25519PubKey, Hash32};
use std::collections::HashSet;

#[derive(Clone, Default, JamEncode, JamDecode)]
pub struct DisputesState {
    pub good_set: HashSet<Hash32>,  // psi_g; hash of correct work-reports
    pub bad_set: HashSet<Hash32>,   // psi_b; hash of incorrect work-reports
    pub wonky_set: HashSet<Hash32>, // psi_w; hash of work-reports that cannot be judged
    pub punish_set: HashSet<Ed25519PubKey>, // psi_o; Ed25519 public keys of validators which have misjudged.
}

impl DisputesState {
    pub fn get_punish_set(&self) -> &HashSet<Ed25519PubKey> {
        &self.punish_set
    }

    pub fn set_punish_set(&mut self, punish_set: HashSet<Ed25519PubKey>) {
        self.punish_set = punish_set;
    }

    pub fn get_all_report_hashes(&self) -> HashSet<Hash32> {
        self.good_set
            .union(&self.bad_set)
            .chain(self.wonky_set.iter())
            .cloned()
            .collect()
    }
}
