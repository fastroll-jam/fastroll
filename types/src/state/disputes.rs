use rjam_codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput};
use rjam_common::{Ed25519PubKey, Hash32};

// TODO: these sets should always be sorted
#[derive(JamEncode, JamDecode)]
pub struct DisputesState {
    good_set: Vec<Hash32>,          // psi_g; recording hash of correct work-reports
    bad_set: Vec<Hash32>,           // psi_b; recording hash of incorrect work-reports
    wonky_set: Vec<Hash32>,         // psi_w; recording hash of work-reports that cannot be judged
    punish_set: Vec<Ed25519PubKey>, // psi_p; recording Ed25519 public keys of validators which have misjudged.
}
