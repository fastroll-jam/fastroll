use rjam_codec::{
    impl_jam_codec_for_newtype, JamCodecError, JamDecode, JamEncode, JamInput, JamOutput,
};
use rjam_common::{Ed25519PubKey, ValidatorKey, ValidatorSet, VALIDATOR_COUNT};
use std::fmt::{Display, Formatter};

/// Represents a ValidatorSet that will become active in a future epoch.
///
/// At the beginning of each epoch, this set is loaded into the Safrole state `gamma_k`
/// as the pending validator set. It will become the active set in the subsequent epoch.
///
/// This is denoted by the Greek letter `iota` in the Graypaper.
#[derive(Clone)]
pub struct StagingSet(pub ValidatorSet);
impl_jam_codec_for_newtype!(StagingSet, ValidatorSet);

impl Display for StagingSet {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{{")?;
        writeln!(f, "  \"StagingSet\": {{")?;
        for (i, validator) in self.0.iter().enumerate() {
            writeln!(f, "    \"Validator_{}\": {{", i)?;
            write!(f, "{}", validator.to_json_like(6))?;
            if i < self.0.len() - 1 {
                writeln!(f, "    }},")?;
            } else {
                writeln!(f, "    }}")?;
            }
        }
        writeln!(f, "  }}")?;
        write!(f, "}}")
    }
}

impl Default for StagingSet {
    fn default() -> Self {
        Self([ValidatorKey::default(); VALIDATOR_COUNT])
    }
}

impl StagingSet {
    pub fn nullify_punished_validators(&mut self, punish_set: &Vec<Ed25519PubKey>) {
        for validator in self.0.iter_mut() {
            if punish_set.contains(&validator.ed25519_key) {
                *validator = ValidatorKey::default();
            }
        }
    }
}

/// Represents a ValidatorSet that is active in the current epoch and determines the authorized
/// block authors of the current epoch.
///
/// This is denoted by the Greek letter `kappa` in the Graypaper.
#[derive(Clone)]
pub struct ActiveSet(pub ValidatorSet);
impl_jam_codec_for_newtype!(ActiveSet, ValidatorSet);

impl Display for ActiveSet {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{{")?;
        writeln!(f, "  \"ActiveSet\": {{")?;
        for (i, validator) in self.0.iter().enumerate() {
            writeln!(f, "    \"Validator_{}\": {{", i)?;
            write!(f, "{}", validator.to_json_like(6))?;
            if i < self.0.len() - 1 {
                writeln!(f, "    }},")?;
            } else {
                writeln!(f, "    }}")?;
            }
        }
        writeln!(f, "  }}")?;
        write!(f, "}}")
    }
}

/// Represents the ValidatorSet that was active in the previous epoch.
/// This is denoted by the Greek letter `lambda` in the Graypaper.
#[derive(Clone)]
pub struct PastSet(pub ValidatorSet);
impl_jam_codec_for_newtype!(PastSet, ValidatorSet);

impl Display for PastSet {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{{")?;
        writeln!(f, "  \"PastSet\": {{")?;
        for (i, validator) in self.0.iter().enumerate() {
            writeln!(f, "    \"Validator_{}\": {{", i)?;
            write!(f, "{}", validator.to_json_like(6))?;
            if i < self.0.len() - 1 {
                writeln!(f, "    }},")?;
            } else {
                writeln!(f, "    }}")?;
            }
        }
        writeln!(f, "  }}")?;
        write!(f, "}}")
    }
}
