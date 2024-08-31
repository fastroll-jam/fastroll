use jam_codec::{
    impl_jam_codec_for_newtype, JamCodecError, JamDecode, JamEncode, JamInput, JamOutput,
};
use jam_common::ValidatorSet;
use std::fmt::{Display, Formatter};

/// Represents a ValidatorSet that will become active in a future epoch.
///
/// At the beginning of each epoch, this set is loaded into the Safrole state `gamma_k`
/// as the pending validator set. It will become the active set in the subsequent epoch.
///
/// This is denoted by the Greek letter `iota` in the Graypaper.
#[derive(Copy, Clone)]
pub struct StagingValidatorSet(pub ValidatorSet);
impl_jam_codec_for_newtype!(StagingValidatorSet, ValidatorSet);

impl Display for StagingValidatorSet {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{{")?;
        writeln!(f, "  \"StagingValidatorSet\": {{")?;
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

/// Represents a ValidatorSet that is active in the current epoch and determines the authorized
/// block authors of the current epoch.
///
/// This is denoted by the Greek letter `kappa` in the Graypaper.
#[derive(Copy, Clone)]
pub struct ActiveValidatorSet(pub ValidatorSet);
impl_jam_codec_for_newtype!(ActiveValidatorSet, ValidatorSet);

impl Display for ActiveValidatorSet {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{{")?;
        writeln!(f, "  \"ActiveValidatorSet\": {{")?;
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
#[derive(Copy, Clone)]
pub struct PastValidatorSet(pub ValidatorSet);
impl_jam_codec_for_newtype!(PastValidatorSet, ValidatorSet);

impl Display for PastValidatorSet {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{{")?;
        writeln!(f, "  \"PastValidatorSet\": {{")?;
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
