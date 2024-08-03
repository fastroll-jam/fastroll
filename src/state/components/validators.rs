use crate::{
    codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput},
    common::VALIDATOR_COUNT,
    impl_jam_codec_for_newtype,
    state::components::{safrole::SafroleState, timeslot::Timeslot},
    transition::{Transition, TransitionError},
};
use std::fmt::{Display, Formatter};

pub type ValidatorSet = [ValidatorKey; VALIDATOR_COUNT];
/// Represents a validator key, composed of 4 distinct components:
/// - Bandersnatch public key (32 bytes)
/// - Ed25519 public key (32 bytes)
/// - BLS public key (144 bytes)
/// - Metadata (128 bytes)
///
/// The total size of a ValidatorKey is 336 bytes, with each component
/// stored as a fixed-size byte array.
///
/// The final ValidatorKey type is a simple concatenation of each component.
#[derive(Copy, Clone, Debug)]
pub struct ValidatorKey {
    pub bandersnatch_key: [u8; 32],
    pub ed25519_key: [u8; 32],
    pub bls_key: [u8; 144],
    pub metadata: [u8; 128],
}

impl Display for ValidatorKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "Bandersnatch key: {}",
            hex::encode(self.bandersnatch_key)
        )?;
        writeln!(f, "Ed25519 key: {}", hex::encode(self.ed25519_key))?;
        writeln!(f, "BLS key: {}", hex::encode(self.bls_key))?;
        write!(f, "Metadata: {}", hex::encode(self.metadata))
    }
}

impl ValidatorKey {
    pub fn to_bytes(&self) -> [u8; 336] {
        let mut result = [0u8; 336];

        result[0..32].copy_from_slice(&self.bandersnatch_key);
        result[32..64].copy_from_slice(&self.ed25519_key);
        result[64..208].copy_from_slice(&self.bls_key);
        result[208..336].copy_from_slice(&self.metadata);

        result
    }

    fn to_json_like(&self, indent: usize) -> String {
        let spaces = " ".repeat(indent);
        format!(
            "{s}\"bandersnatch_key\": \"{}\",\n{s}\"ed25519_key\": \"{}\",\n{s}\"bls_key\": \"{}\",\n{s}\"metadata\": \"{}\"",
            hex::encode(self.bandersnatch_key),
            hex::encode(self.ed25519_key),
            hex::encode(self.bls_key),
            hex::encode(self.metadata),
            s = spaces
        )
    }
}

impl Default for ValidatorKey {
    fn default() -> Self {
        ValidatorKey {
            bandersnatch_key: [0u8; 32],
            ed25519_key: [0u8; 32],
            bls_key: [0u8; 144],
            metadata: [0u8; 128],
        }
    }
}

impl JamEncode for ValidatorKey {
    fn size_hint(&self) -> usize {
        self.bandersnatch_key.size_hint()
            + self.ed25519_key.size_hint()
            + self.bls_key.size_hint()
            + self.metadata.size_hint()
    }

    fn encode_to<T: JamOutput>(&self, dest: &mut T) -> Result<(), JamCodecError> {
        self.bandersnatch_key.encode_to(dest)?;
        self.ed25519_key.encode_to(dest)?;
        self.bls_key.encode_to(dest)?;
        self.metadata.encode_to(dest)?;
        Ok(())
    }
}

impl JamDecode for ValidatorKey {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError>
    where
        Self: Sized,
    {
        Ok(Self {
            bandersnatch_key: JamDecode::decode(input)?,
            ed25519_key: JamDecode::decode(input)?,
            bls_key: JamDecode::decode(input)?,
            metadata: JamDecode::decode(input)?,
        })
    }
}

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

pub struct StagingValidatorSetContext {
    pub timeslot: Timeslot,
}

impl Transition for StagingValidatorSet {
    type Context = StagingValidatorSetContext;

    fn to_next(&mut self, ctx: &Self::Context) -> Result<(), TransitionError>
    where
        Self: Sized,
    {
        // TODO: implement
        // This state is transitioned by the rule specified in a privileged service
        Ok(())
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

pub struct ActiveValidatorSetContext {
    pub timeslot: Timeslot,
    pub current_pending_validator_set: ValidatorSet, // from the Safrole state
}

impl Transition for ActiveValidatorSet {
    type Context = ActiveValidatorSetContext;
    fn to_next(&mut self, ctx: &Self::Context) -> Result<(), TransitionError>
    where
        Self: Sized,
    {
        if ctx.timeslot.is_new_epoch() {
            self.0 = ctx.current_pending_validator_set
        }
        Ok(())
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

pub struct PastValidatorSetContext {
    pub timeslot: Timeslot,
    pub current_active_set: ActiveValidatorSet,
}

impl Transition for PastValidatorSet {
    type Context = PastValidatorSetContext;
    fn to_next(&mut self, ctx: &Self::Context) -> Result<(), TransitionError>
    where
        Self: Sized,
    {
        if ctx.timeslot.is_new_epoch() {
            self.0 = ctx.current_active_set.0;
        }
        Ok(())
    }
}
