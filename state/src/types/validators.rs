use crate::{
    impl_simple_state_component,
    state_utils::{SimpleStateComponent, StateComponent, StateEntryType, StateKeyConstant},
};
use fr_codec::prelude::*;
use fr_crypto::types::*;
use std::{
    array::from_fn,
    collections::HashSet,
    fmt::{Display, Formatter},
    ops::{Deref, DerefMut},
    slice::{Iter, IterMut},
};

pub trait ValidatorSet {
    type Iter<'a>: Iterator<Item = &'a ValidatorKey>
    where
        Self: 'a;

    type IterMut<'a>: Iterator<Item = &'a mut ValidatorKey>
    where
        Self: 'a;

    fn iter(&self) -> Self::Iter<'_>;

    fn iter_mut(&mut self) -> Self::IterMut<'_>;

    fn ed25519_keys_set(&self) -> HashSet<Ed25519PubKey> {
        self.iter()
            .map(|validator| validator.ed25519_key.clone())
            .collect()
    }

    fn ed25519_keys(&self) -> Vec<Ed25519PubKey> {
        self.iter()
            .map(|validator| validator.ed25519_key.clone())
            .collect()
    }

    fn nullify_punished_validators(&mut self, punish_set: &[Ed25519PubKey]) {
        for validator in self.iter_mut() {
            if punish_set.contains(&validator.ed25519_key) {
                *validator = ValidatorKey::default();
            }
        }
    }
}

impl<T> ValidatorSet for T
where
    T: AsRef<[ValidatorKey]> + AsMut<[ValidatorKey]>,
{
    type Iter<'a>
        = Iter<'a, ValidatorKey>
    where
        T: 'a;

    type IterMut<'a>
        = IterMut<'a, ValidatorKey>
    where
        Self: 'a;

    fn iter(&self) -> Self::Iter<'_> {
        self.as_ref().iter()
    }

    fn iter_mut(&mut self) -> Self::IterMut<'_> {
        self.as_mut().iter_mut()
    }
}

fn fmt_validator_set(
    f: &mut Formatter<'_>,
    name: &str,
    validators: &[ValidatorKey],
) -> std::fmt::Result {
    writeln!(f, "{{")?;
    writeln!(f, "\t\"{name}\": {{")?;
    for (i, validator) in validators.iter().enumerate() {
        writeln!(f, "\t\t\"Validator_{i}\": {{")?;
        write!(f, "{}", validator.clone().to_json_like(6))?;
        if i < validators.len() - 1 {
            writeln!(f, "\t\t}},")?;
        } else {
            writeln!(f, "\t\t}}")?;
        }
    }
    writeln!(f, "\t}}")?;
    write!(f, "}}")
}

/// A validator set that will become active in a future epoch.
///
/// At the beginning of each epoch, this set is loaded into the Safrole state `γ_k`
/// as the pending validator set. It will become the active set in the subsequent epoch.
///
/// Represents `ι` in the GP.
#[derive(Clone, Debug, PartialEq, Eq, JamEncode, JamDecode)]
pub struct StagingSet(pub ValidatorKeySet);
impl_simple_state_component!(StagingSet, StagingSet);

impl Deref for StagingSet {
    type Target = ValidatorKeySet;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for StagingSet {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Display for StagingSet {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        fmt_validator_set(f, "StagingSet", self.as_ref())
    }
}

impl Default for StagingSet {
    fn default() -> Self {
        let arr = from_fn(|_| ValidatorKey::default());
        Self(ValidatorKeySet(Box::new(arr)))
    }
}

/// A validator set that is active in the current epoch.
///
/// Represents `κ` of the GP.
#[derive(Clone, Debug, PartialEq, Eq, JamEncode, JamDecode)]
pub struct ActiveSet(pub ValidatorKeySet);
impl_simple_state_component!(ActiveSet, ActiveSet);

impl Deref for ActiveSet {
    type Target = ValidatorKeySet;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for ActiveSet {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Display for ActiveSet {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        fmt_validator_set(f, "ActiveSet", self.as_ref())
    }
}

impl Default for ActiveSet {
    fn default() -> Self {
        let arr = from_fn(|_| ValidatorKey::default());
        Self(ValidatorKeySet(Box::new(arr)))
    }
}

/// A validator set that was active in the previous epoch.
///
/// Represents `λ` of the GP.
#[derive(Clone, Debug, PartialEq, Eq, JamEncode, JamDecode)]
pub struct PastSet(pub ValidatorKeySet);
impl_simple_state_component!(PastSet, PastSet);

impl Deref for PastSet {
    type Target = ValidatorKeySet;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for PastSet {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Display for PastSet {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        fmt_validator_set(f, "PastSet", self.as_ref())
    }
}

impl Default for PastSet {
    fn default() -> Self {
        let arr = from_fn(|_| ValidatorKey::default());
        Self(ValidatorKeySet(Box::new(arr)))
    }
}
