use std::{
    error::Error,
    fmt::{Display, Formatter},
};

#[derive(Debug)]
pub enum TransitionError {}

impl Display for TransitionError {
    fn fmt(&self, _f: &mut Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

impl Error for TransitionError {}

struct TransitionContext {}

pub trait Transition {
    fn next(&mut self, context: &TransitionContext) -> Result<Self, TransitionError>
    where
        Self: Sized;
}
