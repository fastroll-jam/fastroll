use thiserror::Error;

#[derive(Debug, Error)]
pub enum LimitedVecError {
    #[error("LimitedVec is full")]
    LimitedVecFull,
    #[error("Invalid Vec size")]
    InvalidVecSize,
}

#[derive(Debug, Clone)]
pub struct LimitedVec<T, const MAX_SIZE: usize> {
    inner: Vec<T>,
}

impl<T, const MAX_SIZE: usize> Default for LimitedVec<T, MAX_SIZE> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T, const MAX_SIZE: usize> LimitedVec<T, MAX_SIZE> {
    pub fn new() -> Self {
        Self {
            inner: Vec::with_capacity(MAX_SIZE),
        }
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn as_slice(&self) -> &[T] {
        self.inner.as_slice()
    }

    pub fn try_push(&mut self, item: T) -> Result<(), LimitedVecError> {
        if self.inner.len() >= MAX_SIZE {
            return Err(LimitedVecError::LimitedVecFull);
        }
        self.inner.push(item);
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct FixedVec<T, const SIZE: usize> {
    inner: Vec<T>,
}

impl<T, const SIZE: usize> FixedVec<T, SIZE> {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            inner: Vec::with_capacity(SIZE),
        }
    }

    pub fn as_slice(&self) -> &[T] {
        self.inner.as_slice()
    }

    pub fn try_from_vec(vec: Vec<T>) -> Result<Self, LimitedVecError> {
        if vec.len() != SIZE {
            return Err(LimitedVecError::InvalidVecSize);
        }
        Ok(Self { inner: vec })
    }
}
