use std::ops::{Index, IndexMut};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LimitedVecError {
    #[error("LimitedVec is full")]
    LimitedVecFull,
    #[error("Invalid Vec size")]
    InvalidVecSize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct LimitedVec<T, const MAX_SIZE: usize> {
    inner: Vec<T>,
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

    pub fn iter(&self) -> std::slice::Iter<'_, T> {
        self.inner.iter()
    }

    pub fn iter_mut(&mut self) -> std::slice::IterMut<'_, T> {
        self.inner.iter_mut()
    }

    pub fn try_from_vec(vec: Vec<T>) -> Result<Self, LimitedVecError> {
        if vec.len() > MAX_SIZE {
            return Err(LimitedVecError::InvalidVecSize);
        }
        Ok(Self { inner: vec })
    }

    pub fn try_push(&mut self, item: T) -> Result<(), LimitedVecError> {
        if self.inner.len() >= MAX_SIZE {
            return Err(LimitedVecError::LimitedVecFull);
        }
        self.inner.push(item);
        Ok(())
    }

    pub fn shift_push(&mut self, item: T) -> Option<T> {
        if self.inner.len() == MAX_SIZE {
            let oldest = self.inner.remove(0);
            self.inner.push(item);
            Some(oldest)
        } else {
            self.inner.push(item);
            None
        }
    }

    pub fn remove(&mut self, index: usize) -> T {
        self.inner.remove(index)
    }
}

impl<T, const MAX_SIZE: usize> AsRef<[T]> for LimitedVec<T, MAX_SIZE> {
    fn as_ref(&self) -> &[T] {
        self.inner.as_ref()
    }
}

impl<T, const MAX_SIZE: usize> AsMut<[T]> for LimitedVec<T, MAX_SIZE> {
    fn as_mut(&mut self) -> &mut [T] {
        self.inner.as_mut()
    }
}

impl<T, const MAX_SIZE: usize> IntoIterator for LimitedVec<T, MAX_SIZE> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<Self::Item>;
    fn into_iter(self) -> Self::IntoIter {
        self.inner.into_iter()
    }
}

impl<'a, T, const MAX_SIZE: usize> IntoIterator for &'a LimitedVec<T, MAX_SIZE> {
    type Item = &'a T;
    type IntoIter = std::slice::Iter<'a, T>;
    fn into_iter(self) -> Self::IntoIter {
        self.inner.iter()
    }
}

impl<'a, T, const MAX_SIZE: usize> IntoIterator for &'a mut LimitedVec<T, MAX_SIZE> {
    type Item = &'a mut T;
    type IntoIter = std::slice::IterMut<'a, T>;
    fn into_iter(self) -> Self::IntoIter {
        self.inner.iter_mut()
    }
}

impl<T, const MAX_SIZE: usize> Index<usize> for LimitedVec<T, MAX_SIZE> {
    type Output = T;

    fn index(&self, index: usize) -> &Self::Output {
        &self.inner[index]
    }
}

impl<T, const MAX_SIZE: usize> IndexMut<usize> for LimitedVec<T, MAX_SIZE> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.inner[index]
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FixedVec<T, const SIZE: usize>
where
    T: Default + Clone,
{
    inner: Vec<T>,
}

impl<T, const SIZE: usize> Default for FixedVec<T, SIZE>
where
    T: Default + Clone,
{
    fn default() -> Self {
        Self::try_from_vec(vec![T::default(); SIZE]).expect("size checked")
    }
}

impl<T, const SIZE: usize> FixedVec<T, SIZE>
where
    T: Default + Clone,
{
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            inner: Vec::with_capacity(SIZE),
        }
    }

    pub fn as_slice(&self) -> &[T] {
        self.inner.as_slice()
    }

    pub fn iter(&self) -> std::slice::Iter<T> {
        self.inner.iter()
    }

    pub fn iter_mut(&mut self) -> std::slice::IterMut<'_, T> {
        self.inner.iter_mut()
    }

    pub fn try_from_vec(vec: Vec<T>) -> Result<Self, LimitedVecError> {
        if vec.len() != SIZE {
            return Err(LimitedVecError::InvalidVecSize);
        }
        Ok(Self { inner: vec })
    }
}

impl<T, const SIZE: usize> AsRef<[T]> for FixedVec<T, SIZE>
where
    T: Default + Clone,
{
    fn as_ref(&self) -> &[T] {
        self.inner.as_ref()
    }
}

impl<T, const SIZE: usize> AsMut<[T]> for FixedVec<T, SIZE>
where
    T: Default + Clone,
{
    fn as_mut(&mut self) -> &mut [T] {
        self.inner.as_mut()
    }
}

impl<T, const SIZE: usize> IntoIterator for FixedVec<T, SIZE>
where
    T: Default + Clone,
{
    type Item = T;
    type IntoIter = std::vec::IntoIter<Self::Item>;
    fn into_iter(self) -> Self::IntoIter {
        self.inner.into_iter()
    }
}

impl<'a, T, const SIZE: usize> IntoIterator for &'a FixedVec<T, SIZE>
where
    T: Default + Clone,
{
    type Item = &'a T;
    type IntoIter = std::slice::Iter<'a, T>;
    fn into_iter(self) -> Self::IntoIter {
        self.inner.iter()
    }
}

impl<'a, T, const SIZE: usize> IntoIterator for &'a mut FixedVec<T, SIZE>
where
    T: Default + Clone,
{
    type Item = &'a mut T;
    type IntoIter = std::slice::IterMut<'a, T>;
    fn into_iter(self) -> Self::IntoIter {
        self.inner.iter_mut()
    }
}

impl<T, const SIZE: usize> Index<usize> for FixedVec<T, SIZE>
where
    T: Default + Clone,
{
    type Output = T;

    fn index(&self, index: usize) -> &Self::Output {
        &self.inner[index]
    }
}

impl<T, const SIZE: usize> IndexMut<usize> for FixedVec<T, SIZE>
where
    T: Default + Clone,
{
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.inner[index]
    }
}
