use crate::constants::PAGE_SIZE;
use std::{collections::HashMap, fmt::Display, ops::Range};
use thiserror::Error;

pub type MemAddress = u32;

#[derive(Debug, Error)]
pub enum MemoryError {
    #[error("Memory address out of range: {0}")]
    OutOfRange(MemAddress),
    #[error("Invalid page index: {0}")]
    InvalidPageIndex(usize),
    #[error("Page not initialized: {0}")]
    PageNotInitialized(usize),
    #[error("Memory access violation: (address: {0}, allowed access: {1})")]
    AccessViolation(MemAddress, AccessType),
}

/// Memory Cell Access Types
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub enum AccessType {
    #[default]
    Inaccessible,
    ReadOnly,
    ReadWrite,
}

impl Display for AccessType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let variant_name = match self {
            AccessType::Inaccessible => "Inaccessible",
            AccessType::ReadOnly => "ReadOnly",
            AccessType::ReadWrite => "ReadWrite",
        };
        write!(f, "{}", variant_name)
    }
}

pub fn mem_address(page_index: usize, offset: usize) -> MemAddress {
    (page_index * PAGE_SIZE + offset) as MemAddress
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct MemoryPage {
    index: usize,
    data: Vec<u8>, // length: PAGE_SIZE
    access: AccessType,
}

impl MemoryPage {
    pub fn new(index: usize, access: AccessType) -> Self {
        Self {
            index,
            data: vec![0; PAGE_SIZE],
            access,
        }
    }

    pub fn set_access(&mut self, access: AccessType) {
        self.access = access;
    }

    pub fn read_byte(&self, offset: usize) -> Result<u8, MemoryError> {
        if offset >= self.data.len() {
            return Err(MemoryError::OutOfRange(mem_address(self.index, offset)));
        }

        match self.access {
            AccessType::ReadOnly | AccessType::ReadWrite => Ok(self.data[offset]),
            AccessType::Inaccessible => Err(MemoryError::AccessViolation(
                mem_address(self.index, offset),
                self.access,
            )),
        }
    }

    pub fn write_byte(&mut self, offset: usize, byte: u8) -> Result<(), MemoryError> {
        if offset >= self.data.len() {
            return Err(MemoryError::OutOfRange(mem_address(self.index, offset)));
        }

        if self.access != AccessType::ReadWrite {
            return Err(MemoryError::AccessViolation(
                mem_address(self.index, offset),
                self.access,
            ));
        }

        self.data[offset] = byte;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Memory {
    pages: HashMap<usize, MemoryPage>, // (page index, page)
    page_size: usize,
    total_pages: usize,
    pub heap_start: MemAddress,
}

impl Default for Memory {
    fn default() -> Self {
        let pages = (0..PAGE_SIZE)
            .map(|index| (index, MemoryPage::default()))
            .collect();

        Self {
            pages,
            page_size: PAGE_SIZE,
            total_pages: 0,
            heap_start: 0,
        }
    }
}

impl Memory {
    pub fn new(size: usize, page_size: usize) -> Self {
        let total_pages = size.div_ceil(page_size);

        Self {
            pages: HashMap::new(),
            page_size,
            total_pages,
            heap_start: 0,
        }
    }

    /// Validates if the given page index is within the valid range.
    fn validate_page_index(&self, page_index: usize) -> Result<(), MemoryError> {
        if page_index >= self.total_pages {
            Err(MemoryError::InvalidPageIndex(page_index))
        } else {
            Ok(())
        }
    }

    fn get_page_and_offset(&self, address: MemAddress) -> Result<(usize, usize), MemoryError> {
        let page_index = (address as usize) / self.page_size;
        let offset = (address as usize) % self.page_size;
        Ok((page_index, offset))
    }

    fn get_page(&self, page_index: usize) -> Result<&MemoryPage, MemoryError> {
        self.validate_page_index(page_index)?;
        self.pages
            .get(&page_index)
            .ok_or(MemoryError::PageNotInitialized(page_index))
    }

    fn get_page_mut(&mut self, page_index: usize) -> Result<&mut MemoryPage, MemoryError> {
        self.validate_page_index(page_index)?;
        self.pages
            .get_mut(&page_index)
            .ok_or(MemoryError::PageNotInitialized(page_index))
    }

    /// Initializes and sets the access type for the memory page at the given index
    fn set_page_access(
        &mut self,
        page_index: usize,
        access: AccessType,
    ) -> Result<(), MemoryError> {
        self.validate_page_index(page_index)?;

        // Initialize the page if needed
        let page = self
            .pages
            .entry(page_index)
            .or_insert(MemoryPage::new(page_index, access));
        page.set_access(access);
        Ok(())
    }

    /// Initializes and sets the access type for the memory pages for the given range
    pub fn set_page_range_access(
        &mut self,
        page_range: Range<usize>,
        access: AccessType,
    ) -> Result<(), MemoryError> {
        for page_index in page_range {
            self.set_page_access(page_index, access)?;
        }
        Ok(())
    }

    /// Initializes and sets the access type for the memory pages for the given address range
    pub fn set_address_range_access(
        &mut self,
        address_range: Range<MemAddress>,
        access: AccessType,
    ) -> Result<(), MemoryError> {
        let (start_page_index, _) = self.get_page_and_offset(address_range.start)?;
        let (end_page_index, _) = self.get_page_and_offset(address_range.end)?;

        self.set_page_range_access(start_page_index..end_page_index, access)?;
        Ok(())
    }

    /// Check if a memory page is readable
    fn is_page_readable(&self, page_index: usize) -> Result<bool, MemoryError> {
        self.validate_page_index(page_index)?;
        let page = self.get_page(page_index)?;

        Ok(page.access == AccessType::ReadOnly || page.access == AccessType::ReadWrite)
    }

    /// Check if a memory cell at the given address is in a readable page
    #[allow(dead_code)]
    fn is_address_readable(&self, address: MemAddress) -> Result<bool, MemoryError> {
        let (page_index, _) = self.get_page_and_offset(address)?;
        self.is_page_readable(page_index)
    }

    /// Check if a range of memory pages is readable
    pub fn is_page_range_readable(&self, page_range: Range<usize>) -> Result<bool, MemoryError> {
        for page_index in page_range {
            if !self.is_page_readable(page_index)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Check if a range of memory cells is readable
    pub fn is_address_range_readable(
        &self,
        start: MemAddress,
        length: usize,
    ) -> Result<bool, MemoryError> {
        let end = start + length as MemAddress;
        let (start_page_index, _) = self.get_page_and_offset(start)?;
        let (end_page_index, _) = self.get_page_and_offset(end)?;

        self.is_page_range_readable(start_page_index..end_page_index)?;

        Ok(true)
    }

    /// Check if a memory page is writable
    fn is_page_writable(&self, page_index: usize) -> Result<bool, MemoryError> {
        self.validate_page_index(page_index)?;
        let page = self.get_page(page_index)?;
        Ok(page.access == AccessType::ReadWrite)
    }

    /// Check if a memory cell at the given address is in a writable page
    #[allow(dead_code)]
    fn is_address_writable(&self, address: MemAddress) -> Result<bool, MemoryError> {
        let (page_index, _) = self.get_page_and_offset(address)?;
        self.is_page_writable(page_index)
    }

    /// Check if a range of memory pages is writable
    pub fn is_page_range_writable(&self, page_range: Range<usize>) -> Result<bool, MemoryError> {
        for page_index in page_range {
            if !self.is_page_writable(page_index)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Check if a range of memory cells is writable
    pub fn is_address_range_writable(
        &self,
        start: MemAddress,
        length: usize,
    ) -> Result<bool, MemoryError> {
        let end = start + length as MemAddress;
        let (start_page_index, _) = self.get_page_and_offset(start)?;
        let (end_page_index, _) = self.get_page_and_offset(end)?;

        self.is_page_range_writable(start_page_index..end_page_index)?;
        Ok(true)
    }

    /// Read a byte from a memory cell at the given address
    pub fn read_byte(&self, address: MemAddress) -> Result<u8, MemoryError> {
        let (page_index, offset) = self.get_page_and_offset(address)?;
        let page = self.get_page(page_index)?;
        page.read_byte(offset)
    }

    /// Read a specified number of bytes from memory starting at the given address
    pub fn read_bytes(&self, address: MemAddress, length: usize) -> Result<Vec<u8>, MemoryError> {
        (0..length)
            .map(|i| self.read_byte(address + i as MemAddress))
            .collect()
    }

    /// Write a byte to a memory cell at the given address
    pub fn write_byte(&mut self, address: MemAddress, value: u8) -> Result<(), MemoryError> {
        let (page_index, offset) = self.get_page_and_offset(address)?;
        let page = self.get_page_mut(page_index)?;
        page.write_byte(offset, value)
    }

    /// Write a slice of bytes to memory starting at the given address
    pub fn write_bytes(
        &mut self,
        start_address: MemAddress,
        bytes: &[u8],
    ) -> Result<(), MemoryError> {
        for (i, &byte) in bytes.iter().enumerate() {
            self.write_byte(start_address + i as MemAddress, byte)?;
        }
        Ok(())
    }

    /// Get the break address (end of the heap) of current memory layout
    pub fn get_break(&self, _requested_size: usize) -> Result<MemAddress, MemoryError> {
        todo!()
    }

    /// Expand the heap area for the `sbrk` instruction
    pub fn expand_heap(&mut self, _start: MemAddress, _size: usize) -> Result<(), MemoryError> {
        todo!()
    }
}
