use fr_pvm_types::{common::MemAddress, constants::PAGE_SIZE};
use std::{collections::HashMap, fmt::Display, ops::Range};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MemoryError {
    #[error("Memory address out of range: {0}")]
    OutOfRange(MemAddress),
    #[error("Invalid page index: {0}")]
    InvalidPageIndex(usize),
    #[error("Page not initialized: {0}")]
    PageNotInitialized(usize),
    #[error("Memory access violation: (address: {0})")]
    AccessViolation(MemAddress),
    #[error("Heap stack collision occurred during SBRK. Break: {0}, Requested Size: {1}, Stack Start: {2}")]
    SbrkHeapStackCollision(MemAddress, usize, MemAddress),
    #[error("Tried to SBRK to already allocated memory. Heap End: {0}, Requested Size: {1}")]
    InvalidSbrk(MemAddress, usize),
}

/// Memory Cell Access Types.
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
        write!(f, "{variant_name}")
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

    pub fn start_address(&self) -> MemAddress {
        (self.index * PAGE_SIZE) as MemAddress
    }

    pub fn read_byte(&self, offset: usize) -> Result<u8, MemoryError> {
        if offset >= self.data.len() {
            return Err(MemoryError::OutOfRange(mem_address(self.index, offset)));
        }

        match self.access {
            AccessType::ReadOnly | AccessType::ReadWrite => Ok(self.data[offset]),
            AccessType::Inaccessible => Err(MemoryError::AccessViolation(mem_address(
                self.index, offset,
            ))),
        }
    }

    pub fn write_byte(&mut self, offset: usize, byte: u8) -> Result<(), MemoryError> {
        if offset >= self.data.len() {
            return Err(MemoryError::OutOfRange(mem_address(self.index, offset)));
        }

        if self.access != AccessType::ReadWrite {
            return Err(MemoryError::AccessViolation(mem_address(
                self.index, offset,
            )));
        }

        self.data[offset] = byte;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Memory {
    pages: HashMap<usize, MemoryPage>,
    page_size: usize,
    total_pages: usize,
    pub heap_start: MemAddress,
    pub heap_end: MemAddress,
    pub stack_start: MemAddress,
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
            heap_end: 0,
            stack_start: 0,
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
            heap_end: 0,
            stack_start: 0,
        }
    }

    /// Validates if the given page index is within the valid range.
    fn validate_page_index_bound(&self, page_index: usize) -> Result<(), MemoryError> {
        if page_index >= self.total_pages {
            Err(MemoryError::InvalidPageIndex(page_index))
        } else {
            Ok(())
        }
    }

    pub fn get_page_and_offset(&self, address: MemAddress) -> (usize, usize) {
        let page_index = (address as usize) / self.page_size;
        let offset = (address as usize) % self.page_size;
        (page_index, offset)
    }

    fn get_page(&self, page_index: usize) -> Result<Option<&MemoryPage>, MemoryError> {
        self.validate_page_index_bound(page_index)?;
        Ok(self.pages.get(&page_index))
    }

    fn get_page_mut(&mut self, page_index: usize) -> Result<Option<&mut MemoryPage>, MemoryError> {
        self.validate_page_index_bound(page_index)?;
        Ok(self.pages.get_mut(&page_index))
    }

    /// Initializes and sets the access type for the memory page at the given index.
    fn set_page_access(
        &mut self,
        page_index: usize,
        access: AccessType,
    ) -> Result<(), MemoryError> {
        self.validate_page_index_bound(page_index)?;

        // Initialize the page if needed
        let page = self
            .pages
            .entry(page_index)
            .or_insert(MemoryPage::new(page_index, access));
        page.set_access(access);
        Ok(())
    }

    /// Initializes and sets the access type for the memory pages for the given range.
    pub fn set_page_range_access(
        &mut self,
        page_range: Range<usize>,
        access: AccessType,
    ) -> Result<(), MemoryError> {
        if page_range.is_empty() {
            return Ok(());
        }
        for page_index in page_range {
            self.set_page_access(page_index, access)?;
        }
        Ok(())
    }

    /// Initializes and sets the access type for the memory pages for the given address range.
    pub fn set_address_range_access(
        &mut self,
        address_range: Range<MemAddress>,
        access: AccessType,
    ) -> Result<(), MemoryError> {
        if address_range.is_empty() {
            return Ok(());
        }
        let (start_page_index, _) = self.get_page_and_offset(address_range.start);
        let (end_page_index, _) = self.get_page_and_offset(address_range.end - 1);

        self.set_page_range_access(start_page_index..end_page_index + 1, access)?;
        Ok(())
    }

    /// Check if a memory page is readable.
    fn is_page_readable(&self, page_index: usize) -> Result<bool, MemoryError> {
        self.validate_page_index_bound(page_index)?;
        let page = match self.get_page(page_index) {
            Ok(Some(page)) => page,
            _ => return Ok(false), // Not found entry implies `Inaccessible`
        };
        Ok(page.access == AccessType::ReadOnly || page.access == AccessType::ReadWrite)
    }

    /// Check if a memory cell at the given address is in a readable page.
    #[allow(dead_code)]
    fn is_address_readable(&self, address: MemAddress) -> Result<bool, MemoryError> {
        let (page_index, _) = self.get_page_and_offset(address);
        self.is_page_readable(page_index)
    }

    /// Returns the lowest memory address that is not readable, if found any.
    /// If all pages in the range is readable, returns `None`.
    fn check_not_readable_in_range(
        &self,
        page_range: Range<usize>,
    ) -> Result<Option<MemAddress>, MemoryError> {
        for page_index in page_range {
            if !self.is_page_readable(page_index)? {
                // The first address of the page
                return Ok(Some(mem_address(page_index, 0)));
            }
        }
        Ok(None)
    }

    /// Check if a range of memory pages is readable.
    pub fn is_page_range_readable(&self, page_range: Range<usize>) -> Result<bool, MemoryError> {
        if page_range.is_empty() {
            return Ok(false);
        }
        for page_index in page_range.clone() {
            if !self.is_page_readable(page_index)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Check if a range of memory cells is readable.
    pub fn is_address_range_readable(
        &self,
        start: MemAddress,
        length: usize,
    ) -> Result<bool, MemoryError> {
        if length == 0 {
            return Ok(false);
        }
        let (start_page, _) = self.get_page_and_offset(start);
        let (end_page, _) = self.get_page_and_offset(start + (length - 1) as MemAddress);
        self.is_page_range_readable(start_page..end_page + 1)
    }

    /// Check if a memory page is writable.
    fn is_page_writable(&self, page_index: usize) -> Result<bool, MemoryError> {
        self.validate_page_index_bound(page_index)?;
        let page = match self.get_page(page_index) {
            Ok(Some(page)) => page,
            _ => return Ok(false), // Not found entry implies `Inaccessible`
        };
        Ok(page.access == AccessType::ReadWrite)
    }

    /// Check if a memory cell at the given address is in a writable page.
    #[allow(dead_code)]
    fn is_address_writable(&self, address: MemAddress) -> Result<bool, MemoryError> {
        let (page_index, _) = self.get_page_and_offset(address);
        self.is_page_writable(page_index)
    }

    /// Returns the lowest memory address that is not writable, if found any.
    /// If all pages in the range is writable, returns `None`.
    fn check_not_writable_in_range(
        &self,
        page_range: Range<usize>,
    ) -> Result<Option<MemAddress>, MemoryError> {
        for page_index in page_range {
            if !self.is_page_writable(page_index)? {
                // The first address of the page
                return Ok(Some(mem_address(page_index, 0)));
            }
        }
        Ok(None)
    }

    /// Check if a range of memory pages is writable.
    pub fn is_page_range_writable(&self, page_range: Range<usize>) -> Result<bool, MemoryError> {
        if page_range.is_empty() {
            return Ok(false);
        }
        for page_index in page_range {
            if !self.is_page_writable(page_index)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Check if a range of memory cells is writable.
    pub fn is_address_range_writable(
        &self,
        start: MemAddress,
        length: usize,
    ) -> Result<bool, MemoryError> {
        if length == 0 {
            return Ok(false);
        }
        let (start_page, _) = self.get_page_and_offset(start);
        let (end_page, _) = self.get_page_and_offset(start + (length - 1) as MemAddress);

        self.is_page_range_writable(start_page..end_page + 1)
    }

    /// Read a byte from a memory cell at the given address.
    pub fn read_byte(&self, address: MemAddress) -> Result<u8, MemoryError> {
        let (page_index, offset) = self.get_page_and_offset(address);
        let page = self
            .get_page(page_index)?
            .ok_or(MemoryError::AccessViolation(mem_address(
                page_index, offset,
            )))?;
        page.read_byte(offset)
    }

    /// Read a specified number of bytes from memory starting at the given address.
    pub fn read_bytes(&self, address: MemAddress, length: usize) -> Result<Vec<u8>, MemoryError> {
        if length == 0 {
            return Ok(Vec::new());
        }

        let (start_page, _) = self.get_page_and_offset(address);
        let (end_page, _) = self.get_page_and_offset(address + (length - 1) as MemAddress);

        match self.check_not_readable_in_range(start_page..end_page + 1)? {
            None => (0..length)
                .map(|i| self.read_byte(address + i as MemAddress))
                .collect(),
            Some(not_readable_lowest) => Err(MemoryError::AccessViolation(not_readable_lowest)),
        }
    }

    /// Write a byte to a memory cell at the given address.
    pub fn write_byte(&mut self, address: MemAddress, value: u8) -> Result<(), MemoryError> {
        let (page_index, offset) = self.get_page_and_offset(address);
        let page = self
            .get_page_mut(page_index)?
            .ok_or(MemoryError::AccessViolation(mem_address(
                page_index, offset,
            )))?;
        page.write_byte(offset, value)
    }

    /// Write a slice of bytes to memory starting at the given address.
    pub fn write_bytes(
        &mut self,
        start_address: MemAddress,
        bytes: &[u8],
    ) -> Result<(), MemoryError> {
        if bytes.is_empty() {
            return Ok(());
        }

        let (start_page, _) = self.get_page_and_offset(start_address);
        let (end_page, _) =
            self.get_page_and_offset(start_address + (bytes.len() - 1) as MemAddress);

        match self.check_not_writable_in_range(start_page..end_page + 1)? {
            None => {
                // All pages in the rage are writable
                for (i, &byte) in bytes.iter().enumerate() {
                    self.write_byte(start_address + i as MemAddress, byte)?;
                }
                Ok(())
            }
            Some(not_writable_lowest) => Err(MemoryError::AccessViolation(not_writable_lowest)),
        }
    }

    /// Get the break address (end of the heap) of current memory layout.
    pub fn get_break(&self, expand_size: usize) -> Result<MemAddress, MemoryError> {
        let mut break_address = self.heap_end;
        loop {
            // FIXME: Current implementation is a workaround since address-level access control is limited
            if self.is_address_range_readable(break_address, expand_size)?
                && !self.is_address_range_writable(break_address, expand_size)?
            {
                break_address += 1;
            } else {
                break;
            }
        }
        Ok(break_address)
    }

    /// Expand the heap area for the `sbrk` instruction.
    pub fn expand_heap(&mut self, start: MemAddress, size: usize) -> Result<(), MemoryError> {
        let end = start + size as MemAddress;
        if self.heap_start != 0 && end >= self.stack_start {
            return Err(MemoryError::SbrkHeapStackCollision(
                start,
                size,
                self.stack_start,
            ));
        }
        self.set_address_range_access(start..end, AccessType::ReadWrite)?; // FIXME: address-level access control
        self.heap_end = end;
        Ok(())
    }
}
