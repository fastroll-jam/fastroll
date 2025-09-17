use fr_pvm_types::{
    common::MemAddress,
    constants::{INIT_ZONE_SIZE, PAGE_SIZE},
};
use std::ops::Range;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MemoryError {
    #[error("Forbidden memory access (address below 2^16): {0}")]
    Forbidden(MemAddress),
    #[error("Memory address out of range: {0}")]
    OutOfRange(MemAddress),
    #[error("Invalid page index: {0}")]
    InvalidPageIndex(usize),
    #[error("Memory access violation: (address: {0})")]
    AccessViolation(MemAddress),
    #[error("Heap stack collision occurred during SBRK. Break: {0}, Requested Size: {1}, Stack Start: {2}"
    )]
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

pub fn mem_address(page_index: usize, offset: usize) -> MemAddress {
    (page_index * PAGE_SIZE + offset) as MemAddress
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Memory {
    data: Vec<u8>,
    page_accesses: Vec<AccessType>,
    page_size: usize,
    total_pages: usize,
    pub heap_start: MemAddress,
    pub heap_end: MemAddress,
    pub stack_start: MemAddress,
}

impl Memory {
    pub fn new(size: usize, page_size: usize) -> Self {
        let total_pages = size.div_ceil(page_size);
        Self {
            data: vec![0; size],
            page_accesses: vec![AccessType::Inaccessible; total_pages],
            page_size,
            total_pages,
            heap_start: 0,
            heap_end: 0,
            stack_start: 0,
        }
    }

    /// Validates if the given page index is within the valid range.
    #[inline(always)]
    fn validate_page_index_bound(&self, page_index: usize) -> Result<(), MemoryError> {
        if page_index >= self.total_pages {
            Err(MemoryError::InvalidPageIndex(page_index))
        } else {
            Ok(())
        }
    }

    #[inline(always)]
    pub fn get_page_and_offset(&self, address: MemAddress) -> (usize, usize) {
        let page_index = (address as usize) / self.page_size;
        let offset = (address as usize) % self.page_size;
        (page_index, offset)
    }

    /// Sets the access type for the memory page at the given index.
    fn set_page_access(
        &mut self,
        page_index: usize,
        access: AccessType,
    ) -> Result<(), MemoryError> {
        self.validate_page_index_bound(page_index)?;
        self.page_accesses[page_index] = access;
        Ok(())
    }

    /// Sets the access type for a range of memory pages.
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

    /// Sets the access type for a memory range specified by start and end addresses.
    pub fn set_address_range_access(
        &mut self,
        address_range: Range<MemAddress>,
        access: AccessType,
    ) -> Result<(), MemoryError> {
        if address_range.is_empty() {
            return Ok(());
        }
        let (start_page_index, _) = self.get_page_and_offset(address_range.start);
        let (end_page_index, _) = self.get_page_and_offset(address_range.end.saturating_sub(1));

        self.set_page_range_access(start_page_index..end_page_index + 1, access)?;
        Ok(())
    }

    /// Check if a memory page is readable.
    #[inline(always)]
    fn is_page_readable(&self, page_index: usize) -> bool {
        matches!(
            self.page_accesses.get(page_index),
            Some(AccessType::ReadOnly | AccessType::ReadWrite)
        )
    }

    /// Check if a memory cell at the given address is in a readable page.
    #[allow(dead_code)]
    fn is_address_readable(&self, address: MemAddress) -> bool {
        let (page_index, _) = self.get_page_and_offset(address);
        self.is_page_readable(page_index)
    }

    /// Returns the lowest memory address that is not readable, if found any.
    /// If all pages in the range are readable, returns `None`.
    fn check_not_readable_in_range(&self, page_range: Range<usize>) -> Option<MemAddress> {
        for page_index in page_range {
            if !self.is_page_readable(page_index) {
                // The first address of the page
                return Some(mem_address(page_index, 0));
            }
        }
        None
    }

    /// Check if a range of memory pages is readable.
    pub fn is_page_range_readable(&self, page_range: Range<usize>) -> bool {
        page_range
            .clone()
            .all(|page_index| self.is_page_readable(page_index))
    }

    /// Check if a range of memory cells is readable.
    pub fn is_address_range_readable(&self, start: MemAddress, length: usize) -> bool {
        if length == 0 {
            return true;
        }
        let end = start as usize + length - 1;
        let (start_page, _) = self.get_page_and_offset(start);
        let (end_page, _) = self.get_page_and_offset(end as MemAddress);
        self.is_page_range_readable(start_page..end_page + 1)
    }

    /// Check if a memory page is writable.
    #[inline(always)]
    fn is_page_writable(&self, page_index: usize) -> bool {
        matches!(
            self.page_accesses.get(page_index),
            Some(AccessType::ReadWrite)
        )
    }

    /// Check if a memory cell at the given address is in a writable page.
    #[allow(dead_code)]
    fn is_address_writable(&self, address: MemAddress) -> bool {
        let (page_index, _) = self.get_page_and_offset(address);
        self.is_page_writable(page_index)
    }

    /// Returns the lowest memory address that is not writable, if found any.
    /// If all pages in the range are writable, returns `None`.
    fn check_not_writable_in_range(&self, page_range: Range<usize>) -> Option<MemAddress> {
        for page_index in page_range {
            if !self.is_page_writable(page_index) {
                // The first address of the page
                return Some(mem_address(page_index, 0));
            }
        }
        None
    }

    /// Check if a range of memory pages is writable.
    pub fn is_page_range_writable(&self, page_range: Range<usize>) -> bool {
        page_range
            .clone()
            .all(|page_index| self.is_page_writable(page_index))
    }

    /// Check if a range of memory cells is writable.
    pub fn is_address_range_writable(&self, start: MemAddress, length: usize) -> bool {
        if length == 0 {
            return true;
        }
        let end = start as usize + length - 1;
        let (start_page, _) = self.get_page_and_offset(start);
        let (end_page, _) = self.get_page_and_offset(end as MemAddress);
        self.is_page_range_writable(start_page..end_page + 1)
    }

    /// Read a byte from a memory cell at the given address.
    pub fn read_byte(&self, address: MemAddress) -> Result<u8, MemoryError> {
        if address < INIT_ZONE_SIZE as MemAddress {
            return Err(MemoryError::Forbidden(address));
        }

        if address as usize >= self.data.len() {
            return Err(MemoryError::OutOfRange(address));
        }

        let (page_index, _) = self.get_page_and_offset(address);
        if self.is_page_readable(page_index) {
            Ok(self.data[address as usize])
        } else {
            Err(MemoryError::AccessViolation(address))
        }
    }

    /// Read a specified number of bytes from memory starting at the given address.
    pub fn read_bytes(&self, address: MemAddress, length: usize) -> Result<Vec<u8>, MemoryError> {
        if length == 0 {
            return Ok(Vec::new());
        }

        if address < INIT_ZONE_SIZE as MemAddress {
            return Err(MemoryError::Forbidden(address));
        }

        let start = address as usize;
        let end = start
            .checked_add(length)
            .ok_or(MemoryError::OutOfRange(address))?;

        if end > self.data.len() {
            return Err(MemoryError::OutOfRange(address));
        }

        let (start_page, _) = self.get_page_and_offset(address);
        let (end_page, _) = self.get_page_and_offset((end - 1) as MemAddress);

        if let Some(not_readable_addr) = self.check_not_readable_in_range(start_page..end_page + 1)
        {
            return Err(MemoryError::AccessViolation(not_readable_addr));
        }

        Ok(self.data[start..end].to_vec())
    }

    /// Write a byte to a memory cell at the given address.
    pub fn write_byte(&mut self, address: MemAddress, value: u8) -> Result<(), MemoryError> {
        if address < INIT_ZONE_SIZE as MemAddress {
            return Err(MemoryError::Forbidden(address));
        }

        if address as usize >= self.data.len() {
            return Err(MemoryError::OutOfRange(address));
        }

        let (page_index, _) = self.get_page_and_offset(address);
        if self.is_page_writable(page_index) {
            self.data[address as usize] = value;
            Ok(())
        } else {
            Err(MemoryError::AccessViolation(address))
        }
    }

    /// Write a slice of bytes to memory starting at the given address.
    pub fn write_bytes(&mut self, address: MemAddress, bytes: &[u8]) -> Result<(), MemoryError> {
        if bytes.is_empty() {
            return Ok(());
        }

        if address < INIT_ZONE_SIZE as MemAddress {
            return Err(MemoryError::Forbidden(address));
        }

        let start = address as usize;
        let end = start
            .checked_add(bytes.len())
            .ok_or(MemoryError::OutOfRange(address))?;

        if end > self.data.len() {
            return Err(MemoryError::OutOfRange(address));
        }

        let (start_page, _) = self.get_page_and_offset(address);
        let (end_page, _) = self.get_page_and_offset((end - 1) as MemAddress);

        if let Some(not_writable_addr) = self.check_not_writable_in_range(start_page..end_page + 1)
        {
            return Err(MemoryError::AccessViolation(not_writable_addr));
        }

        self.data[start..end].copy_from_slice(bytes);
        Ok(())
    }

    /// Get the break address (end of the heap) of current memory layout.
    pub fn get_break(&self, expand_size: usize) -> MemAddress {
        let mut break_address = self.heap_end;
        loop {
            // FIXME: SBRK: Current implementation is a workaround since address-level access control is limited
            if self.is_address_range_readable(break_address, expand_size)
                && !self.is_address_range_writable(break_address, expand_size)
            {
                break_address += 1;
            } else {
                break;
            }
        }
        break_address
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
        self.set_address_range_access(start..end, AccessType::ReadWrite)?; // FIXME: SBRK: address-level access control
        self.heap_end = end;
        Ok(())
    }
}
