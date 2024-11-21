use crate::constants::PAGE_SIZE;
use thiserror::Error;

pub type MemAddress = u32;

#[derive(Debug, Error)]
pub enum MemoryError {
    #[error("Out of memory")]
    OutOfMemory,
    #[error("Memory access violation: {0}")]
    AccessViolation(MemAddress),
    #[error("Memory cell unavailable: {0}")]
    CellUnavailable(MemAddress),
}

/// Memory Cell Access Types
#[derive(Clone, Copy, Default, PartialEq)]
pub enum AccessType {
    #[default]
    Inaccessible,
    ReadOnly,
    ReadWrite,
}

#[derive(Clone)]
pub struct Memory {
    cells: Vec<MemoryCell>,
    #[allow(dead_code)]
    page_size: usize,
    pub heap_start: MemAddress,
}

#[derive(Clone, Copy, Default)]
struct MemoryCell {
    value: u8,
    access: AccessType,
}

impl Default for Memory {
    fn default() -> Self {
        Self {
            cells: vec![],
            page_size: PAGE_SIZE,
            heap_start: 0,
        }
    }
}

impl Memory {
    pub fn new(size: usize, page_size: usize) -> Self {
        let cells = vec![MemoryCell::default(); size];
        Memory {
            cells,
            page_size,
            heap_start: 0,
        }
    }

    // FIXME: accept `MemAddress` type for start address
    /// Set memory cells of provided range with data and access type
    pub fn set_range(&mut self, start: usize, data: &[u8], access: AccessType) {
        for (i, &byte) in data.iter().enumerate() {
            if let Some(cell) = self.cells.get_mut(start + i) {
                cell.value = byte;
                cell.access = access;
            }
        }
    }

    /// Set memory cells of provided range with access type
    pub fn set_access_range(&mut self, start: usize, end: usize, access: AccessType) {
        for cell in &mut self.cells[start..end] {
            cell.access = access
        }
    }

    /// Check if a memory cell at the given address is readable
    pub fn is_cell_readable(&self, address: MemAddress) -> bool {
        self.read_byte(address).is_ok()
    }

    /// Check if a range of memory cells is readable
    pub fn is_range_readable(&self, start: MemAddress, length: usize) -> Result<bool, MemoryError> {
        if length == 0 {
            return Ok(true);
        }

        let end = start
            .checked_add(length as u32)
            .ok_or(MemoryError::AccessViolation(start))?;

        for address in start..end {
            if !self.is_cell_readable(address) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Check if a memory cell at the given address is writable
    pub fn is_cell_writable(&self, address: MemAddress) -> bool {
        match self.read_byte(address) {
            Ok(_) => {
                // If we can read, we need to check if it's also writable
                matches!(
                    self.cells.get(address as usize),
                    Some(cell) if matches!(cell.access, AccessType::ReadWrite)
                )
            }
            Err(_) => false,
        }
    }

    /// Check if a range of memory cells is writable
    pub fn is_range_writable(&self, start: MemAddress, length: usize) -> Result<bool, MemoryError> {
        if length == 0 {
            return Ok(true);
        }

        let end = start
            .checked_add(length as u32)
            .ok_or(MemoryError::AccessViolation(start))?;

        for address in start..end {
            if !self.is_cell_writable(address) {
                return Ok(false);
            }
        }
        Ok(true)
    }
    /// Read a byte from memory
    pub fn read_byte(&self, address: MemAddress) -> Result<u8, MemoryError> {
        let cell = self
            .cells
            .get(address as usize)
            .ok_or(MemoryError::AccessViolation(address))?;

        match cell.access {
            AccessType::ReadOnly | AccessType::ReadWrite => Ok(cell.value),
            AccessType::Inaccessible => Err(MemoryError::CellUnavailable(address)),
        }
    }

    /// Write an u8 value to memory
    pub fn write_byte(&mut self, address: MemAddress, value: u8) -> Result<(), MemoryError> {
        let cell = self
            .cells
            .get_mut(address as usize)
            .ok_or(MemoryError::AccessViolation(address))?;

        match cell.access {
            AccessType::ReadWrite => {
                cell.value = value;
                Ok(())
            }
            AccessType::ReadOnly | AccessType::Inaccessible => {
                Err(MemoryError::CellUnavailable(address))
            }
        }
    }

    /// Read a specified number of bytes from memory starting at the given address
    pub fn read_bytes(&self, address: MemAddress, length: usize) -> Result<Vec<u8>, MemoryError> {
        (0..length)
            .map(|i| self.read_byte(address + i as MemAddress))
            .collect()
    }

    /// Write a slice of bytes to memory starting at the given address
    pub fn write_bytes(&mut self, address: MemAddress, bytes: &[u8]) -> Result<(), MemoryError> {
        for (i, &byte) in bytes.iter().enumerate() {
            self.write_byte(address + i as MemAddress, byte)?;
        }
        Ok(())
    }

    /// Get the break address (end of the heap) of current memory layout
    pub fn get_break(&self, requested_size: usize) -> Result<MemAddress, MemoryError> {
        let heap_start = self.heap_start;

        let mut current_start = heap_start;
        let mut consecutive_unavailable = 0;

        for (i, cell) in self.cells[heap_start as usize..].iter().enumerate() {
            if cell.access == AccessType::Inaccessible {
                consecutive_unavailable += 1;
                if consecutive_unavailable == requested_size {
                    return Ok(current_start);
                }
            } else {
                current_start = heap_start + i as MemAddress + 1;
                consecutive_unavailable = 0;
            }
        }
        Err(MemoryError::OutOfMemory)
    }

    /// Expand the heap (read-write) area for the `sbrk` instruction
    pub fn expand_heap(&mut self, start: MemAddress, size: usize) -> Result<(), MemoryError> {
        let end = start
            .checked_add(size as MemAddress)
            .ok_or(MemoryError::OutOfMemory)?;

        if end as usize > self.cells.len() {
            return Err(MemoryError::OutOfMemory);
        }

        // mark the new cells (expanding heap area) as writable
        for cell in &mut self.cells[start as usize..end as usize] {
            cell.access = AccessType::ReadWrite;
        }

        Ok(())
    }
}
