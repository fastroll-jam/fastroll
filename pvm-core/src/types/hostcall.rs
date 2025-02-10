use crate::types::error::{PVMError, VMCoreError::InvalidHostCallType};

#[repr(u8)]
#[derive(Clone)]
#[allow(non_camel_case_types)]
pub enum HostCallType {
    // General Functions
    GAS = 0,
    LOOKUP = 1,
    READ = 2,
    WRITE = 3,
    INFO = 4,
    // Accumulate Functions
    BLESS = 5,
    ASSIGN = 6,
    DESIGNATE = 7,
    CHECKPOINT = 8,
    NEW = 9,
    UPGRADE = 10,
    TRANSFER = 11,
    QUIT = 12,
    SOLICIT = 13,
    FORGET = 14,
    // Refine Functions
    HISTORICAL_LOOKUP = 15,
    IMPORT = 16,
    EXPORT = 17,
    MACHINE = 18,
    PEEK = 19,
    POKE = 20,
    ZERO = 21,
    VOID = 22,
    INVOKE = 23,
    EXPUNGE = 24,
}

impl TryFrom<u8> for HostCallType {
    type Error = PVMError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(HostCallType::GAS),
            1 => Ok(HostCallType::LOOKUP),
            2 => Ok(HostCallType::READ),
            3 => Ok(HostCallType::WRITE),
            4 => Ok(HostCallType::INFO),
            5 => Ok(HostCallType::BLESS),
            6 => Ok(HostCallType::ASSIGN),
            7 => Ok(HostCallType::DESIGNATE),
            8 => Ok(HostCallType::CHECKPOINT),
            9 => Ok(HostCallType::NEW),
            10 => Ok(HostCallType::UPGRADE),
            11 => Ok(HostCallType::TRANSFER),
            12 => Ok(HostCallType::QUIT),
            13 => Ok(HostCallType::SOLICIT),
            14 => Ok(HostCallType::FORGET),
            15 => Ok(HostCallType::HISTORICAL_LOOKUP),
            16 => Ok(HostCallType::IMPORT),
            17 => Ok(HostCallType::EXPORT),
            18 => Ok(HostCallType::MACHINE),
            19 => Ok(HostCallType::PEEK),
            20 => Ok(HostCallType::POKE),
            21 => Ok(HostCallType::ZERO),
            22 => Ok(HostCallType::VOID),
            23 => Ok(HostCallType::INVOKE),
            24 => Ok(HostCallType::EXPUNGE),
            _ => Err(PVMError::VMCoreError(InvalidHostCallType)),
        }
    }
}

impl HostCallType {
    pub fn from_u8(value: u8) -> Option<Self> {
        Self::try_from(value).ok()
    }
}
