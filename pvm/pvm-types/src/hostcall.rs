#[repr(u8)]
#[derive(Clone, Debug)]
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
    EJECT = 12,
    QUERY = 13,
    SOLICIT = 14,
    FORGET = 15,
    YIELD = 16,
    // Refine Functions
    HISTORICAL_LOOKUP = 17,
    FETCH = 18,
    EXPORT = 19,
    MACHINE = 20,
    PEEK = 21,
    POKE = 22,
    ZERO = 23,
    VOID = 24,
    INVOKE = 25,
    EXPUNGE = 26,
}

impl TryFrom<u8> for HostCallType {
    type Error = ();

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
            12 => Ok(HostCallType::EJECT),
            13 => Ok(HostCallType::QUERY),
            14 => Ok(HostCallType::SOLICIT),
            15 => Ok(HostCallType::FORGET),
            16 => Ok(HostCallType::YIELD),
            17 => Ok(HostCallType::HISTORICAL_LOOKUP),
            18 => Ok(HostCallType::FETCH),
            19 => Ok(HostCallType::EXPORT),
            20 => Ok(HostCallType::MACHINE),
            21 => Ok(HostCallType::PEEK),
            22 => Ok(HostCallType::POKE),
            23 => Ok(HostCallType::ZERO),
            24 => Ok(HostCallType::VOID),
            25 => Ok(HostCallType::INVOKE),
            26 => Ok(HostCallType::EXPUNGE),
            _ => Err(()),
        }
    }
}

impl HostCallType {
    pub fn from_u8(value: u8) -> Option<Self> {
        Self::try_from(value).ok()
    }
}
