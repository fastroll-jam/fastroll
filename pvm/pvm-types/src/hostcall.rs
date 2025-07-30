#[repr(u8)]
#[derive(Clone, Debug, PartialEq)]
#[allow(non_camel_case_types)]
pub enum HostCallType {
    // General Functions
    GAS = 0,
    FETCH = 1,
    LOOKUP = 2,
    READ = 3,
    WRITE = 4,
    INFO = 5,
    // Refine Functions
    HISTORICAL_LOOKUP = 6,
    EXPORT = 7,
    MACHINE = 8,
    PEEK = 9,
    POKE = 10,
    PAGES = 11,
    INVOKE = 12,
    EXPUNGE = 13,
    // Accumulate Functions
    BLESS = 14,
    ASSIGN = 15,
    DESIGNATE = 16,
    CHECKPOINT = 17,
    NEW = 18,
    UPGRADE = 19,
    TRANSFER = 20,
    EJECT = 21,
    QUERY = 22,
    SOLICIT = 23,
    FORGET = 24,
    YIELD = 25,
    PROVIDE = 26,
}

impl TryFrom<u8> for HostCallType {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(HostCallType::GAS),
            1 => Ok(HostCallType::FETCH),
            2 => Ok(HostCallType::LOOKUP),
            3 => Ok(HostCallType::READ),
            4 => Ok(HostCallType::WRITE),
            5 => Ok(HostCallType::INFO),
            6 => Ok(HostCallType::HISTORICAL_LOOKUP),
            7 => Ok(HostCallType::EXPORT),
            8 => Ok(HostCallType::MACHINE),
            9 => Ok(HostCallType::PEEK),
            10 => Ok(HostCallType::POKE),
            11 => Ok(HostCallType::PAGES),
            12 => Ok(HostCallType::INVOKE),
            13 => Ok(HostCallType::EXPUNGE),
            14 => Ok(HostCallType::BLESS),
            15 => Ok(HostCallType::ASSIGN),
            16 => Ok(HostCallType::DESIGNATE),
            17 => Ok(HostCallType::CHECKPOINT),
            18 => Ok(HostCallType::NEW),
            19 => Ok(HostCallType::UPGRADE),
            20 => Ok(HostCallType::TRANSFER),
            21 => Ok(HostCallType::EJECT),
            22 => Ok(HostCallType::QUERY),
            23 => Ok(HostCallType::SOLICIT),
            24 => Ok(HostCallType::FORGET),
            25 => Ok(HostCallType::YIELD),
            26 => Ok(HostCallType::PROVIDE),
            _ => Err(()),
        }
    }
}

impl HostCallType {
    pub fn from_u8(value: u8) -> Option<Self> {
        Self::try_from(value).ok()
    }
}
