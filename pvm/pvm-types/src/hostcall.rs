use crate::common::RegValue;

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
    // Debugging (JIP-1)
    LOG = 100,
    // Reserved for invalid host call type
    INVALID = u8::MAX,
}

impl From<RegValue> for HostCallType {
    /// Maps a host-call id `h`, the full immediate of `ecalli`, to its host call.
    /// An id that names no host call maps to `INVALID`.
    fn from(id: RegValue) -> Self {
        match id {
            0 => HostCallType::GAS,
            1 => HostCallType::FETCH,
            2 => HostCallType::LOOKUP,
            3 => HostCallType::READ,
            4 => HostCallType::WRITE,
            5 => HostCallType::INFO,
            6 => HostCallType::HISTORICAL_LOOKUP,
            7 => HostCallType::EXPORT,
            8 => HostCallType::MACHINE,
            9 => HostCallType::PEEK,
            10 => HostCallType::POKE,
            11 => HostCallType::PAGES,
            12 => HostCallType::INVOKE,
            13 => HostCallType::EXPUNGE,
            14 => HostCallType::BLESS,
            15 => HostCallType::ASSIGN,
            16 => HostCallType::DESIGNATE,
            17 => HostCallType::CHECKPOINT,
            18 => HostCallType::NEW,
            19 => HostCallType::UPGRADE,
            20 => HostCallType::TRANSFER,
            21 => HostCallType::EJECT,
            22 => HostCallType::QUERY,
            23 => HostCallType::SOLICIT,
            24 => HostCallType::FORGET,
            25 => HostCallType::YIELD,
            26 => HostCallType::PROVIDE,
            100 => HostCallType::LOG,
            _ => HostCallType::INVALID,
        }
    }
}
