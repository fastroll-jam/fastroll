use crate::common::RegValue;

#[repr(u8)]
#[derive(Clone, Debug, PartialEq)]
#[allow(non_camel_case_types)]
pub enum HostCallType {
    // General Functions
    GAS = 0,
    GROW_HEAP = 1,
    FETCH = 2,
    LOOKUP = 3,
    READ = 4,
    WRITE = 5,
    INFO = 6,
    // Refine Functions
    HISTORICAL_LOOKUP = 7,
    EXPORT = 8,
    MACHINE = 9,
    PEEK = 10,
    POKE = 11,
    PAGES = 12,
    INVOKE = 13,
    EXPUNGE = 14,
    // Accumulate Functions
    BLESS = 15,
    ASSIGN = 16,
    DESIGNATE = 17,
    CHECKPOINT = 18,
    NEW = 19,
    UPGRADE = 20,
    TRANSFER = 21,
    EJECT = 22,
    QUERY = 23,
    SOLICIT = 24,
    FORGET = 25,
    YIELD = 26,
    PROVIDE = 27,
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
            1 => HostCallType::GROW_HEAP,
            2 => HostCallType::FETCH,
            3 => HostCallType::LOOKUP,
            4 => HostCallType::READ,
            5 => HostCallType::WRITE,
            6 => HostCallType::INFO,
            7 => HostCallType::HISTORICAL_LOOKUP,
            8 => HostCallType::EXPORT,
            9 => HostCallType::MACHINE,
            10 => HostCallType::PEEK,
            11 => HostCallType::POKE,
            12 => HostCallType::PAGES,
            13 => HostCallType::INVOKE,
            14 => HostCallType::EXPUNGE,
            15 => HostCallType::BLESS,
            16 => HostCallType::ASSIGN,
            17 => HostCallType::DESIGNATE,
            18 => HostCallType::CHECKPOINT,
            19 => HostCallType::NEW,
            20 => HostCallType::UPGRADE,
            21 => HostCallType::TRANSFER,
            22 => HostCallType::EJECT,
            23 => HostCallType::QUERY,
            24 => HostCallType::SOLICIT,
            25 => HostCallType::FORGET,
            26 => HostCallType::YIELD,
            27 => HostCallType::PROVIDE,
            100 => HostCallType::LOG,
            _ => HostCallType::INVALID,
        }
    }
}
