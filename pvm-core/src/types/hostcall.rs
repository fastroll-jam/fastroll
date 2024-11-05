use num_enum::TryFromPrimitive;

#[repr(u8)]
#[derive(Clone, TryFromPrimitive)]
#[allow(non_camel_case_types)]
pub enum HostCallType {
    // General Functions
    GAS = 0,
    LOOKUP = 1,
    READ = 2,
    WRITE = 3,
    INFO = 4,
    // Accumulate Functions
    EMPOWER = 5,
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
    INVOKE = 21,
    EXPUNGE = 22,
}

impl HostCallType {
    pub fn from_u8(value: u8) -> Option<Self> {
        Self::try_from(value).ok()
    }
}
