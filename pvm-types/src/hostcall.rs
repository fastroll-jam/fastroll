#[repr(u8)]
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
    ASSIGN = 21, // TODO: check value
    DESIGNATE = 6,
    CHECKPOINT = 7,
    NEW = 22, // TODO: check value
    UPGRADE = 8,
    TRANSFER = 9,
    QUIT = 10,
    SOLICIT = 11,
    FORGET = 12,
    // Refine Functions
    HISTORICAL_LOOKUP = 13,
    IMPORT = 14,
    EXPORT = 15,
    MACHINE = 16,
    PEEK = 17,
    POKE = 18,
    INVOKE = 19,
    EXPUNGE = 20,
}

impl HostCallType {
    pub fn from_u8(value: u8) -> Option<Self> {
        if value <= 22 {
            Some(unsafe { std::mem::transmute(value) })
        } else {
            None
        }
    }
}
