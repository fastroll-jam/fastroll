pub const VALIDATOR_COUNT: usize = 1023; // 1023 validators
pub const EPOCH_LENGTH: usize = 600; // 600 timeslots per epoch
pub const CORE_COUNT: usize = 341; // (1023 / 3 = 341) cores

pub type Hash32 = [u8; 32]; // should be subset of `[u8; 32]`
pub type Octet = Vec<u8>;
pub type BandersnatchPubKey = Hash32;
pub type BandersnatchSignature = [u8; 64];
pub type BandersnatchRingRoot = [u8; 196608];
pub type Ed25519PubKey = Hash32;
pub type Ticket = (Hash32, u8); // u8 range [0, 2)
pub type SignedGas = i64;
