use crate::{ValidatorKey, VALIDATOR_COUNT};

// Types
pub type Hash32 = [u8; 32]; // FIXME: should be subset of `[u8; 32]`
pub type Octets = Vec<u8>;
pub type AccountAddress = u32; // service account address (index)
pub type TokenBalance = u64;
pub type BandersnatchPubKey = Hash32;
pub type BandersnatchSignature = [u8; 96]; // `F` signature type
pub type BandersnatchRingRoot = [u8; 144];
pub type BandersnatchRingVrfProof = [u8; 784]; // `F bar` signature type
pub type Ed25519PubKey = Hash32;
pub type Ed25519Signature = [u8; 64];
pub type Ed25519SignatureWithKeyAndMessage = Ed25519Signature;
pub type ValidatorSet = [ValidatorKey; VALIDATOR_COUNT];

pub type SignedGas = i64;
pub type UnsignedGas = u64;
pub const HASH32_EMPTY: Hash32 = [0u8; 32];
pub const BANDERSNATCH_RING_ROOT_DEFAULT: BandersnatchRingRoot = [0u8; 144];
