// Types
pub type Hash32 = [u8; 32]; // FIXME: should be subset of `[u8; 32]`
pub type Octets = Vec<u8>;
pub type BandersnatchPubKey = Hash32;
pub type BandersnatchSignature = [u8; 64];
pub type BandersnatchRingRoot = [u8; 144];
pub type BandersnatchRingVrfProof = [u8; 784];
pub type Ed25519PubKey = Hash32;
pub type Ed25519Signature = [u8; 64];
pub type Ed25519SignatureWithKeyAndMessage = Ed25519Signature;
pub type SignedGas = i64;
pub type UnsignedGas = u64;
pub const HASH32_DEFAULT: Hash32 = [0u8; 32];
pub const BANDERSNATCH_RING_ROOT_DEFAULT: BandersnatchRingRoot = [0u8; 144];
