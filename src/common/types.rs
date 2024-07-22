// Types
pub type Hash32 = [u8; 32]; // FIXME: should be subset of `[u8; 32]`
pub type Octets = Vec<u8>;
pub type BandersnatchPubKey = Hash32;
pub type BandersnatchSignature = [u8; 64];
pub type BandersnatchRingRoot = [u8; 196608];
pub type BandersnatchRingVrfProof = [u8; 784];
pub type Ed25519PubKey = Hash32;
pub const ED25519_PUBKEY: Ed25519PubKey = HASH32_DEFAULT;
pub type Ed25519Signature = [u8; 64];
pub type Ed25519SignatureWithKeyAndMessage = Ed25519Signature;
pub type Ticket = (Hash32, u32); // N_N; u32 range [0, 2)
pub type SignedGas = i64;
pub type UnsignedGas = u64;
pub type ValidatorKey = [u8; 336];

pub const HASH32_DEFAULT: Hash32 = [0u8; 32];
pub const BANDERSNATCH_PUBKEY: BandersnatchPubKey = HASH32_DEFAULT;
pub const BANDERSNATCH_SIGNATURE_DEFAULT: BandersnatchSignature = [0u8; 64];
pub const BANDERSNATCH_RING_ROOT_DEFAULT: BandersnatchRingRoot = [0u8; 196608];
pub const BANDERSNATCH_RING_VRF_PROOF_DEFAULT: BandersnatchRingVrfProof = [0u8; 784];
pub const ED25519_SIGNATURE_DEFAULT: Ed25519Signature = [0u8; 64];
pub const ED25519_SIGNATURE_WITH_KEY_AND_MESSAGE_DEFAULT: Ed25519SignatureWithKeyAndMessage =
    ED25519_SIGNATURE_DEFAULT;
pub const TICKET_DEFAULT: Ticket = (HASH32_DEFAULT, 0);
pub const SIGNED_GAS_DEFAULT: SignedGas = 0;
pub const UNSIGNED_GAS_DEFAULT: UnsignedGas = 0;
pub const VALIDATOR_KEY_DEFAULT: ValidatorKey = [0u8; 336];
