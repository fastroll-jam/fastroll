use crate::{impl_byte_encodable, impl_public_key, traits::PublicKey};
use rjam_codec::prelude::*;
use rjam_common::{ByteArray, ByteEncodable, CommonTypeError};

/// 32-byte Bandersnatch public key type.
#[derive(Debug, Default, Clone, PartialEq, Eq, JamEncode, JamDecode)]
pub struct BandersnatchPubKey(pub ByteArray<32>);
impl_byte_encodable!(BandersnatchPubKey);
impl_public_key!(BandersnatchPubKey);

/// 32-byte Ed25519 public key type.
#[derive(Debug, Default, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, JamEncode, JamDecode)]
pub struct Ed25519PubKey(pub ByteArray<32>);
impl_byte_encodable!(Ed25519PubKey);
impl_public_key!(Ed25519PubKey);

/// 144-byte BLS public key type.
#[derive(Debug, Default, Clone, PartialEq, Eq, JamEncode, JamDecode)]
pub struct BlsPubKey(pub ByteArray<144>);
impl_byte_encodable!(BlsPubKey);
impl_public_key!(BlsPubKey);
