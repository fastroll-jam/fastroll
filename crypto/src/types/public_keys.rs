use crate::{impl_byte_encodable, impl_public_key, traits::PublicKey};
use base32::Alphabet;
use rjam_codec::prelude::*;
use rjam_common::{ByteArray, ByteEncodable, CommonTypeError};

/// 32-byte Bandersnatch public key type.
#[derive(Debug, Default, Clone, PartialEq, Eq, Hash, JamEncode, JamDecode)]
pub struct BandersnatchPubKey(pub ByteArray<32>);
impl_byte_encodable!(BandersnatchPubKey);
impl_public_key!(BandersnatchPubKey);

/// 32-byte Ed25519 public key type.
#[derive(Debug, Default, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, JamEncode, JamDecode)]
pub struct Ed25519PubKey(pub ByteArray<32>);
impl_byte_encodable!(Ed25519PubKey);
impl_public_key!(Ed25519PubKey);

impl Ed25519PubKey {
    pub fn as_dns_name(&self) -> String {
        let mut dns_name = "e".to_string();
        let pk_base32 =
            base32::encode(Alphabet::Rfc4648 { padding: false }, self.as_slice()).to_lowercase();
        dns_name.push_str(&pk_base32);
        dns_name
    }
}

/// 144-byte BLS public key type.
#[derive(Debug, Default, Clone, PartialEq, Eq, JamEncode, JamDecode)]
pub struct BlsPubKey(pub ByteArray<144>);
impl_byte_encodable!(BlsPubKey);
impl_public_key!(BlsPubKey);

#[test]
pub fn test_ed25519_dns_name() {
    let pk = Ed25519PubKey::from_hex(
        "0x3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29",
    )
    .unwrap();
    assert_eq!(
        pk.as_dns_name().as_str(),
        "ehnvcppgow2sc2yvdvdicu3ynonsteflxdxrehjr2ybekdc2z3iuq"
    );
}
