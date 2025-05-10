use crate::peers::ValidatorPeer;
use dashmap::DashMap;
use fr_common::ByteEncodable;
use fr_crypto::types::{Ed25519PubKey, ValidatorKeySet};

#[allow(dead_code)]
pub(crate) fn preferred_initiator<'a>(
    a: &'a Ed25519PubKey,
    b: &'a Ed25519PubKey,
) -> &'a Ed25519PubKey {
    if (a.as_slice()[31] > 127) ^ (b.as_slice()[31] > 127) ^ (a < b) {
        a
    } else {
        b
    }
}

pub(crate) fn validator_set_to_peers(
    validator_set: ValidatorKeySet,
) -> DashMap<Ed25519PubKey, ValidatorPeer> {
    validator_set
        .iter()
        .map(|vk| {
            (
                vk.ed25519_key.clone(),
                ValidatorPeer::from_validator_key(vk.clone()),
            )
        })
        .collect()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_preferred_initiator_all_true() {
        let mut a_bytes = [0; 32];
        a_bytes[31] = 128;
        let mut b_bytes = [0; 32];
        b_bytes[31] = 129;
        let a = Ed25519PubKey::from_slice(&a_bytes).unwrap();
        let b = Ed25519PubKey::from_slice(&b_bytes).unwrap();
        assert_eq!(preferred_initiator(&a, &b), &a);
    }

    #[test]
    fn test_preferred_initiator_all_false() {
        let mut a_bytes = [0; 32];
        a_bytes[31] = 127;
        let mut b_bytes = [0; 32];
        b_bytes[31] = 126;
        let a = Ed25519PubKey::from_slice(&a_bytes).unwrap();
        let b = Ed25519PubKey::from_slice(&b_bytes).unwrap();
        assert_eq!(preferred_initiator(&a, &b), &b);
    }

    #[test]
    fn test_preferred_initiator_one_true() {
        let mut a_bytes = [0; 32];
        a_bytes[31] = 128;
        let mut b_bytes = [0; 32];
        b_bytes[31] = 127;
        let a = Ed25519PubKey::from_slice(&a_bytes).unwrap();
        let b = Ed25519PubKey::from_slice(&b_bytes).unwrap();
        assert_eq!(preferred_initiator(&a, &b), &a);
        let mut a_bytes = [0; 32];
        a_bytes[31] = 126;
        let mut b_bytes = [0; 32];
        b_bytes[31] = 127;
        let a = Ed25519PubKey::from_slice(&a_bytes).unwrap();
        let b = Ed25519PubKey::from_slice(&b_bytes).unwrap();
        assert_eq!(preferred_initiator(&a, &b), &a);
    }

    #[test]
    fn test_preferred_initiator_two_true() {
        let mut a_bytes = [0; 32];
        a_bytes[31] = 129;
        let mut b_bytes = [0; 32];
        b_bytes[31] = 128;
        let a = Ed25519PubKey::from_slice(&a_bytes).unwrap();
        let b = Ed25519PubKey::from_slice(&b_bytes).unwrap();
        assert_eq!(preferred_initiator(&a, &b), &b);
        let mut a_bytes = [0; 32];
        a_bytes[31] = 127;
        let mut b_bytes = [0; 32];
        b_bytes[31] = 128;
        let a = Ed25519PubKey::from_slice(&a_bytes).unwrap();
        let b = Ed25519PubKey::from_slice(&b_bytes).unwrap();
        assert_eq!(preferred_initiator(&a, &b), &b);
    }
}
