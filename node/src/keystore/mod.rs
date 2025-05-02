//! Test-only keystore module
use crate::jam_node::ValidatorInfo;
use rjam_codec::prelude::*;
use rjam_conformance_tests::{asn_types::common::AsnByteArray, utils::AsnTypeLoader};
use rjam_crypto::types::{BandersnatchPubKey, BandersnatchSecretKey, BlsPubKey, ValidatorKey};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::{Ipv6Addr, SocketAddrV6},
    path::PathBuf,
};

/// Loads Bandersnatch secret key from the dev keystore that corresponds to the given public key.
pub fn load_author_secret_key(pub_key: &BandersnatchPubKey) -> Option<BandersnatchSecretKey> {
    let dev_accounts_map = DevAccountsKeyMap::from_dev_accounts(load_dev_accounts_from_file());
    dev_accounts_map.load_bander_sk_from_pk(pub_key).cloned()
}

pub fn load_dev_accounts_from_file() -> DevAccountsInfo {
    let json_path = PathBuf::from("src/keystore/dev_accounts.json");
    let full_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(json_path);
    AsnTypeLoader::load_from_json_file(&full_path)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevAccountInfo {
    seed: AsnByteArray<32>,
    ed25519_private: AsnByteArray<32>,
    ed25519_public: AsnByteArray<32>,
    bandersnatch_private: AsnByteArray<32>,
    bandersnatch_public: AsnByteArray<32>,
    dns_alt_name: String,
    metadata: AsnByteArray<128>,
}

impl From<DevAccountInfo> for ValidatorInfo {
    fn from(value: DevAccountInfo) -> Self {
        let ipv6: [u8; 16] = value.metadata.0[0..16].try_into().unwrap();
        let port = u16::decode_fixed(&mut &value.metadata.0[16..18], 2).unwrap();
        let socket_addr_v6 = SocketAddrV6::new(Ipv6Addr::from(ipv6), port, 0, 0);
        let validator_key = ValidatorKey {
            bandersnatch_key: value.bandersnatch_public.into(),
            ed25519_key: value.ed25519_public.into(),
            bls_key: BlsPubKey::default(),
            metadata: value.metadata.into(),
        };
        Self {
            socket_addr_v6,
            validator_key,
        }
    }
}

impl DevAccountInfo {
    pub fn bandersnatch_secret_key(&self) -> BandersnatchSecretKey {
        BandersnatchSecretKey(self.bandersnatch_private.into())
    }

    pub fn bandersnatch_pub_key(&self) -> BandersnatchPubKey {
        BandersnatchPubKey(self.bandersnatch_public.into())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevAccountsInfo {
    pub alice: DevAccountInfo,
    pub bob: DevAccountInfo,
    pub carol: DevAccountInfo,
    pub david: DevAccountInfo,
    pub eve: DevAccountInfo,
    pub fergie: DevAccountInfo,
}

pub struct DevAccountsKeyMap {
    inner: HashMap<BandersnatchPubKey, BandersnatchSecretKey>,
}

impl DevAccountsKeyMap {
    pub fn from_dev_accounts(dev_accounts: DevAccountsInfo) -> Self {
        let mut inner = HashMap::new();
        inner.insert(
            dev_accounts.alice.bandersnatch_pub_key(),
            dev_accounts.alice.bandersnatch_secret_key(),
        );
        inner.insert(
            dev_accounts.bob.bandersnatch_pub_key(),
            dev_accounts.bob.bandersnatch_secret_key(),
        );
        inner.insert(
            dev_accounts.carol.bandersnatch_pub_key(),
            dev_accounts.carol.bandersnatch_secret_key(),
        );
        inner.insert(
            dev_accounts.david.bandersnatch_pub_key(),
            dev_accounts.david.bandersnatch_secret_key(),
        );
        inner.insert(
            dev_accounts.eve.bandersnatch_pub_key(),
            dev_accounts.eve.bandersnatch_secret_key(),
        );
        inner.insert(
            dev_accounts.fergie.bandersnatch_pub_key(),
            dev_accounts.fergie.bandersnatch_secret_key(),
        );
        Self { inner }
    }

    pub fn load_bander_sk_from_pk(
        &self,
        pub_key: &BandersnatchPubKey,
    ) -> Option<&BandersnatchSecretKey> {
        self.inner.get(pub_key)
    }
}
