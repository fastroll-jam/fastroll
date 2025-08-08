//! Test-only keystore module
pub mod dev_account_profile;

use fr_codec::prelude::*;
use fr_common::{utils::serde::FileLoader, ByteArray};
use fr_crypto::types::{
    BandersnatchPubKey, BandersnatchSecretKey, BlsPubKey, Ed25519PubKey, ValidatorKey,
    ValidatorMetadata,
};
use fr_network::manager::LocalNodeInfo;
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
    FileLoader::load_from_json_file(&full_path)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevAccountInfo {
    seed: ByteArray<32>,
    ed25519_private: ByteArray<32>,
    ed25519_public: Ed25519PubKey,
    bandersnatch_private: ByteArray<32>,
    bandersnatch_public: BandersnatchPubKey,
    dns_alt_name: String,
    metadata: ValidatorMetadata,
}

impl From<DevAccountInfo> for LocalNodeInfo {
    fn from(value: DevAccountInfo) -> Self {
        let ipv6: [u8; 16] = value.metadata.0[0..16].try_into().unwrap();
        let port = u16::decode_fixed(&mut &value.metadata.0[16..18], 2).unwrap();
        let socket_addr_v6 = SocketAddrV6::new(Ipv6Addr::from(ipv6), port, 0, 0);
        let validator_key = ValidatorKey {
            bandersnatch: value.bandersnatch_public,
            ed25519: value.ed25519_public,
            bls: BlsPubKey::default(),
            metadata: value.metadata,
        };
        Self {
            socket_addr: socket_addr_v6,
            validator_key,
        }
    }
}

impl DevAccountInfo {
    pub fn bandersnatch_secret_key(&self) -> BandersnatchSecretKey {
        BandersnatchSecretKey(self.bandersnatch_private.clone())
    }

    pub fn bandersnatch_pub_key(&self) -> BandersnatchPubKey {
        self.bandersnatch_public.clone()
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
