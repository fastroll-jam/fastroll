//! Test-only keystore module
use rjam_conformance_tests::{asn_types::common::AsnByteArray, utils::AsnTypeLoader};
use rjam_crypto::types::{BandersnatchPubKey, BandersnatchSecretKey};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, path::PathBuf};

/// Loads Bandersnatch secret key from the dev keystore that corresponds to the given public key.
pub(crate) fn load_author_secret_key(
    pub_key: &BandersnatchPubKey,
) -> Option<BandersnatchSecretKey> {
    let dev_accounts_map = DevAccountsKeyMap::from_dev_accounts(load_dev_accounts_from_file());
    dev_accounts_map.load_bander_sk_from_pk(pub_key).cloned()
}

fn load_dev_accounts_from_file() -> DevAccounts {
    let json_path = PathBuf::from("src/keystore/dev_accounts.json");
    let full_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(json_path);
    AsnTypeLoader::load_from_json_file(&full_path)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct DevAccount {
    seed: AsnByteArray<32>,
    ed25519_private: AsnByteArray<32>,
    ed25519_public: AsnByteArray<32>,
    bandersnatch_private: AsnByteArray<32>,
    bandersnatch_public: AsnByteArray<32>,
    dns_alt_name: String,
}

impl DevAccount {
    pub(crate) fn bandersnatch_secret_key(&self) -> BandersnatchSecretKey {
        BandersnatchSecretKey(self.bandersnatch_private.into())
    }

    pub(crate) fn bandersnatch_pub_key(&self) -> BandersnatchPubKey {
        BandersnatchPubKey(self.bandersnatch_public.into())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct DevAccounts {
    pub(crate) alice: DevAccount,
    pub(crate) bob: DevAccount,
    pub(crate) carol: DevAccount,
    pub(crate) david: DevAccount,
    pub(crate) eve: DevAccount,
    pub(crate) fergie: DevAccount,
}

pub(crate) struct DevAccountsKeyMap {
    inner: HashMap<BandersnatchPubKey, BandersnatchSecretKey>,
}

impl DevAccountsKeyMap {
    pub(crate) fn from_dev_accounts(dev_accounts: DevAccounts) -> Self {
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

    pub(crate) fn load_bander_sk_from_pk(
        &self,
        pub_key: &BandersnatchPubKey,
    ) -> Option<&BandersnatchSecretKey> {
        self.inner.get(pub_key)
    }
}
