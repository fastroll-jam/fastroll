use rjam_block::types::block::{
    BlockHeader, BlockHeaderData, EpochMarker, EpochMarkerValidatorKey,
};
use rjam_common::{ByteEncodable, Hash32, VALIDATOR_COUNT};
use rjam_crypto::types::*;

struct GenesisValidatorKeyConfig {
    bandersnatch_hex: &'static str,
    ed25519_hex: &'static str,
}

fn create_genesis_block_header(
    validator_configs: [GenesisValidatorKeyConfig; VALIDATOR_COUNT],
    author_index: u16,
) -> BlockHeader {
    let validators: [EpochMarkerValidatorKey; VALIDATOR_COUNT] = validator_configs
        .iter()
        .map(|config| EpochMarkerValidatorKey {
            bandersnatch_key: BandersnatchPubKey::from_hex(config.bandersnatch_hex)
                .expect("Should decode bandersnatch hex string"),
            ed25519_key: Ed25519PubKey::from_hex(config.ed25519_hex)
                .expect("Should decode ed25519 hex string"),
        })
        .collect::<Vec<_>>()
        .try_into()
        .expect("Validator count must match VALIDATOR_COUNT");

    BlockHeader {
        data: BlockHeaderData {
            epoch_marker: Some(EpochMarker {
                entropy: Hash32::default(),
                tickets_entropy: Hash32::default(),
                validators: Box::new(validators),
            }),
            author_index,
            ..Default::default()
        },
        block_seal: BandersnatchSig::default(),
    }
}

pub(crate) fn genesis_block_header() -> BlockHeader {
    const DEFAULT_VALIDATOR_CONFIGS: [GenesisValidatorKeyConfig; VALIDATOR_COUNT] = [
        GenesisValidatorKeyConfig {
            bandersnatch_hex: "0x5e465beb01dbafe160ce8216047f2155dd0569f058afd52dcea601025a8d161d",
            ed25519_hex: "0x3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29",
        },
        GenesisValidatorKeyConfig {
            bandersnatch_hex: "0x3d5e5a51aab2b048f8686ecd79712a80e3265a114cc73f14bdb2a59233fb66d0",
            ed25519_hex: "0x22351e22105a19aabb42589162ad7f1ea0df1c25cebf0e4a9fcd261301274862",
        },
        GenesisValidatorKeyConfig {
            bandersnatch_hex: "0xaa2b95f7572875b0d0f186552ae745ba8222fc0b5bd456554bfe51c68938f8bc",
            ed25519_hex: "0xe68e0cf7f26c59f963b5846202d2327cc8bc0c4eff8cb9abd4012f9a71decf00",
        },
        GenesisValidatorKeyConfig {
            bandersnatch_hex: "0x7f6190116d118d643a98878e294ccf62b509e214299931aad8ff9764181a4e33",
            ed25519_hex: "0xb3e0e096b02e2ec98a3441410aeddd78c95e27a0da6f411a09c631c0f2bea6e9",
        },
        GenesisValidatorKeyConfig {
            bandersnatch_hex: "0x48e5fcdce10e0b64ec4eebd0d9211c7bac2f27ce54bca6f7776ff6fee86ab3e3",
            ed25519_hex: "0x5c7f34a4bd4f2d04076a8c6f9060a0c8d2c6bdd082ceb3eda7df381cb260faff",
        },
        GenesisValidatorKeyConfig {
            bandersnatch_hex: "0xf16e5352840afb47e206b5c89f560f2611835855cf2e6ebad1acc9520a72591d",
            ed25519_hex: "0x837ce344bc9defceb0d7de7e9e9925096768b7adb4dad932e532eb6551e0ea02",
        },
    ];

    create_genesis_block_header(DEFAULT_VALIDATOR_CONFIGS, u16::MAX)
}
