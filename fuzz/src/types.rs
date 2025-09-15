//! JAM fuzzing test message types

use fr_block::types::block::{Block, BlockHeader};
use fr_codec::prelude::*;
use fr_common::{ByteArray, ByteSequence, Hash32, Octets, TimeslotIndex, STATE_KEY_SIZE};
use fr_limited_vec::LimitedVec;
use fr_test_utils::importer_harness::AsnRawState;
use std::{
    error::Error,
    fmt::{Display, Formatter},
    str::FromStr,
};

pub type TrieKey = ByteArray<STATE_KEY_SIZE>;
pub type HeaderHash = Hash32;
pub type StateRootHash = Hash32;
pub type FuzzError = String;

#[derive(Clone, Debug, PartialEq, JamEncode, JamDecode)]
pub struct Version {
    pub major: u8,
    pub minor: u8,
    pub patch: u8,
}

impl Display for Version {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl FromStr for Version {
    type Err = Box<dyn Error>;

    fn from_str(version: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = version.split('.').collect();
        if parts.len() != 3 {
            panic!("Invalid version format: expected `major.minor.patch`, got `{version}`",);
        }

        let major = parts[0].parse::<u8>().expect("Invalid major version");
        let minor = parts[1].parse::<u8>().expect("Invalid minor version");
        let patch = parts[2].parse::<u8>().expect("Invalid patch version");
        Ok(Self {
            major,
            minor,
            patch,
        })
    }
}

impl Version {
    pub fn new(major: u8, minor: u8, patch: u8) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }
}

#[derive(Clone, Debug, PartialEq, JamEncode, JamDecode)]
pub struct PeerInfo {
    pub fuzz_version: u8,
    pub fuzz_features: u8,
    pub jam_version: Version,
    pub app_version: Version,
    pub app_name: Vec<u8>,
}

impl PeerInfo {
    pub fn new(
        fuzz_version: u8,
        fuzz_features: u8,
        jam_version: Version,
        app_version: Version,
        app_name: String,
    ) -> Self {
        Self {
            fuzz_version,
            fuzz_features,
            jam_version,
            app_version,
            app_name: app_name.into_bytes(),
        }
    }
}

#[derive(Clone, Debug, JamEncode, JamDecode)]
pub struct KeyValue {
    pub key: TrieKey,
    pub value: ByteSequence,
}

#[derive(Clone, Debug, JamEncode, JamDecode)]
pub struct State(pub Vec<KeyValue>);

/// Convert ASN raw state type into fuzzer-specific state type
impl From<AsnRawState> for State {
    fn from(value: AsnRawState) -> Self {
        Self(
            value
                .keyvals
                .into_iter()
                .map(|asn_kv| KeyValue {
                    key: asn_kv.key,
                    value: asn_kv.value,
                })
                .collect(),
        )
    }
}

#[derive(Clone, Debug, JamEncode, JamDecode)]
pub struct AncestryItem {
    slot: TimeslotIndex,
    header_hash: HeaderHash,
}

pub type Ancestry = LimitedVec<AncestryItem, 24>;

#[derive(Clone, Debug, JamEncode, JamDecode)]
pub struct ImportBlock(pub Block);

#[derive(Clone, Debug, JamEncode, JamDecode)]
pub struct Initialize {
    pub header: BlockHeader,
    pub state: State,
    pub ancestry: Ancestry,
}

#[derive(Clone, Debug, JamEncode, JamDecode)]
pub struct GetState(pub HeaderHash);

#[derive(Clone, Debug, JamEncode, JamDecode)]
pub struct StateRoot(pub StateRootHash);

/// The fuzzing protocol message
#[derive(Debug)]
pub enum FuzzMessageKind {
    PeerInfo(PeerInfo),       // Sender: Fuzzer & Target
    Initialize(Initialize),   // Sender: Fuzzer
    StateRoot(StateRoot),     // Sender: Target
    ImportBlock(ImportBlock), // Sender: Fuzzer
    GetState(GetState),       // Sender: Fuzzer
    State(State),             // Sender: Target
    Error(FuzzError),         // Sender: Target
}

impl JamEncode for FuzzMessageKind {
    fn size_hint(&self) -> usize {
        let variant_size = match self {
            Self::PeerInfo(msg) => msg.size_hint(),
            Self::Initialize(msg) => msg.size_hint(),
            Self::StateRoot(msg) => msg.size_hint(),
            Self::ImportBlock(msg) => msg.size_hint(),
            Self::GetState(msg) => msg.size_hint(),
            Self::State(msg) => msg.size_hint(),
            Self::Error(err_msg) => err_msg.len(),
        };
        1 + variant_size
    }

    fn encode_to<T: JamOutput>(&self, dest: &mut T) -> Result<(), JamCodecError> {
        let (msg_id, msg_encoded) = match self {
            Self::PeerInfo(msg) => (0u8, msg.encode()?),
            Self::Initialize(msg) => (1u8, msg.encode()?),
            Self::StateRoot(msg) => (2u8, msg.encode()?),
            Self::ImportBlock(msg) => (3u8, msg.encode()?),
            Self::GetState(msg) => (4u8, msg.encode()?),
            Self::State(msg) => (5u8, msg.encode()?),
            Self::Error(err_msg) => (255u8, err_msg.clone().into_bytes()),
        };

        dest.push_byte(msg_id);
        dest.write(&msg_encoded);
        Ok(())
    }
}

impl JamDecode for FuzzMessageKind {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError>
    where
        Self: Sized,
    {
        let msg_id = input.read_byte()?;
        match msg_id {
            0 => Ok(Self::PeerInfo(PeerInfo::decode(input)?)),
            1 => Ok(Self::ImportBlock(ImportBlock::decode(input)?)),
            2 => Ok(Self::Initialize(Initialize::decode(input)?)),
            3 => Ok(Self::GetState(GetState::decode(input)?)),
            4 => Ok(Self::State(State::decode(input)?)),
            5 => Ok(Self::StateRoot(StateRoot::decode(input)?)),
            255 => {
                let len = input.remaining_len();
                let value = Octets::decode_fixed(input, len)?;
                Ok(Self::Error(FuzzError::from_utf8_lossy(&value).into_owned()))
            }
            _ => Err(JamCodecError::InputError("Unknown message id".to_string())),
        }
    }
}

pub struct FuzzProtocolMessage {
    pub msg_length: u32,
    pub kind: FuzzMessageKind,
}

impl JamEncode for FuzzProtocolMessage {
    fn size_hint(&self) -> usize {
        4 + self.kind.size_hint()
    }

    fn encode_to<T: JamOutput>(&self, dest: &mut T) -> Result<(), JamCodecError> {
        self.msg_length.encode_to_fixed(dest, 4)?;
        self.kind.encode_to(dest)?;
        Ok(())
    }
}

impl FuzzProtocolMessage {
    pub fn from_kind(kind: FuzzMessageKind) -> Result<Self, JamCodecError> {
        let encoded = kind.encode()?;
        let msg_length = encoded.len() as u32;
        Ok(Self { msg_length, kind })
    }
}
