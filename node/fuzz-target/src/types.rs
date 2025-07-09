//! JAM fuzzing test message types

use fr_block::types::block::{Block, BlockHeader};
use fr_codec::prelude::*;
use fr_common::{ByteArray, ByteSequence, Hash32, STATE_KEY_SIZE};
use std::fmt::{Display, Formatter};

pub type TrieKey = ByteArray<STATE_KEY_SIZE>;
pub type HeaderHash = Hash32;
pub type StateRootHash = Hash32;

#[derive(Clone, Debug, JamEncode, JamDecode)]
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

impl Version {
    pub fn new(major: u8, minor: u8, patch: u8) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }
}

#[derive(Clone, Debug, JamEncode, JamDecode)]
pub struct PeerInfo {
    pub name: Vec<u8>,
    pub app_version: Version,
    pub jam_version: Version,
}

impl PeerInfo {
    pub fn new(name: String, app_version: Version, jam_version: Version) -> Self {
        Self {
            name: name.into_bytes(),
            app_version,
            jam_version,
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

#[derive(Clone, Debug, JamEncode, JamDecode)]
pub struct ImportBlock(pub Block);

#[derive(Clone, Debug, JamEncode, JamDecode)]
pub struct SetState {
    pub header: BlockHeader,
    pub state: State,
}

#[derive(Clone, Debug, JamEncode, JamDecode)]
pub struct GetState(pub HeaderHash);

#[derive(Clone, Debug, JamEncode, JamDecode)]
pub struct StateRoot(pub StateRootHash);

/// The fuzzing protocol message
#[derive(Debug)]
pub enum FuzzMessageKind {
    PeerInfo(PeerInfo),       // Sender: Fuzzer & Target
    ImportBlock(ImportBlock), // Sender: Fuzzer
    SetState(SetState),       // Sender: Fuzzer
    GetState(GetState),       // Sender: Fuzzer
    State(State),             // Sender: Target
    StateRoot(StateRoot),     // Sender: Target
}

impl JamEncode for FuzzMessageKind {
    fn size_hint(&self) -> usize {
        let variant_size = match self {
            Self::PeerInfo(msg) => msg.size_hint(),
            Self::ImportBlock(msg) => msg.size_hint(),
            Self::SetState(msg) => msg.size_hint(),
            Self::GetState(msg) => msg.size_hint(),
            Self::State(msg) => msg.size_hint(),
            Self::StateRoot(msg) => msg.size_hint(),
        };
        1 + variant_size
    }

    fn encode_to<T: JamOutput>(&self, dest: &mut T) -> Result<(), JamCodecError> {
        let (msg_id, msg_encoded) = match self {
            Self::PeerInfo(msg) => (0u8, msg.encode()?),
            Self::ImportBlock(msg) => (1u8, msg.encode()?),
            Self::SetState(msg) => (2u8, msg.encode()?),
            Self::GetState(msg) => (3u8, msg.encode()?),
            Self::State(msg) => (4u8, msg.encode()?),
            Self::StateRoot(msg) => (5u8, msg.encode()?),
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
            2 => Ok(Self::SetState(SetState::decode(input)?)),
            3 => Ok(Self::GetState(GetState::decode(input)?)),
            4 => Ok(Self::State(State::decode(input)?)),
            5 => Ok(Self::StateRoot(StateRoot::decode(input)?)),
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

// FIXME: probably redundant?
impl JamDecode for FuzzProtocolMessage {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError>
    where
        Self: Sized,
    {
        Ok(Self {
            msg_length: u32::decode_fixed(input, 4)?,
            kind: FuzzMessageKind::decode(input)?,
        })
    }
}

impl FuzzProtocolMessage {
    pub fn from_kind(kind: FuzzMessageKind) -> Result<Self, JamCodecError> {
        let encoded = kind.encode()?;
        let msg_length = encoded.len() as u32;
        Ok(Self { msg_length, kind })
    }
}
