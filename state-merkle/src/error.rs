use rjam_codec::JamCodecError;
use rjam_crypto::CryptoError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StateMerkleError {
    #[error("Cache size must be larger than zero")]
    CacheSizeNonPositive,
    #[error("Invalid node type with hash")]
    InvalidNodeType,
    #[error("State not initialized")]
    EmptyState,
    #[error("Node codec error")]
    NodeCodecError,
    #[error("Node not found")]
    NodeNotFound,
    #[error("Invalid byte length")]
    InvalidByteLength(usize),
    #[error("Invalid bitvec length")]
    InvalidBitVecLength(usize),
    #[error("Invalid BitVec slice range")]
    InvalidBitVecSliceRange,
    #[error("Invalid node data length")]
    InvalidNodeDataLength(usize),
    #[error("Invalid input for conversion to Hash32 type")]
    InvalidHash32Input,
    #[error("Write batch lock error")]
    WriteBatchLockError,
    #[error("RocksDB error: {0}")]
    RocksDBError(#[from] rocksdb::Error),
    #[error("CryptoError: {0}")]
    CryptoError(#[from] CryptoError),
    #[error("JamCodec error: {0}")]
    JamCodecError(#[from] JamCodecError),
}
