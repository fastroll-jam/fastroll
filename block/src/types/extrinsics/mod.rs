use crate::types::extrinsics::{
    assurances::AssurancesXt, disputes::DisputesXt, guarantees::GuaranteesXt,
    preimages::PreimagesXt, tickets::TicketsXt,
};
use fr_codec::prelude::*;
use fr_common::{Hash32, XtHash, HASH_SIZE};
use fr_crypto::{
    error::CryptoError,
    hash::{hash, Blake2b256},
};
use fr_db::core::cached_db::{CacheItem, CacheItemCodecError};
use thiserror::Error;

pub mod assurances;
pub mod disputes;
pub mod guarantees;
pub mod preimages;
pub mod tickets;

#[derive(Debug, Error)]
pub enum ExtrinsicsError {
    #[error("Credential for the validator index already exists")]
    DuplicateValidatorIndex,
    #[error("Invalid number of credentials. Must have either 2 or 3 credentials")]
    InvalidCredentialCount,
    #[error("JamCodecError: {0}")]
    JamCodecError(#[from] JamCodecError),
    #[error("CryptoError: {0}")]
    CryptoError(#[from] CryptoError),
}

#[derive(Clone, Ord, PartialOrd, PartialEq, Eq)]
pub enum XtType {
    Ticket,
    Guarantee,
    Assurance,
    PreimageLookup,
    Verdict,
    Culprit,
    Fault,
}

pub trait XtEntry: JamEncode + JamDecode {
    const XT_TYPE: XtType;

    fn hash(&self) -> Result<Hash32, ExtrinsicsError> {
        Ok(hash::<Blake2b256>(&self.encode()?)?)
    }
}

/// Struct used for Extrinsics serialization
#[derive(Debug, Clone, Default, PartialEq, Eq, JamEncode, JamDecode)]
pub struct Extrinsics {
    pub tickets: TicketsXt,
    pub preimages: PreimagesXt,
    pub guarantees: GuaranteesXt,
    pub assurances: AssurancesXt,
    pub disputes: DisputesXt,
}

impl CacheItem for Extrinsics {
    fn into_db_value(self) -> Result<Vec<u8>, CacheItemCodecError> {
        Ok(self.encode()?)
    }

    fn from_db_kv(_key: &[u8], val: Vec<u8>) -> Result<Self, CacheItemCodecError>
    where
        Self: Sized,
    {
        Ok(Self::decode(&mut val.as_slice())?)
    }
}

impl Extrinsics {
    pub fn hash(&self) -> Result<XtHash, ExtrinsicsError> {
        let mut buf = Vec::with_capacity(HASH_SIZE * 5);
        hash::<Blake2b256>(&self.tickets.encode()?)?.encode_to(&mut buf)?;
        hash::<Blake2b256>(&self.preimages.encode()?)?.encode_to(&mut buf)?;
        hash::<Blake2b256>(&self.guarantees.encode_with_hashed_reports()?)?.encode_to(&mut buf)?;
        hash::<Blake2b256>(&self.assurances.encode()?)?.encode_to(&mut buf)?;
        hash::<Blake2b256>(&self.disputes.encode()?)?.encode_to(&mut buf)?;
        Ok(hash::<Blake2b256>(&buf)?)
    }
}
