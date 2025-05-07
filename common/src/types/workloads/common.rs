use crate::Hash32;
use fr_codec::prelude::*;
use std::{
    collections::BTreeSet,
    fmt::{Display, Formatter},
};

/// Context of the blockchain at the point of evaluation of the report's corresponding work-package.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RefinementContext {
    /// `a`: Anchor block header hash
    pub anchor_header_hash: Hash32,
    /// `s`: Anchor block posterior state root
    pub anchor_state_root: Hash32,
    /// `b`: Anchor block posterior BEEFY root
    pub beefy_root: Hash32,
    /// `l`: Lookup anchor block header hash
    pub lookup_anchor_header_hash: Hash32,
    /// `t`: Lookup anchor block timeslot index
    pub lookup_anchor_timeslot: u32,
    /// **`p`**: Set of prerequisite work package hash
    pub prerequisite_work_packages: BTreeSet<Hash32>,
}

impl Display for RefinementContext {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "RefineContext: {{ anchor_header_hash: {}, anchor_state_root: {} beefy_root: {}, lookup_anchor_header_hash: {},\
            lookup_anchor_timeslot: {}
        ", self.anchor_header_hash, self.anchor_state_root, self.beefy_root, self.lookup_anchor_header_hash, self.lookup_anchor_timeslot)?;
        if self.prerequisite_work_packages.is_empty() {
            write!(f, "  prerequisites: []}}")?;
        } else {
            write!(f, "  prerequisites: [")?;
            for wp_hash in self.prerequisite_work_packages.iter() {
                write!(f, "    {}", &wp_hash)?;
            }
            write!(f, "  ]}}")?;
        }
        Ok(())
    }
}

impl JamEncode for RefinementContext {
    fn size_hint(&self) -> usize {
        self.anchor_header_hash.size_hint()
            + self.anchor_state_root.size_hint()
            + self.beefy_root.size_hint()
            + self.lookup_anchor_header_hash.size_hint()
            + 4
            + self.prerequisite_work_packages.size_hint()
    }

    fn encode_to<T: JamOutput>(&self, dest: &mut T) -> Result<(), JamCodecError> {
        self.anchor_header_hash.encode_to(dest)?;
        self.anchor_state_root.encode_to(dest)?;
        self.beefy_root.encode_to(dest)?;
        self.lookup_anchor_header_hash.encode_to(dest)?;
        self.lookup_anchor_timeslot.encode_to_fixed(dest, 4)?;
        self.prerequisite_work_packages.encode_to(dest)?;
        Ok(())
    }
}

impl JamDecode for RefinementContext {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError>
    where
        Self: Sized,
    {
        Ok(Self {
            anchor_header_hash: Hash32::decode(input)?,
            anchor_state_root: Hash32::decode(input)?,
            beefy_root: Hash32::decode(input)?,
            lookup_anchor_header_hash: Hash32::decode(input)?,
            lookup_anchor_timeslot: u32::decode_fixed(input, 4)?,
            prerequisite_work_packages: BTreeSet::<Hash32>::decode(input)?,
        })
    }
}
