use crate::{BeefyRoot, BlockHeaderHash, StateRoot, TimeslotIndex, WorkPackageHash};
use fr_codec::prelude::*;
use std::{
    collections::BTreeSet,
    fmt::{Display, Formatter},
};

/// Context of the blockchain at the point of evaluation of the report's corresponding work-package.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RefinementContext {
    /// `a`: Anchor block header hash
    pub anchor_header_hash: BlockHeaderHash,
    /// `n`: Anchor block timeslot index
    pub anchor_timeslot: TimeslotIndex,
    /// `s`: Anchor block posterior state root
    pub anchor_state_root: StateRoot,
    /// `b`: Anchor block posterior BEEFY root
    pub anchor_beefy_root: BeefyRoot,
    /// `l`: Lookup anchor block header hash
    pub lookup_anchor_header_hash: BlockHeaderHash,
    /// `t`: Lookup anchor block timeslot index
    pub lookup_anchor_timeslot: TimeslotIndex,
    /// `r`: Lookup anchor block posterior state root
    pub lookup_anchor_state_root: StateRoot,
    /// **`p`**: Set of prerequisite work package hash
    pub prerequisite_work_packages: BTreeSet<WorkPackageHash>,
}

impl Display for RefinementContext {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "RefineContext {{ anchor_header_hash: {}, anchor_timeslot: {}, anchor_state_root: {} beefy_root: {}, lookup_anchor_header_hash: {}, \
            lookup_anchor_timeslot: {}, lookup_anchor_state_root: {}
        ", self.anchor_header_hash, self.anchor_timeslot, self.anchor_state_root, self.anchor_beefy_root, self.lookup_anchor_header_hash, self.lookup_anchor_timeslot, self.lookup_anchor_state_root)?;
        if self.prerequisite_work_packages.is_empty() {
            writeln!(f, "  prerequisites: []}}")?;
        } else {
            writeln!(f, "  prerequisites: [")?;
            for wp_hash in self.prerequisite_work_packages.iter() {
                writeln!(f, "    {}", wp_hash)?;
            }
            writeln!(f, "  ]}}")?;
        }
        Ok(())
    }
}

impl JamEncode for RefinementContext {
    fn size_hint(&self) -> usize {
        self.anchor_header_hash.size_hint()
            + 4
            + self.anchor_state_root.size_hint()
            + self.anchor_beefy_root.size_hint()
            + self.lookup_anchor_header_hash.size_hint()
            + 4
            + self.lookup_anchor_state_root.size_hint()
            + self.prerequisite_work_packages.size_hint()
    }

    fn encode_to<T: JamOutput>(&self, dest: &mut T) -> Result<(), JamCodecError> {
        self.anchor_header_hash.encode_to(dest)?;
        self.anchor_timeslot.encode_to_fixed(dest, 4)?;
        self.anchor_state_root.encode_to(dest)?;
        self.anchor_beefy_root.encode_to(dest)?;
        self.lookup_anchor_header_hash.encode_to(dest)?;
        self.lookup_anchor_timeslot.encode_to_fixed(dest, 4)?;
        self.lookup_anchor_state_root.encode_to(dest)?;
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
            anchor_header_hash: BlockHeaderHash::decode(input)?,
            anchor_timeslot: TimeslotIndex::decode_fixed(input, 4)?,
            anchor_state_root: StateRoot::decode(input)?,
            anchor_beefy_root: BeefyRoot::decode(input)?,
            lookup_anchor_header_hash: BlockHeaderHash::decode(input)?,
            lookup_anchor_timeslot: TimeslotIndex::decode_fixed(input, 4)?,
            lookup_anchor_state_root: StateRoot::decode(input)?,
            prerequisite_work_packages: BTreeSet::<WorkPackageHash>::decode(input)?,
        })
    }
}
