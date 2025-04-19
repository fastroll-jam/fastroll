use crate::{
    impl_simple_state_component,
    state_utils::{SimpleStateComponent, StateComponent, StateEntryType, StateKeyConstant},
};
use rjam_block::types::extrinsics::preimages::PreimagesXtEntry;
use rjam_codec::{
    JamCodecError, JamDecode, JamDecodeFixed, JamEncode, JamEncodeFixed, JamInput, JamOutput,
};
use rjam_common::{
    workloads::RefineStats, CoreIndex, ServiceId, UnsignedGas, ValidatorIndex, CORE_COUNT,
    VALIDATOR_COUNT,
};
use std::{
    collections::BTreeMap,
    ops::{Deref, DerefMut},
};

/// The on-chain activity statistics for validators, cores and services.
/// Validator statistics is tracked in a per-epoch basis, whereas cores and services statistics is
/// tracked in a per-block basis.
///
/// Represents `π` of the GP.
#[derive(Clone, Debug, Default, PartialEq, Eq, JamEncode, JamDecode)]
pub struct OnChainStatistics {
    pub validator_stats: ValidatorStats,
    /// `π_C`: Per-block core statistics.
    pub core_stats: CoreStats,
    /// `π_S`: Per-block service statistics.
    pub service_stats: ServiceStats,
}
impl_simple_state_component!(OnChainStatistics, OnChainStatistics);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ValidatorStatsEntry {
    /// `b`: The number of blocks produced by the validator.
    pub blocks_produced_count: u32,
    /// `t`: The number of tickets introduced by the validator.
    pub tickets_count: u32,
    /// `p`: The number of preimages introduced by the validator.
    pub preimages_count: u32,
    /// `d`: The total number of octets across all preimages introduced by the validator.
    pub preimage_data_octets_count: u32,
    /// `g`: The number of reports guaranteed by the validator.
    pub guarantees_count: u32,
    /// `a`: The number of availability assurances made by the validator.
    pub assurances_count: u32,
}

impl JamEncode for ValidatorStatsEntry {
    fn size_hint(&self) -> usize {
        4 * 6
    }

    fn encode_to<T: JamOutput>(&self, dest: &mut T) -> Result<(), JamCodecError> {
        self.blocks_produced_count.encode_to_fixed(dest, 4)?;
        self.tickets_count.encode_to_fixed(dest, 4)?;
        self.preimages_count.encode_to_fixed(dest, 4)?;
        self.preimage_data_octets_count.encode_to_fixed(dest, 4)?;
        self.guarantees_count.encode_to_fixed(dest, 4)?;
        self.assurances_count.encode_to_fixed(dest, 4)?;
        Ok(())
    }
}

impl JamDecode for ValidatorStatsEntry {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError>
    where
        Self: Sized,
    {
        Ok(Self {
            blocks_produced_count: u32::decode_fixed(input, 4)?,
            tickets_count: u32::decode_fixed(input, 4)?,
            preimages_count: u32::decode_fixed(input, 4)?,
            preimage_data_octets_count: u32::decode_fixed(input, 4)?,
            guarantees_count: u32::decode_fixed(input, 4)?,
            assurances_count: u32::decode_fixed(input, 4)?,
        })
    }
}

/// Holds statistics for all validator activities during a single epoch.
/// Each entry tracks activities such as block production, ticket introduction, and assurances.
///
/// This structure is used both to accumulate statistics for the current epoch
/// and to store completed statistics for the previous epoch.
#[derive(Clone, Debug, PartialEq, Eq, JamEncode, JamDecode)]
pub struct EpochValidatorStats {
    items: Box<[ValidatorStatsEntry; VALIDATOR_COUNT]>,
}

impl Deref for EpochValidatorStats {
    type Target = [ValidatorStatsEntry];

    fn deref(&self) -> &Self::Target {
        &*self.items
    }
}

impl DerefMut for EpochValidatorStats {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut *self.items
    }
}

impl Default for EpochValidatorStats {
    fn default() -> Self {
        Self {
            items: Box::new([ValidatorStatsEntry::default(); VALIDATOR_COUNT]),
        }
    }
}

impl EpochValidatorStats {
    pub fn new(items: Box<[ValidatorStatsEntry; VALIDATOR_COUNT]>) -> Self {
        Self { items }
    }

    pub fn validator_stats(&self, validator_index: ValidatorIndex) -> &ValidatorStatsEntry {
        &self.items[validator_index as usize]
    }

    pub fn validator_stats_mut(
        &mut self,
        validator_index: ValidatorIndex,
    ) -> &mut ValidatorStatsEntry {
        &mut self.items[validator_index as usize]
    }
}

/// The validator activities statistics recorded on-chain, on a per-epoch basis.
///
/// It maintains two records:
/// - `curr` (`π_V`): Accumulates statistics for the current epoch.
/// - `prev` (`π_L`): Stores the statistics from the previous epoch.
#[derive(Clone, Debug, Default, PartialEq, Eq, JamEncode, JamDecode)]
pub struct ValidatorStats {
    pub curr: EpochValidatorStats,
    pub prev: EpochValidatorStats,
}

impl ValidatorStats {
    pub fn current_epoch_stats(&self) -> &EpochValidatorStats {
        &self.curr
    }

    pub fn current_epoch_stats_mut(&mut self) -> &mut EpochValidatorStats {
        &mut self.curr
    }

    pub fn current_epoch_validator_stats_mut(
        &mut self,
        validator_index: ValidatorIndex,
    ) -> &mut ValidatorStatsEntry {
        self.current_epoch_stats_mut()
            .validator_stats_mut(validator_index)
    }

    pub fn previous_epoch_stats(&self) -> &EpochValidatorStats {
        &self.prev
    }

    pub fn replace_previous_epoch_stats(&mut self, new_epoch_stats: EpochValidatorStats) {
        self.prev = new_epoch_stats
    }

    pub fn clear_current_epoch_stats(&mut self) {
        self.curr = EpochValidatorStats::default()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, JamEncode, JamDecode)]
pub struct CoreStatsEntry {
    /// `i`: The number of imported segments in the core.
    pub imports_count: u16,
    /// `x`: The number of extrinsics items used in the core.
    pub extrinsics_count: u16,
    /// `z`: The total size of extrinsics used in the core, in octets.
    pub extrinsics_octets: u32,
    /// `e`: The number of exported segments in the core.
    pub exports_count: u16,
    /// `u`: The actual amount of gas used during refinement in the core.
    pub refine_gas_used: UnsignedGas,
    /// `b`: Auditable work bundle length.
    pub work_bundle_length: u32,
    /// `d`: The size of items placed in the Audit DA and the Import DA by available work reports in the core.
    pub da_items_size: u32,
    /// `p`: The number of assurers who attested availability for a work report in the core.
    pub assurers_count: u16,
}

impl CoreStatsEntry {
    pub fn accumulate_refine_stats(&mut self, refine_stats: &RefineStats) {
        self.imports_count += refine_stats.imports_count;
        self.extrinsics_count += refine_stats.extrinsics_count;
        self.extrinsics_octets += refine_stats.extrinsics_octets;
        self.exports_count += refine_stats.exports_count;
        self.refine_gas_used += refine_stats.refine_gas_used;
    }
}

/// The core activities statistics recorded on-chain, on a per-block basis.
#[derive(Clone, Debug, Default, PartialEq, Eq, JamEncode, JamDecode)]
pub struct CoreStats(pub Box<[CoreStatsEntry; CORE_COUNT]>);

impl CoreStats {
    pub fn core_stats_entry_mut(&mut self, core_index: CoreIndex) -> &mut CoreStatsEntry {
        &mut self.0[core_index as usize]
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, JamEncode, JamDecode)]
pub struct ServiceStatsEntry {
    /// `i`: The number of imported segments by the service.
    pub imports_count: u16,
    /// `x`: The number of extrinsics items used by the service.
    pub extrinsics_count: u16,
    /// `z`: The total size of extrinsics used by the service, in octets.
    pub extrinsics_octets: u32,
    /// `e`: The number of exported segments by the service.
    pub exports_count: u16,
    /// `r.0`: The number of work digests associated with the service.
    pub work_digests_count: u16,
    /// `r.1`: The actual amount of gas used during refinement of the service.
    pub refine_gas_used: UnsignedGas,
    /// `p.0`: The number of preimage extrinsics introduced in the block, requested by the service.
    pub preimage_xts_count: u16,
    /// `p.1`: The total size of preimage extrinsics introduced in the block, requested by the service.
    pub preimage_blob_size: u32,
    /// `a.0`: The total amount of gas used in the block by accumulation of the service.
    pub accumulate_gas_used: UnsignedGas,
    /// `a.1`: The number of accumulated reports in the block by the service.
    pub accumulate_reports_count: u32,
    /// `t.0`: The number of transfers to the service in the block.
    pub on_transfer_transfers_count: u32,
    /// `t.1`: The total amount of gas used in the block by transfers to the service.
    pub on_transfer_gas_used: UnsignedGas,
}

impl ServiceStatsEntry {
    pub fn accumulate_refine_stats(&mut self, refine_stats: &RefineStats) {
        self.imports_count += refine_stats.imports_count;
        self.extrinsics_count += refine_stats.extrinsics_count;
        self.extrinsics_octets += refine_stats.extrinsics_octets;
        self.exports_count += refine_stats.exports_count;
        self.refine_gas_used += refine_stats.refine_gas_used;
        self.work_digests_count += 1;
    }

    pub fn add_preimage_load(&mut self, preimage: &PreimagesXtEntry) {
        self.preimage_xts_count += 1;
        self.preimage_blob_size += preimage.preimage_data.len() as u32
    }
}

/// The service activities statistics recorded on-chain, on a per-block basis.
#[derive(Clone, Debug, Default, PartialEq, Eq, JamEncode, JamDecode)]
pub struct ServiceStats(pub BTreeMap<ServiceId, ServiceStatsEntry>);

impl ServiceStats {
    pub fn service_stats_entry_mut(&mut self, service_id: ServiceId) -> &mut ServiceStatsEntry {
        self.0.entry(service_id).or_default()
    }
}
