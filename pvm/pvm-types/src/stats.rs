use crate::{invoke_args::DeferredTransfer, invoke_results::AccumulationGasPairs};
use fr_common::{workloads::WorkReport, ServiceId, UnsignedGas};
use std::{collections::HashMap, ops::Deref};

/// Accumulation statistics of a single service (`S(s)`), recorded as `a` of its service statistics.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct AccumulateStatsEntry {
    /// `N(s)`: The number of accumulated work-digests of the service.
    pub digests_count: u32,
    /// `T(s)`: The number of processed deferred transfers whose destination is the service.
    pub transfers_count: u32,
    /// `G(s)`: The total amount of gas used by accumulation of the service.
    pub gas_used: UnsignedGas,
}

/// Accumulation statistics of a block (`I`), built from the outer accumulation `Δ+` and recorded into the service statistics `π_S`.
#[derive(Default)]
pub struct AccumulateStats {
    inner: HashMap<ServiceId, AccumulateStatsEntry>,
}

impl Deref for AccumulateStats {
    type Target = HashMap<ServiceId, AccumulateStatsEntry>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl AccumulateStats {
    /// Aggregates `S(s) = (N(s), T(s), G(s))` per service from the outputs of `Δ+`.
    /// Services with `S(s) = (0, 0, 0)` are omitted.
    pub fn from_outer_accumulation(
        accumulated_reports: &[WorkReport],       // R*[..n]
        service_gas_pairs: &AccumulationGasPairs, // u
        processed_transfers: &[DeferredTransfer], // t
    ) -> Self {
        let mut inner: HashMap<ServiceId, AccumulateStatsEntry> = HashMap::new();
        for digest in accumulated_reports.iter().flat_map(|wr| wr.digests.iter()) {
            inner.entry(digest.service_id).or_default().digests_count += 1;
        }
        for transfer in processed_transfers {
            inner.entry(transfer.to).or_default().transfers_count += 1;
        }
        for pair in service_gas_pairs {
            inner.entry(pair.service).or_default().gas_used += pair.gas;
        }
        // A service can have gas pairs with zero gas but no digests or transfers (e.g. an always-accumulate service without code)
        inner.retain(|_, entry| *entry != AccumulateStatsEntry::default());
        Self { inner }
    }
}

#[cfg(test)]
mod accumulate_stats_tests {
    use super::*;
    use crate::invoke_results::AccumulationGasPair;
    use fr_common::workloads::{RefineStats, WorkDigest, WorkDigests, WorkExecutionResult};
    use std::error::Error;

    fn work_report(service_ids: &[ServiceId]) -> WorkReport {
        let digests = service_ids
            .iter()
            .map(|&service_id| WorkDigest {
                service_id,
                service_code_hash: Default::default(),
                payload_hash: Default::default(),
                accumulate_gas_limit: 0,
                refine_result: WorkExecutionResult::ok_empty(),
                refine_stats: RefineStats::default(),
            })
            .collect::<Vec<_>>();
        WorkReport {
            digests: WorkDigests::try_from(digests).expect("too many digests"),
            ..Default::default()
        }
    }

    fn transfer(to: ServiceId) -> DeferredTransfer {
        DeferredTransfer {
            from: 0,
            to,
            amount: 10,
            memo: Default::default(),
            gas_limit: 100,
        }
    }

    fn gas_pair(service: ServiceId, gas: UnsignedGas) -> AccumulationGasPair {
        AccumulationGasPair { service, gas }
    }

    fn accumulate_stats_entry(
        digests_count: u32,
        transfers_count: u32,
        gas_used: UnsignedGas,
    ) -> AccumulateStatsEntry {
        AccumulateStatsEntry {
            digests_count,
            transfers_count,
            gas_used,
        }
    }

    #[test]
    fn test_aggregates_digests_transfers_and_gas_per_service() -> Result<(), Box<dyn Error>> {
        let stats = AccumulateStats::from_outer_accumulation(
            &[work_report(&[1, 2, 1]), work_report(&[1])],
            &vec![gas_pair(1, 30), gas_pair(2, 5), gas_pair(1, 20)],
            &[transfer(2), transfer(2)],
        );

        assert_eq!(stats.len(), 2);
        assert_eq!(stats[&1], accumulate_stats_entry(3, 0, 50));
        assert_eq!(stats[&2], accumulate_stats_entry(1, 2, 5));
        Ok(())
    }

    #[test]
    fn test_records_transfer_only_service() -> Result<(), Box<dyn Error>> {
        let stats =
            AccumulateStats::from_outer_accumulation(&[], &vec![gas_pair(3, 0)], &[transfer(3)]);

        assert_eq!(stats[&3], accumulate_stats_entry(0, 1, 0));
        Ok(())
    }

    #[test]
    fn test_omits_service_with_zero_stats() -> Result<(), Box<dyn Error>> {
        let stats = AccumulateStats::from_outer_accumulation(&[], &vec![gas_pair(4, 0)], &[]);

        assert!(stats.is_empty());
        Ok(())
    }
}
