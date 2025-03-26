use crate::invoke_results::AccumulationGasPairs;
use rjam_common::{workloads::WorkReport, ServiceId, UnsignedGas};
use std::collections::{HashMap, HashSet};

pub type OnTransferStats = HashMap<ServiceId, OnTransferStatsEntry>;

pub struct OnTransferStatsEntry {
    pub transfers_count: u32,
    pub gas_used: UnsignedGas,
}

#[allow(dead_code)]
struct AccumulateStatsEntry {
    gas_used: UnsignedGas,
    reports_count: u32,
}

#[allow(dead_code)]
pub struct AccumulateStats {
    inner: HashMap<ServiceId, AccumulateStatsEntry>,
}

impl AccumulateStats {
    pub fn from_accumulated_reports(
        reports: &[WorkReport],
        gas_pairs: &AccumulationGasPairs,
    ) -> Self {
        let mut inner = HashMap::new();
        let service_ids = gas_pairs.iter().map(|e| e.service).collect::<HashSet<_>>();
        let service_reports_counts: HashMap<ServiceId, usize> = reports
            .iter()
            .flat_map(|wr| wr.results.clone())
            .fold(HashMap::new(), |mut map, result| {
                let service_reports_count = map.entry(result.service_id).or_default();
                *service_reports_count += 1;
                map
            });
        let service_gas_counts: HashMap<ServiceId, UnsignedGas> =
            gas_pairs.iter().fold(HashMap::new(), |mut map, pair| {
                let service_gas_count = map.entry(pair.service).or_default();
                *service_gas_count += pair.gas;
                map
            });

        for service_id in service_ids {
            inner.insert(
                service_id,
                AccumulateStatsEntry {
                    gas_used: service_gas_counts
                        .get(&service_id)
                        .cloned()
                        .expect("Should exist"),
                    reports_count: service_reports_counts
                        .get(&service_id)
                        .cloned()
                        .expect("Should exist") as u32,
                },
            );
        }
        Self { inner }
    }
}
