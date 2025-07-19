use crate::invoke_results::AccumulationGasPairs;
use fr_common::{workloads::WorkReport, ServiceId, UnsignedGas};
use std::{
    collections::{HashMap, HashSet},
    ops::Deref,
};

pub type OnTransferStats = HashMap<ServiceId, OnTransferStatsEntry>;

#[derive(Default)]
pub struct OnTransferStatsEntry {
    pub transfers_count: u32,
    pub gas_used: UnsignedGas,
}

#[derive(Default)]
pub struct AccumulateStatsEntry {
    pub gas_used: UnsignedGas,
    pub digests_count: u32,
}

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
    pub fn from_accumulated_reports(
        reports: &[WorkReport],
        gas_pairs: &AccumulationGasPairs,
    ) -> Self {
        let mut inner = HashMap::new();
        let service_digests_counts: HashMap<ServiceId, usize> = reports
            .iter()
            .flat_map(|wr| wr.digests.clone())
            .fold(HashMap::new(), |mut map, digest| {
                let service_digests_count = map.entry(digest.service_id).or_default();
                *service_digests_count += 1;
                map
            });
        let service_gas_counts: HashMap<ServiceId, UnsignedGas> =
            gas_pairs.iter().fold(HashMap::new(), |mut map, pair| {
                let service_gas_count = map.entry(pair.service).or_default();
                *service_gas_count += pair.gas;
                map
            });
        let service_ids: HashSet<ServiceId> = service_digests_counts
            .keys()
            .cloned()
            .chain(service_gas_counts.keys().cloned())
            .collect();

        for service_id in service_ids {
            inner.insert(
                service_id,
                AccumulateStatsEntry {
                    gas_used: service_gas_counts
                        .get(&service_id)
                        .cloned()
                        .expect("Should exist"),
                    digests_count: service_digests_counts
                        .get(&service_id)
                        .cloned()
                        .expect("Should exist") as u32,
                },
            );
        }
        Self { inner }
    }
}
