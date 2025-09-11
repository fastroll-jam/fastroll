use crate::{
    impl_simple_state_component,
    state_utils::{SimpleStateComponent, StateComponent, StateEntryType, StateKeyConstant},
};
use fr_codec::prelude::*;
use fr_common::{ServiceId, UnsignedGas, CORE_COUNT};
use fr_limited_vec::FixedVec;
use std::{
    collections::BTreeMap,
    fmt::{Display, Formatter},
};

pub type AssignServices = FixedVec<ServiceId, CORE_COUNT>;
pub type AlwaysAccumulateServices = BTreeMap<ServiceId, UnsignedGas>;

/// Identifier of services that are allowed to conduct privileged state transitions,
/// along with metadata of the always-accumulate services.
///
/// Represents `χ` of the GP.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PrivilegedServices {
    /// `M`: A privileged service that can alter privileged services state.
    pub manager_service: ServiceId,
    /// `A`: Privileged services that can alter the auth queue, one for each core.
    pub assign_services: AssignServices,
    /// `V`: A privileged service that can alter the staging validator set (`ι`).
    pub designate_service: ServiceId,
    /// `R`: A privileged service that can create new services with small IDs in the protected range.
    pub registrar_service: ServiceId,
    /// `Z`: A mapping of always-accumulate services and their basic gas usages.
    pub always_accumulate_services: AlwaysAccumulateServices,
}
impl_simple_state_component!(PrivilegedServices, PrivilegedServices);

impl Display for PrivilegedServices {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        writeln!(f, "PrivilegedService {{")?;
        writeln!(f, "  manager: {}", self.manager_service)?;
        writeln!(f, "  assign: [")?;
        for s in self.assign_services.iter() {
            writeln!(f, "    {s},")?;
        }
        writeln!(f, "  ]")?;
        writeln!(f, "  designate: {}", self.designate_service)?;
        writeln!(f, "  registrar: {}", self.registrar_service)?;
        writeln!(f, "  always_accumulate: [")?;
        for (s, g) in self.always_accumulate_services.iter() {
            writeln!(f, "    (service={s}, gas={g}),")?;
        }
        writeln!(f, "  ]")?;
        write!(f, "}}")
    }
}

impl JamEncode for PrivilegedServices {
    fn size_hint(&self) -> usize {
        4 + 4 * CORE_COUNT + 4 + 4 + self.always_accumulate_services.size_hint()
    }

    fn encode_to<T: JamOutput>(&self, dest: &mut T) -> Result<(), JamCodecError> {
        self.manager_service.encode_to_fixed(dest, 4)?;
        for assign_service in &self.assign_services {
            assign_service.encode_to_fixed(dest, 4)?;
        }
        self.designate_service.encode_to_fixed(dest, 4)?;
        self.registrar_service.encode_to_fixed(dest, 4)?;
        self.always_accumulate_services.encode_to(dest)?;
        Ok(())
    }
}

impl JamDecode for PrivilegedServices {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError>
    where
        Self: Sized,
    {
        let manager_service = ServiceId::decode_fixed(input, 4)?;
        let mut assign_services_vec = Vec::with_capacity(CORE_COUNT);
        for _ in 0..CORE_COUNT {
            let assign_service = ServiceId::decode_fixed(input, 4)?;
            assign_services_vec.push(assign_service);
        }
        let assign_services = AssignServices::try_from(assign_services_vec)
            .expect("assign_services_vec should have length of 2");
        let designate_service = ServiceId::decode_fixed(input, 4)?;
        let registrar_service = ServiceId::decode_fixed(input, 4)?;
        let always_accumulate_services = AlwaysAccumulateServices::decode(input)?;

        Ok(Self {
            manager_service,
            assign_services,
            designate_service,
            registrar_service,
            always_accumulate_services,
        })
    }
}
