use crate::{
    error::{PVMError, VMCoreError::TooLargeGasCounter},
    state::vm_state::VMState,
};
use rjam_common::{SignedGas, UnsignedGas};

pub struct GasCharger;
impl GasCharger {
    /// Deducts gas counter of `VMState` with the given `gas_charge`, returning the posterior gas
    /// which could be negative on out-of-gas error.
    pub fn apply_gas_cost(
        vm_state: &mut VMState,
        gas_charge: UnsignedGas,
    ) -> Result<SignedGas, PVMError> {
        let gas_counter_signed: SignedGas = vm_state
            .gas_counter
            .try_into()
            .map_err(|_| PVMError::VMCoreError(TooLargeGasCounter))?;
        let post_gas = gas_counter_signed - gas_charge as SignedGas;

        // Keep `gas_counter` of `VMState` as unsigned integer
        vm_state.gas_counter = vm_state.gas_counter.saturating_sub(gas_charge);
        Ok(post_gas)
    }
}
