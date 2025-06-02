use crate::{error::VMCoreError, state::vm_state::VMState};
use fr_common::{SignedGas, UnsignedGas};

pub struct GasCharger;
impl GasCharger {
    /// Deducts gas counter of `VMState` with the given `gas_charge`, returning the posterior gas
    /// which could be negative on out-of-gas error.
    pub fn apply_gas_cost(
        vm_state: &mut VMState,
        gas_charge: UnsignedGas,
    ) -> Result<SignedGas, VMCoreError> {
        let gas_charge_signed: SignedGas = gas_charge
            .try_into()
            .map_err(|_| VMCoreError::TooLargeGasCharge(gas_charge))?;
        vm_state
            .gas_counter
            .checked_sub(gas_charge_signed)
            .ok_or(VMCoreError::GasCounterOverflow)?;
        Ok(vm_state.gas_counter)
    }
}
