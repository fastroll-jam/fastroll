pub(crate) mod gas_cost_model;
pub(crate) mod gas_cost_tables;
pub(crate) mod register_usage;

use crate::{
    error::VMCoreError, program::types::program_state::ProgramState, state::vm_state::VMState,
};
use fr_common::{SignedGas, UnsignedGas};
use fr_pvm_types::common::RegValue;

pub struct GasCharger;
impl GasCharger {
    /// Charges the gas of the basic block that holds the instruction at `pc` (0-based, in octets) unless it is already charged, as in `Ψ_1`.
    ///
    /// Returns `false` for out-of-gas when the gas counter is below the gas cost of the basic block that holds `pc`. The gas counter and the gas-charged flag then stay unchanged.
    pub fn charge_basic_block_gas(
        vm_state: &mut VMState,
        program_state: &ProgramState,
        pc: usize,
    ) -> Result<bool, VMCoreError> {
        if vm_state.is_basic_block_gas_charged {
            return Ok(true);
        }
        let basic_block_gas_cost = program_state
            .basic_block_gas_cost_at(pc)
            .ok_or(VMCoreError::InvalidPCVal(pc as RegValue))?;
        let Ok(basic_block_gas_cost) = SignedGas::try_from(basic_block_gas_cost) else {
            return Ok(false);
        };
        if vm_state.gas_counter < basic_block_gas_cost {
            return Ok(false);
        }
        vm_state.gas_counter -= basic_block_gas_cost;
        vm_state.is_basic_block_gas_charged = true;
        Ok(true)
    }

    /// Deducts gas counter of `VMState` with the given `gas_charge`, returning the posterior gas
    /// which could be negative on out-of-gas error.
    #[inline(always)]
    pub fn apply_gas_cost(
        vm_state: &mut VMState,
        gas_charge: UnsignedGas,
    ) -> Result<SignedGas, VMCoreError> {
        let gas_charge_signed: SignedGas = gas_charge
            .try_into()
            .map_err(|_| VMCoreError::TooLargeGasCharge(gas_charge))?;
        vm_state.gas_counter = vm_state
            .gas_counter
            .checked_sub(gas_charge_signed)
            .ok_or(VMCoreError::GasCounterOverflow)?;
        Ok(vm_state.gas_counter)
    }
}
