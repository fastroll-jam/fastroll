use jam_codec::JamEncode;
use jam_common::{AccountAddress, Hash32, UnsignedGas};
use jam_crypto::utils::octets_to_hash32;
use jam_host_interface::contexts::{AccumulateContext, AccumulateContextPair, InvocationContext};
use jam_pvm::{CommonInvocationResult, PVM};
use jam_pvm_core::types::{
    accumulation::AccumulateOperand,
    error::{
        HostCallError::{AccountNotFound, InvalidContext},
        PVMError,
    },
};
use jam_types::state::services::ServiceAccounts;

pub enum AccumulateResult {
    Unchanged,
    Result(AccumulateContext, Option<Hash32>), // (mutated context, optional result hash)
}

struct PVMInvocation;

impl PVMInvocation {
    //
    // PVM invocation entry-points
    //

    /// Accumulate invocation function
    ///
    /// # Arguments
    ///
    /// * `service_accounts` - The current global state of service accounts, after preimage integration but before accumulation
    /// * `target_address` - The address of the target service account to run the accumulation process
    /// * `gas_limit` - The maximum amount of gas allowed for the accumulation operation
    /// * `operands` - A vector of `AccumulateOperand`s, which are the outputs from the refinement process to be accumulated
    ///
    /// Represents `Psi_A` of the GP
    pub fn accumulate(
        service_accounts: &ServiceAccounts,
        target_address: AccountAddress,
        gas_limit: UnsignedGas,
        operands: Vec<AccumulateOperand>,
    ) -> Result<AccumulateResult, PVMError> {
        let target_account = service_accounts
            .get_account(&target_address)
            .ok_or(PVMError::HostCallError(AccountNotFound))?
            .clone();

        let code = target_account.get_code().cloned();

        if operands.is_empty() || code.is_none() {
            return Ok(AccumulateResult::Unchanged);
        }

        // `x` for a regular dimension and `y` for an exceptional dimension
        let context_pair = AccumulateContextPair {
            x: AccumulateContext::initialize_context(
                service_accounts,
                &target_account,
                target_address,
            )?,
            y: AccumulateContext::initialize_context(
                service_accounts,
                &target_account,
                target_address,
            )?,
        };

        let mut context = InvocationContext::X_A(context_pair);

        let common_invocation_result = PVM::common_invocation(
            target_address,
            &code.unwrap()[..],
            2,
            gas_limit,
            &operands.encode()?,
            &mut context,
        )?;

        let AccumulateContextPair { x, y } = if let InvocationContext::X_A(pair) = context {
            pair
        } else {
            return Err(PVMError::HostCallError(InvalidContext));
        };

        match common_invocation_result {
            CommonInvocationResult::Result((_gas, output))
            | CommonInvocationResult::ResultUnavailable((_gas, output)) => {
                Ok(AccumulateResult::Result(x, octets_to_hash32(output)))
            }

            CommonInvocationResult::OutOfGas(_) | CommonInvocationResult::Failure(_) => {
                Ok(AccumulateResult::Result(y, None))
            }
        }
    }
}
