//! Preimages state transition integration tests
use async_trait::async_trait;
use fr_asn_types::preimages::*;
use fr_block::{header_db::BlockHeaderDB, types::block::BlockHeader};
use fr_common::{LookupsKey, PreimagesKey};
use fr_state::{error::StateManagerError, manager::StateManager, types::Timeslot};
use fr_test_utils::{
    err_map::preimages::map_error_to_custom_code,
    generate_typed_tests,
    stf_harness::{run_test_case, StateTransitionTest},
};
use fr_transition::{
    error::TransitionError,
    state::{services::transition_services_integrate_preimages, timeslot::transition_timeslot},
};
use std::{collections::BTreeSet, sync::Arc};

struct PreimagesTest;

#[async_trait]
impl StateTransitionTest for PreimagesTest {
    const PATH_PREFIX: &'static str = "jamtestvectors-polkajam/stf/preimages";

    type Input = Input;
    type JamInput = JamInput;
    type State = State;
    type JamTransitionOutput = ();
    type Output = Output;
    type ErrorCode = PreimagesErrorCode;

    async fn load_pre_state(
        test_pre_state: &Self::State,
        state_manager: Arc<StateManager>,
    ) -> Result<(), StateManagerError> {
        // Convert ASN pre-state into FastRoll types and load pre-state info the state cache.
        for account in &test_pre_state.accounts {
            // Add preimages entries
            for preimage in &account.data.preimage_blobs {
                let key = &preimage.hash;
                let val = PreimagesMapEntry::from(preimage.clone()).data;
                state_manager
                    .add_account_preimages_entry(account.id, key, val)
                    .await?;
            }
            // Add lookups entries
            for lookup in &account.data.preimage_requests {
                state_manager
                    .add_account_lookups_entry(
                        account.id,
                        LookupsKey::from(lookup.key.clone()),
                        LookupMetaMapEntry::from(lookup.clone()).data,
                    )
                    .await?;
            }
        }

        // Additionally, initialize the timeslot state cache
        state_manager.add_timeslot(Timeslot::new(0)).await?;

        Ok(())
    }

    fn convert_input_type(test_input: &Self::Input) -> Result<Self::JamInput, TransitionError> {
        // Convert ASN Input into FastRoll types.
        Ok(JamInput {
            extrinsic: test_input.preimages.clone().into(),
            slot: Timeslot::new(test_input.slot),
        })
    }

    async fn run_state_transition(
        state_manager: Arc<StateManager>,
        _header_db: Arc<BlockHeaderDB>,
        _new_header: &mut BlockHeader,
        jam_input: Self::JamInput,
    ) -> Result<Self::JamTransitionOutput, TransitionError> {
        // Run state transitions.
        transition_timeslot(state_manager.clone(), &jam_input.slot).await?;
        transition_services_integrate_preimages(state_manager, &jam_input.extrinsic).await
    }

    fn map_error_code(e: TransitionError) -> Self::ErrorCode {
        map_error_to_custom_code(e)
    }

    fn extract_output(
        _new_header: &BlockHeader,
        _transition_output: Option<&Self::JamTransitionOutput>,
        error_code: &Option<Self::ErrorCode>,
    ) -> Self::Output {
        if let Some(error_code) = error_code {
            return Output::err(error_code.clone());
        }
        Output::ok
    }

    async fn extract_post_state(
        state_manager: Arc<StateManager>,
        pre_state: &Self::State,
        test_case_post_state: &Self::State,
        error_code: &Option<Self::ErrorCode>,
    ) -> Result<Self::State, StateManagerError> {
        if error_code.is_some() {
            // Rollback state transition
            return Ok(pre_state.clone());
        }

        // Get the posterior state from the state cache.
        // A state key holds only a hash of the item key, so the harness cannot list the entries of an account.
        // The transition only adds or updates entries, so it reads the keys of the prior and the expected posterior account.
        let mut curr_accounts = Vec::with_capacity(pre_state.accounts.len());
        for prior_account in &pre_state.accounts {
            let service_id = prior_account.id;
            let prior_and_expected_accounts = pre_state
                .accounts
                .iter()
                .chain(&test_case_post_state.accounts)
                .filter(|account| account.id == service_id);
            let preimage_keys: BTreeSet<PreimagesKey> = prior_and_expected_accounts
                .clone()
                .flat_map(|account| &account.data.preimage_blobs)
                .map(|entry| entry.hash.clone())
                .collect();
            let lookups_keys: BTreeSet<LookupsKey> = prior_and_expected_accounts
                .flat_map(|account| &account.data.preimage_requests)
                .map(|entry| LookupsKey::from(entry.key.clone()))
                .collect();

            let mut curr_preimages = Vec::with_capacity(preimage_keys.len());
            for key in preimage_keys {
                if let Some(data) = state_manager
                    .get_account_preimages_entry(service_id, &key)
                    .await?
                {
                    curr_preimages
                        .push(AsnPreimagesMapEntry::from(PreimagesMapEntry { key, data }));
                }
            }

            let mut curr_lookups = Vec::with_capacity(lookups_keys.len());
            for key in lookups_keys {
                if let Some(data) = state_manager
                    .get_account_lookups_entry(service_id, &key)
                    .await?
                {
                    curr_lookups.push(AsnLookupMetaMapEntry::from(LookupMetaMapEntry {
                        key,
                        data,
                    }));
                }
            }

            curr_accounts.push(AsnAccountsMapEntry {
                id: service_id,
                data: AsnAccount {
                    preimage_blobs: curr_preimages,
                    preimage_requests: curr_lookups,
                },
            });
        }

        Ok(State {
            accounts: curr_accounts,
        })
    }
}

generate_typed_tests! {
    PreimagesTest,

    // Success
    // Nothing is provided.
    preimage_needed_1: "preimage_needed-1.json",

    // Success
    // Provide one solicited blob.
    preimage_needed_2: "preimage_needed-2.json",

    // Fail
    // Provide two blobs, but one of them has not been solicited.
    preimage_not_needed_1: "preimage_not_needed-1.json",

    // Fail
    // Provide two blobs, but one of them has already been provided.
    preimage_not_needed_2: "preimage_not_needed-2.json",

    // Fail
    // Bad order of services.
    preimages_order_check_1: "preimages_order_check-1.json",

    // Fail
    // Bad order of images for a service.
    preimages_order_check_2: "preimages_order_check-2.json",

    // Success
    // Order is correct.
    preimages_order_check_3: "preimages_order_check-3.json",

    // Fail
    // Duplicate item.
    preimages_order_check_4: "preimages_order_check-4.json",
}
