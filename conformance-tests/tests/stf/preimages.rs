//! Preimages state transition conformance tests
use async_trait::async_trait;
use fr_asn_types::preimages::*;
use fr_block::{header_db::BlockHeaderDB, types::block::BlockHeader};
use fr_common::LookupsKey;
use fr_conformance_tests::{
    err_map::preimages::map_error_to_custom_code,
    generate_typed_tests,
    harness::{run_test_case, StateTransitionTest},
};
use fr_state::{error::StateManagerError, manager::StateManager, types::Timeslot};
use fr_transition::{
    error::TransitionError,
    state::{services::transition_services_integrate_preimages, timeslot::transition_timeslot},
};
use futures::future::join_all;
use std::sync::Arc;

struct PreimagesTest;

#[async_trait]
impl StateTransitionTest for PreimagesTest {
    const PATH_PREFIX: &'static str = "jamtestvectors-polkajam/stf/preimages/tiny";

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
            for preimage in &account.data.preimages {
                let key = &preimage.hash;
                let val = PreimagesMapEntry::from(preimage.clone()).data;
                state_manager
                    .add_account_preimages_entry(account.id, key, val)
                    .await?;
            }
            // Add lookups entries
            for lookup in &account.data.lookup_meta {
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
        error_code: &Option<Self::ErrorCode>,
    ) -> Result<Self::State, StateManagerError> {
        if error_code.is_some() {
            // Rollback state transition
            return Ok(pre_state.clone());
        }

        // Get the posterior state from the state cache.
        let curr_accounts = join_all(pre_state.accounts.iter().map(|s| async {
            let curr_preimages = join_all(s.data.preimages.iter().map(|e| async {
                // Get the key from the pre-state
                let key = e.hash.clone();
                // Get the posterior preimage value
                let preimage = state_manager
                    .get_account_preimages_entry(s.id, &key)
                    .await
                    .unwrap()
                    .unwrap();
                AsnPreimagesMapEntry::from(PreimagesMapEntry {
                    key,
                    data: preimage,
                })
            }))
            .await;

            let curr_lookups = join_all(s.data.lookup_meta.iter().map(|e| async {
                // Get the key from the pre-state
                let key = LookupsKey::from(e.key.clone());
                // Get the posterior lookups value
                let lookups = state_manager
                    .get_account_lookups_entry(s.id, &key)
                    .await
                    .unwrap()
                    .unwrap();
                AsnLookupMetaMapEntry::from(LookupMetaMapEntry { key, data: lookups })
            }))
            .await;

            AsnAccountsMapEntry {
                id: s.id,
                data: AsnAccount {
                    preimages: curr_preimages,
                    lookup_meta: curr_lookups,
                },
            }
        }))
        .await;

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

    // FIXME: Need information of all preimage keys of a service account.
    // Success
    // Provide one solicited blob.
    // preimage_needed_2: "preimage_needed-2.json",

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

    // FIXME: Need information of all preimage keys of a service account.
    // Success
    // Order is correct.
    // preimages_order_check_3: "preimages_order_check-3.json",

    // Fail
    // Duplicate item.
    preimages_order_check_4: "preimages_order_check-4.json",
}
