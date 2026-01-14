use fr_block::types::extrinsics::tickets::TicketsXt;
use fr_common::{TimeslotIndex, EPOCH_LENGTH};
use fr_crypto::{
    types::{BandersnatchRingRoot, Ed25519PubKey, ValidatorKey, ValidatorKeySet, ValidatorKeys},
    vrf::bandersnatch_vrf::RingVrfVerifier,
};
use fr_node::genesis::load_genesis_validator_set;
use fr_state::{
    cache::StateMut,
    error::StateManagerError,
    manager::{RingContext, StateManager},
    test_utils::init_db_and_manager,
    types::{
        ActiveSet, DisputesState, EpochEntropy, PastSet, SafroleState, SlotSealers, StagingSet,
        TicketAccumulator, Timeslot, ValidatorSet,
    },
};
use fr_transition::{
    ring_cache::{compute_effective_staging_set_hash, schedule_ring_cache_update},
    state::{safrole::transition_safrole, timeslot::transition_timeslot},
};
use std::{convert::TryFrom, error::Error, path::PathBuf, sync::Arc, time::Duration};
use tempfile::tempdir;
use tokio::time::{sleep, Instant};

const WAIT_TIMEOUT: Duration = Duration::from_secs(20);
const WAIT_POLL_INTERVAL: Duration = Duration::from_millis(30);

fn genesis_validator_set() -> ValidatorKeySet {
    load_genesis_validator_set()
}

fn rotate_validator_set(set: &ValidatorKeySet) -> ValidatorKeySet {
    let mut validators: Vec<ValidatorKey> = set.0.clone().into();
    validators.rotate_left(1);
    ValidatorKeySet(ValidatorKeys::try_from(validators).unwrap())
}

fn compute_ring_root(set: &ValidatorKeySet) -> BandersnatchRingRoot {
    use fr_crypto::vrf::bandersnatch_vrf::RingVrfVerifier;
    let verifier = RingVrfVerifier::new(set).unwrap();
    verifier.compute_ring_root().unwrap()
}

fn build_ring_context(
    inserted_at: TimeslotIndex,
    staging_set: &StagingSet,
    punish_set: &[Ed25519PubKey],
) -> RingContext {
    let mut effective_set = staging_set.clone();
    effective_set.nullify_punished_validators(punish_set);
    let verifier = RingVrfVerifier::new(&effective_set).unwrap();
    let ring_root = verifier.compute_ring_root().unwrap();
    RingContext {
        inserted_at,
        validator_set: (*effective_set).clone(),
        verifier,
        ring_root,
    }
}

struct RingCacheHarness {
    manager: Arc<StateManager>,
    genesis_validator_set: ValidatorKeySet,
}

impl RingCacheHarness {
    async fn new(temp_path: PathBuf) -> Result<Self, StateManagerError> {
        let (_header_db, manager) = init_db_and_manager(temp_path);
        let manager = Arc::new(manager);
        let genesis_validator_set = genesis_validator_set();

        manager.add_timeslot(Timeslot::new(0)).await?;
        manager
            .add_staging_set(StagingSet(genesis_validator_set.clone()))
            .await?;
        manager
            .add_active_set(ActiveSet(genesis_validator_set.clone()))
            .await?;
        manager
            .add_past_set(PastSet(genesis_validator_set.clone()))
            .await?;
        manager.add_disputes(DisputesState::default()).await?;
        manager.add_epoch_entropy(EpochEntropy::default()).await?;
        manager
            .add_safrole(SafroleState {
                pending_set: genesis_validator_set.clone(),
                ring_root: BandersnatchRingRoot::default(),
                slot_sealers: SlotSealers::default(),
                ticket_accumulator: TicketAccumulator::default(),
            })
            .await?;

        Ok(Self {
            manager,
            genesis_validator_set,
        })
    }

    fn manager(&self) -> Arc<StateManager> {
        self.manager.clone()
    }

    fn genesis_validator_set(&self) -> ValidatorKeySet {
        self.genesis_validator_set.clone()
    }

    async fn set_timeslot(&self, slot: TimeslotIndex) -> Result<(), Box<dyn Error>> {
        transition_timeslot(self.manager(), &Timeslot::new(slot)).await?;
        Ok(())
    }

    async fn set_safrole_pending_set(
        &self,
        pending_set: &ValidatorKeySet,
    ) -> Result<(), Box<dyn Error>> {
        let pending_clone = pending_set.clone();
        self.manager
            .with_mut_safrole(
                StateMut::Update,
                move |safrole| -> Result<(), StateManagerError> {
                    safrole.pending_set = pending_clone.clone();
                    Ok(())
                },
            )
            .await?;
        Ok(())
    }

    /// Mocks `StagingSet` STF at the given timeslot without invoking `accumulate`.
    async fn transition_staging_set(
        &self,
        timeslot_index: TimeslotIndex,
        new_staging_set: &ValidatorKeySet,
    ) -> Result<(), Box<dyn Error>> {
        let punish_set = self.manager.get_disputes().await?.punish_set;
        let new_staging_set_cloned = new_staging_set.clone();
        let staging_set = StagingSet(new_staging_set_cloned.clone());
        let staging_set_hash = compute_effective_staging_set_hash(&staging_set, &punish_set)?;
        schedule_ring_cache_update(
            self.manager.clone(),
            timeslot_index,
            staging_set.clone(),
            punish_set,
            staging_set_hash.clone(),
        );

        self.manager
            .with_mut_staging_set(
                StateMut::Update,
                move |staging| -> Result<(), StateManagerError> {
                    *staging = StagingSet(new_staging_set_cloned);
                    Ok(())
                },
            )
            .await?;

        self.manager
            .update_last_staging_set_transition_context(timeslot_index, staging_set_hash);

        Ok(())
    }

    /// Waits until the `RingCache.staging` entry is updated with the expected timeslot value
    /// and returns the update `RingContext`.
    ///
    /// Here, we're polling and observing the `RingCache` state since the `RingVRFVerifier`
    /// computation runs in a dedicated blocking thread.
    async fn wait_for_staging_cache_entry_update(
        &self,
        expected_timeslot: TimeslotIndex,
    ) -> RingContext {
        let timeout = Instant::now() + WAIT_TIMEOUT;
        loop {
            if let Some(staging) = self.manager.ring_cache_snapshot().1 {
                if staging.inserted_at == expected_timeslot {
                    return staging;
                }
            }

            if Instant::now() >= timeout {
                panic!("timed out waiting for staging cache entry at slot {expected_timeslot}");
            }
            sleep(WAIT_POLL_INTERVAL).await;
        }
    }
}

/// Verifies that `curr` ring cache entries are reused for the following ticket validations,
/// without redundant recomputations.
///
/// Note: Since ticket validation happens right after the epoch-progressing STF, it should be always
/// getting the `curr` entry from the cache rather than re-building in general.
#[tokio::test]
async fn ring_cache_reuses_curr_entry_within_epoch() -> Result<(), Box<dyn Error>> {
    let _temp_dir = tempdir().unwrap();
    let db_path = _temp_dir.path().join("ring_cache_test");
    let harness = RingCacheHarness::new(db_path).await?;
    let manager = harness.manager();
    let genesis_set = harness.genesis_validator_set();
    let epoch0_last_slot = (EPOCH_LENGTH - 1) as TimeslotIndex;

    // Set state values
    harness.set_timeslot(epoch0_last_slot).await?;
    harness
        .transition_staging_set(epoch0_last_slot, &genesis_set)
        .await?;
    harness
        .wait_for_staging_cache_entry_update(epoch0_last_slot)
        .await;

    // Run STFs: epoch progress (epoch #0 -> epoch #1)
    manager.commit_and_rotate_ring_cache(); // Ring cache rotation

    let first_slot_epoch1 = epoch0_last_slot + 1;
    harness.set_timeslot(first_slot_epoch1).await?;
    harness.set_safrole_pending_set(&genesis_set).await?;

    // -- Mocking TicketsXt validation (calls `get_or_generate_curr_ring_context`)

    // First lookup after the rotation
    let (_verifier, ring_root) = manager
        .get_or_generate_curr_ring_context(first_slot_epoch1, &genesis_set)
        .await?;
    assert_eq!(ring_root, compute_ring_root(&genesis_set));

    // Check RingCache.curr is already there (`inserted_at` != first_slot_epoch1)
    let (curr, _staging) = manager.ring_cache_snapshot();
    assert_eq!(curr.as_ref().unwrap().inserted_at, epoch0_last_slot);

    // Second lookup ensures that the same cached verifier / root are reused without recomputation
    let (_verifier, ring_root_cached) = manager
        .get_or_generate_curr_ring_context(first_slot_epoch1, &genesis_set)
        .await?;
    assert_eq!(ring_root_cached, ring_root);

    // RingCache.curr should still hold the same entry
    let (curr, _staging) = manager.ring_cache_snapshot();
    assert_eq!(curr.as_ref().unwrap().inserted_at, epoch0_last_slot);

    Ok(())
}

/// If `StagingSet` gets transitioned multiple times within an epoch, we should be using the
/// Ring context (speculatively) constructed from the latest version of the `StagingSet`.
#[tokio::test]
async fn ring_cache_kept_updated_on_multiple_staging_set_transitions() -> Result<(), Box<dyn Error>>
{
    let _temp_dir = tempdir().unwrap();
    let db_path = _temp_dir.path().join("ring_cache_test");
    let harness = RingCacheHarness::new(db_path).await?;
    let manager = harness.manager();
    let genesis_set = harness.genesis_validator_set();
    let epoch0_last_slot = (EPOCH_LENGTH - 1) as TimeslotIndex;

    // Set state values
    harness.set_timeslot(epoch0_last_slot).await?;
    harness
        .transition_staging_set(epoch0_last_slot, &genesis_set)
        .await?;
    harness
        .wait_for_staging_cache_entry_update(epoch0_last_slot)
        .await;
    manager.commit_and_rotate_ring_cache();
    harness.set_safrole_pending_set(&genesis_set).await?;

    let rotated_set = rotate_validator_set(&genesis_set);
    let staging_set_transitioned_at = epoch0_last_slot + 3;
    harness.set_timeslot(staging_set_transitioned_at).await?;
    harness
        .transition_staging_set(staging_set_transitioned_at, &rotated_set)
        .await?;
    harness
        .wait_for_staging_cache_entry_update(staging_set_transitioned_at)
        .await;

    let epoch1_last_slot = (EPOCH_LENGTH * 2 - 1) as TimeslotIndex;
    harness.set_timeslot(epoch1_last_slot).await?;
    manager.commit_and_rotate_ring_cache();
    harness.set_safrole_pending_set(&rotated_set).await?;

    let epoch2_first_slot = epoch1_last_slot + 1;
    let (_verifier, ring_root) = manager
        .get_or_generate_staging_ring_context(epoch2_first_slot, &rotated_set)
        .await?;

    // Ring root should match the last staged `StagingSet`
    assert_ne!(ring_root, compute_ring_root(&genesis_set));
    assert_eq!(ring_root, compute_ring_root(&rotated_set));

    Ok(())
}

/// When an offender's key appears in the cached `StagingSet`, we expect it to be
/// replaced with the null key and the ring root to be recomputed accordingly.
#[tokio::test]
async fn ring_cache_nullifies_offenders_from_staging_entry() -> Result<(), Box<dyn Error>> {
    let _temp_dir = tempdir().unwrap();
    let db_path = _temp_dir.path().join("ring_cache_test");
    let harness = RingCacheHarness::new(db_path).await?;
    let manager = harness.manager();
    let genesis_set = harness.genesis_validator_set();
    let staging_slot = 5;

    // Set state values
    harness.set_timeslot(staging_slot).await?;
    harness
        .transition_staging_set(staging_slot, &genesis_set)
        .await?;
    let staging_entry = harness
        .wait_for_staging_cache_entry_update(staging_slot)
        .await;

    let offender_key = staging_entry.validator_set[0].ed25519.clone();
    // The ring root be recomputed here
    manager.nullify_offenders_from_staging_ring_cache(std::slice::from_ref(&offender_key))?;

    let (_curr, staging) = manager.ring_cache_snapshot();
    let new_staging_entry = staging.expect("staging cache should exist");

    // Check nullified
    assert_eq!(new_staging_entry.validator_set[0], ValidatorKey::default());

    let mut validator_set_with_punishment = staging_entry.validator_set.clone();
    validator_set_with_punishment.nullify_punished_validators(&[offender_key]);
    assert_eq!(
        new_staging_entry.ring_root,
        compute_ring_root(&validator_set_with_punishment)
    );
    assert_ne!(new_staging_entry.ring_root, compute_ring_root(&genesis_set));

    Ok(())
}

/// Rejects stale ring-cache updates when same-slot forks differ only in the punish set.
#[tokio::test]
async fn ring_cache_rejects_stale_update_on_same_slot_punish_set_fork() -> Result<(), Box<dyn Error>>
{
    let _temp_dir = tempdir().unwrap();
    let db_path = _temp_dir.path().join("ring_cache_sync_test");
    let harness = RingCacheHarness::new(db_path).await?;
    let manager = harness.manager();
    let staging_set = manager.get_staging_set().await?;
    let timeslot = 7;

    harness.set_timeslot(timeslot).await?;

    let punish_set_a: Vec<Ed25519PubKey> = Vec::new();
    let hash_a = compute_effective_staging_set_hash(&staging_set, &punish_set_a)?;
    manager.update_last_staging_set_transition_context(timeslot, hash_a.clone());

    let ring_context_a = build_ring_context(timeslot, &staging_set, &punish_set_a);

    let offender_key = staging_set[0].ed25519.clone();
    let punish_set_b = vec![offender_key];
    manager
        .with_mut_disputes(
            StateMut::Update,
            |disputes| -> Result<(), StateManagerError> {
                disputes.punish_set = punish_set_b.clone();
                Ok(())
            },
        )
        .await?;
    let hash_b = compute_effective_staging_set_hash(&staging_set, &punish_set_b)?;
    manager.update_last_staging_set_transition_context(timeslot, hash_b.clone());

    manager.update_staging_ring_cache_entry_guarded(ring_context_a, hash_a);

    let (_curr, staging) = manager.ring_cache_snapshot();
    assert!(staging.is_none(), "stale update should be rejected");

    Ok(())
}

/// `StagingSet` transition (by accumulation) at the first block of the new epoch should not
/// affect the per-epoch transition of the ring context. The posterior value of `StagingValue`
/// will be staged for the future.
#[tokio::test]
async fn ring_cache_staging_set_transition_at_epoch_boundary_1() -> Result<(), Box<dyn Error>> {
    let _temp_dir = tempdir().unwrap();
    let db_path = _temp_dir.path().join("ring_cache_test");
    let harness = RingCacheHarness::new(db_path).await?;
    let manager = harness.manager();
    let first_staging_set = rotate_validator_set(&harness.genesis_validator_set());

    let epoch0_last_slot = (EPOCH_LENGTH - 1) as TimeslotIndex;
    let epoch1_first_slot = epoch0_last_slot + 1;

    // `StagingSet` transition at `epoch0_last_slot`
    harness.set_timeslot(epoch0_last_slot).await?;
    harness
        .transition_staging_set(epoch0_last_slot, &first_staging_set)
        .await?;
    harness
        .wait_for_staging_cache_entry_update(epoch0_last_slot)
        .await;
    manager.commit_and_rotate_ring_cache();
    harness.set_safrole_pending_set(&first_staging_set).await?;

    let (_verifier_epoch1, ring_root_epoch1) = manager
        .get_or_generate_staging_ring_context(epoch1_first_slot, &first_staging_set)
        .await?;
    assert_eq!(ring_root_epoch1, compute_ring_root(&first_staging_set));

    let next_staging_set = rotate_validator_set(&first_staging_set);

    // `StagingSet` transition at `epoch1_first_slot` (should not be considered)
    harness.set_timeslot(epoch1_first_slot).await?;
    harness
        .transition_staging_set(epoch1_first_slot, &next_staging_set)
        .await?;
    harness
        .wait_for_staging_cache_entry_update(epoch1_first_slot)
        .await;

    let (curr, _staging) = manager.ring_cache_snapshot();
    assert_eq!(curr.as_ref().unwrap().ring_root, ring_root_epoch1);

    manager.commit_and_rotate_ring_cache();
    harness.set_safrole_pending_set(&next_staging_set).await?;
    let second_epoch_slot = epoch1_first_slot + EPOCH_LENGTH as u32;
    let (_verifier_epoch2, ring_root_epoch2) = manager
        .get_or_generate_staging_ring_context(second_epoch_slot, &next_staging_set)
        .await?;
    assert_eq!(ring_root_epoch2, compute_ring_root(&next_staging_set));

    Ok(())
}

/// Tests "rotate-before-async-ring-cache-update-job-finishes" case.
///
/// On epoch progress, if `StagingSet` transition (by accumulation) at the last block of the previous
/// epoch triggered speculative build of `RingVrfVerifier` but the task has not been finished yet,
/// users of `RingVrfVerifier` should get the correct current `RingVrfVerifier` anyway.
#[tokio::test]
async fn ring_cache_staging_set_transition_at_epoch_boundary_2() -> Result<(), Box<dyn Error>> {
    let _temp_dir = tempdir().unwrap();
    let db_path = _temp_dir.path().join("ring_cache_test");
    let harness = RingCacheHarness::new(db_path).await?;
    let manager = harness.manager();
    let updated_staging_set = rotate_validator_set(&harness.genesis_validator_set());

    let epoch0_last_slot = (EPOCH_LENGTH - 1) as TimeslotIndex;
    let epoch1_first_slot = epoch0_last_slot + 1;

    // Simulates `StagingSet` transition at both `epoch0_last_slot` and its previous slot
    let epoch0_last_slot_minus_one = epoch0_last_slot - 1;
    harness.set_timeslot(epoch0_last_slot_minus_one).await?;
    harness
        .transition_staging_set(epoch0_last_slot_minus_one, &harness.genesis_validator_set())
        .await?;
    harness
        .wait_for_staging_cache_entry_update(epoch0_last_slot_minus_one)
        .await;

    // `StagingSet` transition at `epoch0_last_slot`
    harness.set_timeslot(epoch0_last_slot).await?;
    harness
        .transition_staging_set(epoch0_last_slot, &updated_staging_set)
        .await?;
    assert_eq!(manager.last_staging_set_transition_slot(), epoch0_last_slot);

    // Do NOT wait for the async cache update; rotate immediately
    manager.commit_and_rotate_ring_cache();
    harness
        .set_safrole_pending_set(&updated_staging_set)
        .await?;

    // Rotation should have promoted the stale entry into `curr`
    let (curr_before, staging_before) = manager.ring_cache_snapshot();
    assert_eq!(curr_before.unwrap().inserted_at, epoch0_last_slot_minus_one);
    assert_eq!(
        staging_before.unwrap().inserted_at,
        epoch0_last_slot_minus_one
    );

    // Consumer of the `curr` ring cache
    // This should rebuild the ring context for the new StagingSet, since the `curr` entry is stale
    let (_verifier_epoch1, ring_root_epoch1) = manager
        .get_or_generate_curr_ring_context(epoch1_first_slot, &updated_staging_set)
        .await?;
    assert_eq!(ring_root_epoch1, compute_ring_root(&updated_staging_set));

    let (curr_after, _staging_after) = manager.ring_cache_snapshot();
    let curr_after = curr_after.unwrap();
    assert_eq!(curr_after.inserted_at, epoch1_first_slot);
    assert_eq!(
        curr_after.ring_root,
        compute_ring_root(&updated_staging_set)
    );

    // Eventually the background task finishes and updates the `staging` cache
    let staging_entry = harness
        .wait_for_staging_cache_entry_update(epoch0_last_slot)
        .await;
    assert_eq!(
        staging_entry.ring_root,
        compute_ring_root(&updated_staging_set)
    );

    // Ensure the fresh `curr` entry remains untouched after the delayed staging update arrives
    let (curr_final, staging_final) = manager.ring_cache_snapshot();
    let curr_final = curr_final.unwrap();
    assert_eq!(curr_final.inserted_at, epoch1_first_slot);
    assert_eq!(
        curr_final.ring_root,
        compute_ring_root(&updated_staging_set)
    );
    if let Some(staging_final) = staging_final {
        assert!(staging_final.inserted_at >= epoch0_last_slot);
    }

    Ok(())
}

/// Test with the fallback mode.
#[tokio::test]
async fn ring_cache_safrole_fallback_mode() -> Result<(), Box<dyn Error>> {
    let _temp_dir = tempdir().unwrap();
    let db_path = _temp_dir.path().join("ring_cache_test");
    let harness = RingCacheHarness::new(db_path).await?;
    let manager = harness.manager();
    let genesis_set = harness.genesis_validator_set();

    let epoch0_last_slot = (EPOCH_LENGTH - 1) as TimeslotIndex;
    let epoch1_first_slot = epoch0_last_slot + 1;

    harness.set_timeslot(epoch0_last_slot).await?;
    harness
        .transition_staging_set(epoch0_last_slot, &genesis_set)
        .await?;
    harness
        .wait_for_staging_cache_entry_update(epoch0_last_slot)
        .await;
    manager.commit_and_rotate_ring_cache();

    let prior_timeslot = Timeslot::new(epoch0_last_slot);
    let current_timeslot = Timeslot::new(epoch1_first_slot);
    harness.set_timeslot(epoch1_first_slot).await?;
    harness.set_safrole_pending_set(&genesis_set).await?;

    // Fallback mode enacted
    transition_safrole(
        manager.clone(),
        &prior_timeslot,
        &current_timeslot,
        true,
        &TicketsXt { items: vec![] },
    )
    .await?;

    let safrole_state = manager.get_safrole().await?;
    assert!(matches!(
        safrole_state.slot_sealers,
        SlotSealers::BandersnatchPubKeys(_)
    ));
    assert_eq!(safrole_state.ring_root, compute_ring_root(&genesis_set));

    let (curr, _staging) = manager.ring_cache_snapshot();
    assert_eq!(curr.as_ref().unwrap().ring_root, safrole_state.ring_root);

    Ok(())
}
