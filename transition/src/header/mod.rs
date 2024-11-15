use crate::error::BlockHeaderUpdateError;
use rjam_common::{BandersnatchSignature, Ed25519PubKey, Hash32, ValidatorIndex};
use rjam_db::BlockHeaderDB;
use rjam_types::{
    block::header::{EpochMarker, WinningTicketsMarker},
    state::timeslot::Timeslot,
};

pub fn set_header_timeslot(header_db: &mut BlockHeaderDB) -> Result<(), BlockHeaderUpdateError> {
    header_db.assert_staging_header_initialized()?;
    let current_timeslot = Timeslot::from_now()?;
    header_db.update_staging_header(|header| {
        header.timeslot_index = current_timeslot.slot();
    })?;

    Ok(())
}

pub fn set_header_parent_state_root(
    header_db: &mut BlockHeaderDB,
    parent_state_root: &Hash32,
) -> Result<(), BlockHeaderUpdateError> {
    header_db.assert_staging_header_initialized()?;
    header_db.update_staging_header(|header| {
        header.parent_state_root = *parent_state_root;
    })?;

    Ok(())
}

pub fn set_header_extrinsic_hash(
    header_db: &mut BlockHeaderDB,
    extrinsic_hash: &Hash32,
) -> Result<(), BlockHeaderUpdateError> {
    header_db.assert_staging_header_initialized()?;
    header_db.update_staging_header(|header| {
        header.extrinsic_hash = *extrinsic_hash;
    })?;

    Ok(())
}

pub fn set_header_vrf_signature(
    header_db: &mut BlockHeaderDB,
    vrf_signature: &BandersnatchSignature,
) -> Result<(), BlockHeaderUpdateError> {
    header_db.assert_staging_header_initialized()?;
    header_db.update_staging_header(|header| {
        header.vrf_signature = *vrf_signature;
    })?;

    Ok(())
}

pub fn set_header_block_seal(
    header_db: &mut BlockHeaderDB,
    block_seal: &BandersnatchSignature,
) -> Result<(), BlockHeaderUpdateError> {
    header_db.assert_staging_header_initialized()?;
    header_db.update_staging_header(|header| {
        header.block_seal = *block_seal;
    })?;

    Ok(())
}

pub fn set_header_block_author_index(
    header_db: &mut BlockHeaderDB,
    block_author_index: ValidatorIndex,
) -> Result<(), BlockHeaderUpdateError> {
    header_db.assert_staging_header_initialized()?;
    header_db.update_staging_header(|header| {
        header.block_author_index = block_author_index;
    })?;

    Ok(())
}

pub fn set_header_epoch_marker(
    header_db: &mut BlockHeaderDB,
    epoch_marker: &EpochMarker,
) -> Result<(), BlockHeaderUpdateError> {
    header_db.assert_staging_header_initialized()?;
    header_db.update_staging_header(|header| {
        header.epoch_marker = Some(epoch_marker.clone());
    })?;

    Ok(())
}

pub fn set_header_winning_tickets_marker(
    header_db: &mut BlockHeaderDB,
    winning_tickets_marker: &WinningTicketsMarker,
) -> Result<(), BlockHeaderUpdateError> {
    header_db.assert_staging_header_initialized()?;
    header_db.update_staging_header(|header| {
        header.winning_tickets_marker = Some(*winning_tickets_marker);
    })?;

    Ok(())
}

pub fn set_header_offenders_marker(
    header_db: &mut BlockHeaderDB,
    offenders_marker: &[Ed25519PubKey],
) -> Result<(), BlockHeaderUpdateError> {
    header_db.assert_staging_header_initialized()?;
    header_db.update_staging_header(|header| {
        header.offenders_marker = offenders_marker.to_vec();
    })?;

    Ok(())
}
