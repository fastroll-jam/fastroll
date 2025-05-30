use crate::{
    ACCUMULATION_GAS_ALL_CORES, ACCUMULATION_GAS_PER_CORE, AUTH_QUEUE_SIZE, BLOCK_HISTORY_LENGTH,
    CORE_COUNT, DATA_SEGMENTS_CHUNKS, EPOCH_LENGTH, ERASURE_CHUNK_SIZE, GUARANTOR_ROTATION_PERIOD,
    IS_AUTHORIZED_GAS_PER_WORK_PACKAGE, MAX_ACCUMULATE_QUEUE_ENTRIES, MAX_AUTH_POOL_SIZE,
    MAX_EXPORTS_PER_PACKAGE, MAX_EXTRINSICS_PER_PACKAGE, MAX_IMPORTS_PER_PACKAGE,
    MAX_IS_AUTHORIZED_CODE_SIZE, MAX_LOOKUP_ANCHOR_AGE, MAX_PACKAGE_AND_DATA_SIZE,
    MAX_REPORT_DEPENDENCIES, MAX_SERVICE_CODE_SIZE, MAX_WORK_ITEMS_PER_PACKAGE,
    MIN_BALANCE_PER_ITEM, MIN_BALANCE_PER_OCTET, MIN_BASIC_BALANCE, PENDING_REPORT_TIMEOUT,
    PREIMAGE_EXPIRATION_PERIOD, REFINE_GAS_PER_WORK_PACKAGE, SEGMENT_SIZE, SLOT_DURATION,
    TICKET_CONTEST_DURATION, TRANSFER_MEMO_SIZE, VALIDATOR_COUNT, WORK_REPORT_OUTPUT_SIZE_LIMIT,
};
use fr_codec::prelude::*;

pub fn encode_constants_for_fetch_hostcall() -> Result<Vec<u8>, JamCodecError> {
    let mut buf = Vec::with_capacity(136);
    MIN_BALANCE_PER_ITEM.encode_to_fixed(&mut buf, 8)?; // B_I
    MIN_BALANCE_PER_OCTET.encode_to_fixed(&mut buf, 8)?; // B_L
    MIN_BASIC_BALANCE.encode_to_fixed(&mut buf, 8)?; // B_S
    CORE_COUNT.encode_to_fixed(&mut buf, 2)?; // C
    PREIMAGE_EXPIRATION_PERIOD.encode_to_fixed(&mut buf, 4)?; // D
    EPOCH_LENGTH.encode_to_fixed(&mut buf, 4)?; // E
    ACCUMULATION_GAS_PER_CORE.encode_to_fixed(&mut buf, 8)?; // G_A
    IS_AUTHORIZED_GAS_PER_WORK_PACKAGE.encode_to_fixed(&mut buf, 8)?; // G_I
    REFINE_GAS_PER_WORK_PACKAGE.encode_to_fixed(&mut buf, 8)?; // G_R
    ACCUMULATION_GAS_ALL_CORES.encode_to_fixed(&mut buf, 8)?; // G_T
    BLOCK_HISTORY_LENGTH.encode_to_fixed(&mut buf, 2)?; // H
    MAX_WORK_ITEMS_PER_PACKAGE.encode_to_fixed(&mut buf, 2)?; // I
    MAX_REPORT_DEPENDENCIES.encode_to_fixed(&mut buf, 2)?; // J
    MAX_LOOKUP_ANCHOR_AGE.encode_to_fixed(&mut buf, 4)?; // L
    MAX_AUTH_POOL_SIZE.encode_to_fixed(&mut buf, 2)?; // O
    SLOT_DURATION.encode_to_fixed(&mut buf, 2)?; // P
    AUTH_QUEUE_SIZE.encode_to_fixed(&mut buf, 2)?; // Q
    GUARANTOR_ROTATION_PERIOD.encode_to_fixed(&mut buf, 2)?; // R
    MAX_ACCUMULATE_QUEUE_ENTRIES.encode_to_fixed(&mut buf, 2)?; // S
    MAX_EXTRINSICS_PER_PACKAGE.encode_to_fixed(&mut buf, 2)?; // T
    PENDING_REPORT_TIMEOUT.encode_to_fixed(&mut buf, 2)?; // U
    VALIDATOR_COUNT.encode_to_fixed(&mut buf, 2)?; // V
    MAX_IS_AUTHORIZED_CODE_SIZE.encode_to_fixed(&mut buf, 4)?; // W_A
    MAX_PACKAGE_AND_DATA_SIZE.encode_to_fixed(&mut buf, 4)?; // W_B
    MAX_SERVICE_CODE_SIZE.encode_to_fixed(&mut buf, 4)?; // W_C
    ERASURE_CHUNK_SIZE.encode_to_fixed(&mut buf, 4)?; // W_E
    SEGMENT_SIZE.encode_to_fixed(&mut buf, 4)?; // W_G
    MAX_IMPORTS_PER_PACKAGE.encode_to_fixed(&mut buf, 4)?; // W_M
    DATA_SEGMENTS_CHUNKS.encode_to_fixed(&mut buf, 4)?; // W_P
    WORK_REPORT_OUTPUT_SIZE_LIMIT.encode_to_fixed(&mut buf, 4)?; // W_R
    TRANSFER_MEMO_SIZE.encode_to_fixed(&mut buf, 4)?; // W_T
    MAX_EXPORTS_PER_PACKAGE.encode_to_fixed(&mut buf, 4)?; // W_X
    TICKET_CONTEST_DURATION.encode_to_fixed(&mut buf, 4)?; // Y
    Ok(buf)
}
