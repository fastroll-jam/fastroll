use parity_scale_codec::Encode;

#[derive(Encode)]
pub(crate) struct ValidatorStatEntry {
    block_production_count: u32, // b; the number of blocks produced by the validator.
    ticket_count: u32,           // t; the number of tickets introduced by the validator.
    preimage_count: u32,         // p; the number of preimages introduced by the validator.
    preimage_data_octet_count: u32, // d; the total number of octets across all preimages introduced by the validator.
    guarantee_count: u32,           // g; the number of reports guaranteed by the validator.
    assurance_count: u32, // a; the number of availability assurances made by the validator.
}
