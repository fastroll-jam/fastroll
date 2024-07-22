use parity_scale_codec::{Decode, Encode};

#[derive(Encode, Decode)]
pub(crate) struct PrivilegedServicesState {
    empower_service_index: u32,   // m; N_S
    assign_service_index: u32,    // a; N_S
    designate_service_index: u32, // v; N_S
}
