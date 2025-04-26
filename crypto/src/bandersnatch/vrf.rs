use crate::bandersnatch::vrf_core::{IetfVrfSignature, RingVrfSignature};
use ark_vrf::reexports::ark_serialize::CanonicalDeserialize;
use rjam_common::{BandersnatchRingVrfSig, BandersnatchSig, Hash32};

/// `Y` hash output function for a VRF signature
pub fn entropy_hash_ietf_vrf(signature_bytes: &BandersnatchSig) -> Hash32 {
    IetfVrfSignature::deserialize_compressed(&signature_bytes[..])
        .unwrap()
        .output_hash()
}

/// `Y` hash output function for an anonymous RingVRF signature
pub fn entropy_hash_ring_vrf(signature_bytes: &BandersnatchRingVrfSig) -> Hash32 {
    RingVrfSignature::deserialize_compressed(&signature_bytes[..])
        .unwrap()
        .output_hash()
}
