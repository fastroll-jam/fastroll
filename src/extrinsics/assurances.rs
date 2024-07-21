use crate::common::{Ed25519Signature, Hash32};
use bit_vec::BitVec;
use parity_scale_codec::{Compact, Encode, Output};

pub(crate) struct AssuranceExtrinsicEntry {
    anchor_parent_hash: Hash32,    // a
    assuring_cores_bitvec: BitVec, // f
    validator_index: u16,          // v; N_V
    signature: Ed25519Signature,   // s
}

impl Encode for AssuranceExtrinsicEntry {
    fn size_hint(&self) -> usize {
        self.anchor_parent_hash.size_hint()
            + Compact(self.assuring_cores_bitvec.len() as u32).size_hint() // size hint for bit vector length
            + (self.assuring_cores_bitvec.len() + 7) / 8 // size hint for packed bits in bytes
            + self.validator_index.size_hint()
            + self.signature.size_hint()
    }

    fn encode_to<W: Output + ?Sized>(&self, dest: &mut W) {
        self.anchor_parent_hash.encode_to(dest);

        // Encode the bit vector length as a compact integer
        let bit_length = self.assuring_cores_bitvec.len() as u32;
        Compact(bit_length).encode_to(dest);

        // Encode the bit vector as Octets (packing)
        let mut byte = 0u8;
        for (i, bit) in self.assuring_cores_bitvec.iter().enumerate() {
            if bit {
                byte |= 1 << (i % 8);
            }
            if i % 8 == 7 {
                byte.encode_to(dest);
                byte = 0;
            }
        }
        // Encode any remaining bits in the final byte
        if self.assuring_cores_bitvec.len() % 8 != 0 {
            byte.encode_to(dest);
        }

        self.validator_index.encode_to(dest); // TODO: check if this should take the first 2 bytes only
        self.signature.encode_to(dest);
    }
}
