use jam_common::Octets;

// Zero-padding function for octet sequences
pub fn zero_pad(mut input: Octets, block_size: usize) -> Octets {
    let padding_len = block_size - (((input.len() + block_size - 1) % block_size) + 1);
    input.extend(vec![0; padding_len]);
    input
}
