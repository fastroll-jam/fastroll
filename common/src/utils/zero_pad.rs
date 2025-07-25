/// Zero-padding function for octet sequences.
///
/// Pads the input array with zeros to make the output length equal to the smallest multiple of
/// `BLOCK_SIZE`.
pub fn zero_pad<const BLOCK_SIZE: usize>(mut data: Vec<u8>) -> Vec<u8> {
    if BLOCK_SIZE == 0 {
        panic!("BLOCK_SIZE must be greater than 0")
    }

    let output_size = if data.is_empty() {
        BLOCK_SIZE // Pad empty input to one block
    } else {
        data.len().div_ceil(BLOCK_SIZE) * BLOCK_SIZE
    };

    data.resize(output_size, 0);
    data
}

#[cfg(test)]
mod zero_pad_tests {
    use super::*;

    #[test]
    fn test_zero_pad_empty() {
        assert_eq!(zero_pad::<5>(vec![]), vec![0, 0, 0, 0, 0]);
    }

    #[test]
    #[should_panic]
    fn test_zero_pad_zero_block_size_should_panic() {
        let _ = zero_pad::<0>(vec![1, 2, 3]);
    }

    #[test]
    fn test_zero_pad_1() {
        assert_eq!(zero_pad::<5>(vec![0]), vec![0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_zero_pad_2() {
        assert_eq!(zero_pad::<5>(vec![1, 2, 3, 4]), vec![1, 2, 3, 4, 0]);
    }

    #[test]
    fn test_zero_pad_3() {
        assert_eq!(zero_pad::<5>(vec![1, 2, 3, 4, 5]), vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_zero_pad_4() {
        assert_eq!(
            zero_pad::<5>(vec![1, 2, 3, 4, 5, 6]),
            vec![1, 2, 3, 4, 5, 6, 0, 0, 0, 0]
        );
    }
}
