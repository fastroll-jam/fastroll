// common/erasure-coding/lib.rs

use reed_solomon_simd::{Error as ReedSolomonError, ReedSolomonEncoder};
use thiserror::Error;

type Chunk = Vec<u8>; // length: k words (2k octets)

#[derive(Debug, Error)]
pub enum ErasureCodingError {
    #[error("ReedSolomonError: {0}")]
    ReedSolomonError(#[from] ReedSolomonError),
}

/// Reed-solomon erasure codec on Galois field GF(2^16).
///
/// ## Field Parameters
/// * Irreducible polynomial coefficients: 0x1002D
/// * Cantor basis: [ 0x0001, 0xACCA, 0x3C0E, 0x163E, 0xC582, 0xED2E, 0x914C, 0x4012, 0x6C98,
///   0x10D8, 0x6A72, 0xB900, 0xFDB8, 0xFB34, 0xFF38, 0x991E ]
pub struct ReedSolomon {
    /// The total number of symbols in a codeword (message + recovery symbols).
    /// For `k:n` reed-solomon rate, this is `n`.
    total_words: usize,
    /// The number of original message symbols.
    /// For `k:n` reed-solomon rate, this is `k`.
    msg_words: usize,
}

impl ReedSolomon {
    pub fn new_tiny() -> Self {
        Self {
            total_words: 6,
            msg_words: 2,
        }
    }

    pub fn new_full() -> Self {
        Self {
            total_words: 1023,
            msg_words: 342,
        }
    }

    pub fn total_words(&self) -> usize {
        self.total_words
    }

    pub fn msg_words(&self) -> usize {
        self.msg_words
    }

    fn zero_pad_data(data: &[u8], msg_words: usize) -> Vec<u8> {
        if data.len() % (msg_words * 2) == 0 {
            data.to_vec()
        } else {
            let mut padded_data = data.to_vec();
            let qt = data.len() / (msg_words * 2);
            let target_len = (qt + 1) * (msg_words * 2);
            let pad_len = target_len - data.len();
            padded_data.extend(std::iter::repeat_n(0, pad_len));
            padded_data
        }
    }

    // TODO: alternative could be to transpose the entire data in advance
    pub fn erasure_encode(&self, data: &[u8]) -> Result<Vec<Chunk>, ErasureCodingError> {
        // TODO: input validation
        let data_padded = Self::zero_pad_data(data, self.msg_words); // length: (`self.msg_words` * k) words
        let chunk_octets = data_padded.len() / self.msg_words;
        let chunk_octet_pairs = chunk_octets / 2; // k

        let mut chunks = vec![Chunk::with_capacity(chunk_octets); self.total_words];

        let mut encoder =
            ReedSolomonEncoder::new(self.msg_words, self.total_words - self.msg_words, 2)?;

        for word_idx in 0..chunk_octet_pairs {
            for (chunk_idx, chunk) in chunks.iter_mut().enumerate().take(self.msg_words) {
                // Transpose
                let pair_offset_octets = 2 * (word_idx + chunk_idx * chunk_octet_pairs);
                let original_word = &data_padded[pair_offset_octets..pair_offset_octets + 2]; // A single word

                chunk.extend_from_slice(original_word); // Transposed back to original format
                encoder.add_original_shard(original_word)? // Transposed data is added to the encoder
            }
            {
                // Transpose back
                encoder
                    .encode()?
                    .recovery_iter()
                    .enumerate()
                    .for_each(|(chunk_idx, word)| {
                        chunks[self.msg_words + chunk_idx].extend_from_slice(word)
                    });
            }
            encoder.reset(self.msg_words, self.total_words - self.msg_words, 2)?
        }

        Ok(chunks)
    }

    pub fn erasure_recover(
        &self,
        _chunks: Vec<Option<Chunk>>,
    ) -> Result<Vec<u8>, ErasureCodingError> {
        unimplemented!()
    }
}
