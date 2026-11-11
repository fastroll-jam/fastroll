use fr_common::SEGMENT_SIZE;
use rayon::prelude::*;
use reed_solomon_simd::{Error as ReedSolomonError, ReedSolomonDecoder, ReedSolomonEncoder};
use thiserror::Error;

pub type Chunk = Vec<u8>; // length: k words (2k octets)

#[derive(Debug, Error)]
pub enum ErasureCodingError {
    #[error(
        "Provided chunks ({provided}) are not enough to recover the data. Required: {required}"
    )]
    InsufficientChunks { provided: usize, required: usize },
    #[error("ReedSolomonError: {0}")]
    ReedSolomonError(#[from] ReedSolomonError),
}

enum ChunkIndex {
    Original(usize),
    Recovery(usize),
}

/// Reed-solomon erasure codec on Galois field GF(2^16).
///
/// ## Field Parameters
/// * Irreducible polynomial coefficients: 0x1002D
/// * Cantor basis: [ 0x0001, 0xACCA, 0x3C0E, 0x163E, 0xC582, 0xED2E, 0x914C, 0x4012, 0x6C98,
///   0x10D8, 0x6A72, 0xB900, 0xFDB8, 0xFB34, 0xFF38, 0x991E ]
pub struct ErasureCodec {
    /// The total number of symbols in a codeword (message + recovery symbols).
    /// For `k:n` reed-solomon rate, this is `n`.
    total_chunks: usize,
    /// The number of original message symbols.
    /// For `k:n` reed-solomon rate, this is `k`.
    msg_chunks: usize,
}

impl ErasureCodec {
    /// Creates a codec of rate `d(v):v` for a validator set of `validator_count` validators.
    pub fn new(validator_count: usize) -> Self {
        Self {
            total_chunks: validator_count,
            msg_chunks: original_chunk_count(validator_count),
        }
    }

    pub fn total_chunks(&self) -> usize {
        self.total_chunks
    }

    pub fn msg_chunks(&self) -> usize {
        self.msg_chunks
    }

    pub fn recovery_chunks(&self) -> usize {
        self.total_chunks - self.msg_chunks
    }

    fn shard_index_typed(&self, index: usize) -> ChunkIndex {
        if index < self.msg_chunks {
            ChunkIndex::Original(index)
        } else {
            ChunkIndex::Recovery(index - self.msg_chunks)
        }
    }

    pub fn zero_pad_data(data: &[u8], msg_chunks: usize) -> Vec<u8> {
        if data.len().is_multiple_of(msg_chunks * 2) {
            data.to_vec()
        } else {
            let mut padded_data = data.to_vec();
            let qt = data.len() / (msg_chunks * 2);
            let target_len = (qt + 1) * (msg_chunks * 2);
            let pad_len = target_len - data.len();
            padded_data.extend(std::iter::repeat_n(0, pad_len));
            padded_data
        }
    }

    pub fn erasure_encode(&self, data: &[u8]) -> Result<Vec<Chunk>, ErasureCodingError> {
        let data_padded = Self::zero_pad_data(data, self.msg_chunks); // length: (self.msg_chunks * k) words
        let chunk_octets = data_padded.len() / self.msg_chunks;
        let chunk_octet_pairs = chunk_octets / 2; // The number of octet pairs per chunk (k)

        // Initialize with proper size
        let mut chunks = vec![vec![0u8; chunk_octets]; self.total_chunks];

        tracing::trace!("Parallel encoding start");
        let words_encodings: Result<Vec<_>, ReedSolomonError> = (0..chunk_octet_pairs)
            .into_par_iter()
            .map(|word_pos| {
                let mut encoder =
                    ReedSolomonEncoder::new(self.msg_chunks, self.recovery_chunks(), 2)?;

                let mut words_encoding = Vec::with_capacity(self.total_chunks);

                for original_chunk_idx in 0..self.msg_chunks {
                    let word_offset_octets =
                        2 * (word_pos + original_chunk_idx * chunk_octet_pairs);
                    let original_word = &data_padded[word_offset_octets..word_offset_octets + 2]; // A single word

                    words_encoding.push((word_pos, original_chunk_idx, original_word.to_vec()));
                    encoder.add_original_shard(original_word)?; // Transposed data is added to the encoder
                }

                // Transpose back to original format
                encoder.encode()?.recovery_iter().enumerate().for_each(
                    |(recovery_chunk_idx, recovery_word)| {
                        words_encoding.push((
                            word_pos,
                            self.msg_chunks + recovery_chunk_idx,
                            recovery_word.to_vec(),
                        ));
                    },
                );
                Ok::<Vec<_>, ReedSolomonError>(words_encoding)
            })
            .collect();
        tracing::trace!("Parallel encoding end");

        // Merge the results
        tracing::trace!("Merging start");
        for words_encoding in words_encodings? {
            for (word_pos, chunk_idx, word) in words_encoding {
                let word_offset_octets = 2 * word_pos;
                chunks[chunk_idx][word_offset_octets..word_offset_octets + 2]
                    .copy_from_slice(&word);
            }
        }
        tracing::trace!("Merging end");

        Ok(chunks)
    }

    pub fn erasure_recover(
        &self,
        chunks: Vec<Option<Chunk>>,
    ) -> Result<Vec<u8>, ErasureCodingError> {
        let chunks_indexed: Vec<(Chunk, usize)> = chunks
            .into_iter()
            .enumerate()
            .filter_map(|(i, maybe_chunk)| maybe_chunk.map(|chunk| (chunk, i)))
            .collect();

        if chunks_indexed.len() < self.msg_chunks {
            return Err(ErasureCodingError::InsufficientChunks {
                provided: chunks_indexed.len(),
                required: self.msg_chunks,
            });
        }

        let chunk_octets = chunks_indexed[0].0.len();
        let chunk_octet_pairs = chunk_octets / 2; // The number of octet pairs per chunk (k)

        // Initialize with proper size
        let mut result = vec![vec![0u8; chunk_octets]; self.msg_chunks];

        // Parallel recovery of octet pair groups at each word index (transposed).
        // For example, iteration `#i` collects `ith` word of all chunks and then decode them together.
        // This gives an effect of transposing the input data, decoding each and then transposing
        // back and joining as specified in GP.
        tracing::trace!("Parallel recovery start");
        let word_recoveries: Result<Vec<_>, _> = (0..chunk_octet_pairs)
            .into_par_iter()
            .map(|word_pos| {
                let mut decoder =
                    ReedSolomonDecoder::new(self.msg_chunks, self.recovery_chunks(), 2)?;

                // Recovered word by word position
                let mut words_recovery = Vec::with_capacity(self.msg_chunks);

                // Add chunks to the decoder for this word position
                for (chunk, chunk_idx) in &chunks_indexed {
                    let word_offset_octets = 2 * word_pos;
                    let word = &chunk[word_offset_octets..word_offset_octets + 2];

                    match self.shard_index_typed(*chunk_idx) {
                        ChunkIndex::Original(idx) => {
                            decoder.add_original_shard(idx, word)?;
                            // Collect original message chunks
                            words_recovery.push((word_pos, idx, word.to_vec()));
                        }
                        ChunkIndex::Recovery(idx) => {
                            decoder.add_recovery_shard(idx, word)?;
                        }
                    }
                }

                // Decode and collect results for this word position
                decoder
                    .decode()?
                    .restored_original_iter()
                    .for_each(|(chunk_idx, word)| {
                        words_recovery.push((word_pos, chunk_idx, word.to_vec()))
                    });

                Ok::<Vec<_>, ReedSolomonError>(words_recovery)
            })
            .collect();
        tracing::trace!("Parallel recovery end");

        // Merge the results
        tracing::trace!("Merging start");
        for word_recovery in word_recoveries? {
            for (word_pos, chunk_idx, word) in word_recovery {
                let word_offset_octets = 2 * word_pos;
                result[chunk_idx][word_offset_octets..word_offset_octets + 2]
                    .copy_from_slice(&word);
            }
        }
        tracing::trace!("Merging end");

        Ok(result.into_iter().flatten().collect::<Vec<_>>())
    }
}

/// Computes `d(v)`, the number of original chunks in the erasure code for a validator set of `validator_count` validators.
/// It is the largest `d` below `v/3 + 2` whose `2d` octets divide a segment of `W_G` octets, e.g. `d(6) = 3` and `d(1023) = 342`.
/// A validator count in `𝕍` is a multiple of 3, so the bound is `d <= v/3 + 1`.
pub const fn original_chunk_count(validator_count: usize) -> usize {
    let mut chunk_count = validator_count / 3 + 1;
    while !SEGMENT_SIZE.is_multiple_of(2 * chunk_count) {
        chunk_count -= 1;
    }
    chunk_count
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn test_original_chunk_count_optimal_rates() -> Result<(), Box<dyn Error>> {
        // GP 0.8.0 lists the validator counts whose rate is optimal, i.e. `d(v) = v/3 + 1`.
        const OPTIMAL_VALIDATOR_COUNTS: [usize; 18] = [
            6, 9, 15, 24, 33, 51, 54, 78, 105, 111, 159, 168, 225, 321, 339, 510, 681, 1023,
        ];
        for validator_count in (6..=1023).step_by(3) {
            let is_optimal = original_chunk_count(validator_count) == validator_count / 3 + 1;
            assert_eq!(
                is_optimal,
                OPTIMAL_VALIDATOR_COUNTS.contains(&validator_count),
                "validator_count={validator_count}"
            );
        }
        Ok(())
    }

    #[test]
    fn test_original_chunk_count_falls_back_to_a_divisor() -> Result<(), Box<dyn Error>> {
        // `v/3 + 1 = 5` octet pairs do not divide a segment, so `d(12)` falls back to 4.
        assert_eq!(original_chunk_count(12), 4);
        Ok(())
    }
}
