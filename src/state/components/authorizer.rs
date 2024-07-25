// use crate::{
//     codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput},
//     common::{Hash32, CORE_COUNT},
// };
// use std::array;
//
// fn create_empty_entries() -> [Vec<Hash32>; CORE_COUNT] {
//     array::from_fn(|_| Vec::new())
// }
//
// pub(crate) struct AuthorizationPool {
//     entries: [Vec<Hash32>; CORE_COUNT], // Vec<Hash32> length up to `O = 8`
// }
//
// impl JamEncode for AuthorizationPool {
//     fn size_hint(&self) -> usize {
//         self.entries.iter().map(|entry| entry.size_hint()).sum()
//     }
//
//     fn encode_to<W: JamOutput>(&self, dest: &mut W) -> Result<(), JamCodecError> {
//         for entry in &self.entries {
//             entry.encode_to(dest)?;
//         }
//         Ok(())
//     }
// }
//
// impl JamDecode for AuthorizationPool {
//     fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError> {
//         let mut entries: [Vec<Hash32>; CORE_COUNT] = create_empty_entries();
//
//         for entry in &mut entries {
//             *entry = Vec::decode(input)?;
//         }
//
//         Ok(Self { entries })
//     }
// }
