use crate::{
    constants::MAX_WORK_ITEMS_PER_PACKAGE, workloads::common::RefinementContext, Hash32, Octets,
    ServiceId, UnsignedGas, HASH_SIZE,
};
use fr_codec::prelude::*;
use fr_limited_vec::LimitedVec;

pub type WorkItems = LimitedVec<WorkItem, MAX_WORK_ITEMS_PER_PACKAGE>;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WorkPackage {
    /// **`j`**: Authorizer token blob
    pub auth_token: Octets,
    /// `h`: Authorization code host service id
    pub authorizer_service_id: ServiceId,
    /// `u` & **`p`**: Authorization code hash and config blob
    pub authorizer: Authorizer,
    /// **`x`**: Refinement context
    pub context: RefinementContext,
    /// **`w`**: Sequence of work items
    pub work_items: WorkItems,
}

impl JamEncode for WorkPackage {
    fn size_hint(&self) -> usize {
        self.auth_token.size_hint()
            + 4
            + self.authorizer.size_hint()
            + self.context.size_hint()
            + self.work_items.size_hint()
    }

    fn encode_to<T: JamOutput>(&self, dest: &mut T) -> Result<(), JamCodecError> {
        self.auth_token.encode_to(dest)?;
        self.authorizer_service_id.encode_to_fixed(dest, 4)?;
        self.authorizer.encode_to(dest)?;
        self.context.encode_to(dest)?;
        self.work_items.encode_to(dest)?;
        Ok(())
    }
}

impl JamDecode for WorkPackage {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError>
    where
        Self: Sized,
    {
        Ok(Self {
            auth_token: Octets::decode(input)?,
            authorizer_service_id: ServiceId::decode_fixed(input, 4)?,
            authorizer: Authorizer::decode(input)?,
            context: RefinementContext::decode(input)?,
            work_items: WorkItems::decode(input)?,
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, JamEncode, JamDecode)]
pub struct Authorizer {
    /// `u`: Authorization code hash
    pub auth_code_hash: Hash32,
    /// **`p`**: Authorization config blob
    pub config_blob: Octets,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkItem {
    /// `s`: Associated service id
    pub service_id: ServiceId,
    /// `h`: Code hash of the service, at the time of reporting
    pub service_code_hash: Hash32,
    /// **`y`**: Work item payload blob
    pub payload_blob: Octets,
    /// `g`: Service-specific gas limit for Refinement
    pub refine_gas_limit: UnsignedGas,
    /// `a`: Service-specific gas limit for Accumulation
    pub accumulate_gas_limit: UnsignedGas,
    /// **`i`**: Import segments info (hash and index).
    /// max length = `IMPORT_EXPORT_SEGMENTS_LENGTH_LIMIT`
    pub import_segment_ids: Vec<ImportInfo>,
    /// **`x`**: Extrinsic data info (hash and length)
    pub extrinsic_data_info: Vec<ExtrinsicInfo>,
    /// `e`: Number of export data segments exported by the work item.
    /// max value = `IMPORT_EXPORT_SEGMENTS_LENGTH_LIMIT`
    pub export_segment_count: u16,
}

impl JamEncode for WorkItem {
    fn size_hint(&self) -> usize {
        4 + self.service_code_hash.size_hint()
            + self.payload_blob.size_hint()
            + 8
            + 8
            + self.import_segment_ids.size_hint()
            + self.extrinsic_data_info.size_hint()
            + 2
    }

    fn encode_to<T: JamOutput>(&self, dest: &mut T) -> Result<(), JamCodecError> {
        self.service_id.encode_to_fixed(dest, 4)?;
        self.service_code_hash.encode_to(dest)?;
        self.payload_blob.encode_to(dest)?;
        self.refine_gas_limit.encode_to_fixed(dest, 8)?;
        self.accumulate_gas_limit.encode_to_fixed(dest, 8)?;
        self.import_segment_ids.encode_to(dest)?;
        self.extrinsic_data_info.encode_to(dest)?;
        self.export_segment_count.encode_to_fixed(dest, 2)?;
        Ok(())
    }
}

impl JamDecode for WorkItem {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError>
    where
        Self: Sized,
    {
        Ok(Self {
            service_id: ServiceId::decode_fixed(input, 4)?,
            service_code_hash: Hash32::decode(input)?,
            payload_blob: Octets::decode(input)?,
            refine_gas_limit: UnsignedGas::decode_fixed(input, 8)?,
            accumulate_gas_limit: UnsignedGas::decode_fixed(input, 8)?,
            import_segment_ids: Vec::<ImportInfo>::decode(input)?,
            extrinsic_data_info: Vec::<ExtrinsicInfo>::decode(input)?,
            export_segment_count: u16::decode_fixed(input, 2)?,
        })
    }
}

impl WorkItem {
    pub fn encode_for_fetch_hostcall(&self) -> Result<Vec<u8>, JamCodecError> {
        let mut buf = vec![];
        self.service_id.encode_to_fixed(&mut buf, 4)?;
        self.service_code_hash.encode_to(&mut buf)?;
        self.refine_gas_limit.encode_to_fixed(&mut buf, 8)?;
        self.accumulate_gas_limit.encode_to_fixed(&mut buf, 8)?;
        self.export_segment_count.encode_to_fixed(&mut buf, 2)?;
        self.import_segment_ids.len().encode_to_fixed(&mut buf, 2)?;
        self.extrinsic_data_info
            .len()
            .encode_to_fixed(&mut buf, 2)?;
        self.payload_blob.len().encode_to_fixed(&mut buf, 4)?;
        Ok(buf)
    }
}

// FIXME: according to GP, WPH should be converted to SR and then serialized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkPackageId {
    /// `h`: Export segments root
    SegmentRoot(Hash32),
    /// `h+` (boxplus): Exporting work-package hash
    WorkPackageHash(Hash32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportInfo {
    /// `h` or `h+`: Work package id
    pub work_package_id: WorkPackageId,
    /// `i`: Work item index within the work package, up to 2^15
    pub item_index: u16,
}

impl JamEncode for ImportInfo {
    fn size_hint(&self) -> usize {
        HASH_SIZE + 2
    }

    fn encode_to<T: JamOutput>(&self, dest: &mut T) -> Result<(), JamCodecError> {
        let (hash, item_index) = match &self.work_package_id {
            WorkPackageId::SegmentRoot(hash) => (hash, self.item_index),
            WorkPackageId::WorkPackageHash(hash) => (hash, self.item_index + (1 << 15)),
        };
        hash.encode_to(dest)?;
        item_index.encode_to_fixed(dest, 2)?;
        Ok(())
    }
}

impl JamDecode for ImportInfo {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError>
    where
        Self: Sized,
    {
        let hash = Hash32::decode(input)?;
        let item_index = u16::decode_fixed(input, 2)?;

        let work_package_id = if item_index >= (1 << 15) {
            WorkPackageId::WorkPackageHash(hash) // the `boxplus` tagged variant of hash
        } else {
            WorkPackageId::SegmentRoot(hash)
        };

        let original_item_index = if let WorkPackageId::WorkPackageHash(_) = work_package_id {
            item_index - (1 << 15)
        } else {
            item_index
        };

        Ok(ImportInfo {
            work_package_id,
            item_index: original_item_index,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ExtrinsicInfo {
    /// `h`: Extrinsic data hash
    pub blob_hash: Hash32,
    /// `i`: Extrinsic data size
    pub blob_length: u32,
}

impl JamEncode for ExtrinsicInfo {
    fn size_hint(&self) -> usize {
        self.blob_hash.size_hint() + 4
    }

    fn encode_to<T: JamOutput>(&self, dest: &mut T) -> Result<(), JamCodecError> {
        self.blob_hash.encode_to(dest)?;
        self.blob_length.encode_to_fixed(dest, 4)?;
        Ok(())
    }
}

impl JamDecode for ExtrinsicInfo {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError>
    where
        Self: Sized,
    {
        Ok(Self {
            blob_hash: Hash32::decode(input)?,
            blob_length: u32::decode_fixed(input, 4)?,
        })
    }
}
