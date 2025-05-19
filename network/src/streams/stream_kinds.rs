use crate::error::NetworkError;

#[repr(u8)]
#[derive(Debug)]
pub enum StreamKind {
    UP(UpStreamKind),
    CE(CeStreamKind),
}

impl StreamKind {
    pub fn from_u8(value: u8) -> Result<Self, NetworkError> {
        match value {
            0..=127 => Ok(StreamKind::UP(UpStreamKind::from_u8(value)?)),
            128..=u8::MAX => Ok(StreamKind::CE(CeStreamKind::from_u8(value)?)),
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub enum UpStreamKind {
    BlockAnnouncement = 0,
}

impl TryFrom<u8> for UpStreamKind {
    type Error = NetworkError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(UpStreamKind::BlockAnnouncement),
            _ => Err(NetworkError::InvalidUpStreamKind(value)),
        }
    }
}

impl UpStreamKind {
    pub fn from_u8(value: u8) -> Result<Self, NetworkError> {
        Self::try_from(value)
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum CeStreamKind {
    BlockRequest = 128,
    StateRequest = 129,
    TicketDistributionFirst = 131,
    TicketDistributionSecond = 132,
    WorkPackageSubmission = 133,
    WorkPackageSharing = 134,
    WorkReportDistribution = 135,
    WorkReportRequest = 136,
    ShardDistribution = 137,
    AuditShardRequest = 138,
    SegmentShardRequestFirst = 139,
    SegmentShardRequestSecond = 140,
    AssuranceDistribution = 141,
    PreimageAnnouncement = 142,
    PreimageRequest = 143,
    AuditAnnouncement = 144,
    JudgmentPublication = 145,
}

impl TryFrom<u8> for CeStreamKind {
    type Error = NetworkError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            128 => Ok(CeStreamKind::BlockRequest),
            129 => Ok(CeStreamKind::StateRequest),
            131 => Ok(CeStreamKind::TicketDistributionFirst),
            132 => Ok(CeStreamKind::TicketDistributionSecond),
            133 => Ok(CeStreamKind::WorkPackageSubmission),
            134 => Ok(CeStreamKind::WorkPackageSharing),
            135 => Ok(CeStreamKind::WorkReportDistribution),
            136 => Ok(CeStreamKind::WorkReportRequest),
            137 => Ok(CeStreamKind::ShardDistribution),
            138 => Ok(CeStreamKind::AuditShardRequest),
            139 => Ok(CeStreamKind::SegmentShardRequestFirst),
            140 => Ok(CeStreamKind::SegmentShardRequestSecond),
            141 => Ok(CeStreamKind::AssuranceDistribution),
            142 => Ok(CeStreamKind::PreimageAnnouncement),
            143 => Ok(CeStreamKind::PreimageRequest),
            144 => Ok(CeStreamKind::AuditAnnouncement),
            145 => Ok(CeStreamKind::JudgmentPublication),
            _ => Err(NetworkError::InvalidCeStreamKind(value)),
        }
    }
}

impl CeStreamKind {
    pub fn from_u8(value: u8) -> Result<Self, NetworkError> {
        Self::try_from(value)
    }
}
