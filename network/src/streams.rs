use quinn::{RecvStream, SendStream};

pub struct UpStream {
    pub stream_kind: StreamKind,
    pub send_stream: SendStream,
    pub recv_stream: RecvStream,
}

#[repr(u8)]
pub enum StreamKind {
    // --- UP stream kinds
    BlockAnnouncement = 0,
    // --- CE stream kinds
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
