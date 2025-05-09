use quinn::{RecvStream, SendStream};

#[derive(Debug)]
pub struct UpStream {
    pub stream_kind: UpStreamKind,
    pub send_stream: SendStream,
    pub recv_stream: RecvStream,
}

#[repr(u8)]
#[derive(Debug)]
pub enum StreamKind {
    UP(UpStreamKind),
    CE(CeStreamKind),
}

#[repr(u8)]
#[derive(Debug, Hash, PartialEq, Eq)]
pub enum UpStreamKind {
    BlockAnnouncement = 0,
}

#[repr(u8)]
#[derive(Debug)]
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

#[derive(Debug)]
pub enum LocalNodeRole {
    Initiator,
    Acceptor,
}
