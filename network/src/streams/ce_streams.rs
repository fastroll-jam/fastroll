use crate::error::NetworkError;

pub enum NodeRole {
    Node,
    Builder,
    Validator,
    Guarantor,
    Assurer,
    Auditor,
}

pub trait CeStream {
    const INITIATOR_ROLE: NodeRole;
    const ACCEPTOR_ROLE: NodeRole;

    fn initiate() -> Result<(), NetworkError>;

    fn respond() -> Result<(), NetworkError>;
}

pub struct BlockRequest;
impl CeStream for BlockRequest {
    const INITIATOR_ROLE: NodeRole = NodeRole::Node;
    const ACCEPTOR_ROLE: NodeRole = NodeRole::Node;

    fn initiate() -> Result<(), NetworkError> {
        todo!()
    }

    fn respond() -> Result<(), NetworkError> {
        todo!()
    }
}
