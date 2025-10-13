use fr_block::types::block::BlockHeader;
use fr_common::BlockHeaderHash;
use fr_state::manager::StateCommitArtifact;
use fr_transition::state::services::AccountStateChanges;
use std::collections::HashMap;

/// A block header and its uncommitted state change artifacts
/// that can be either committed or discarded after forks get resolved.
#[derive(Clone)]
pub struct StagedBlock {
    pub header: BlockHeader,
    pub account_state_changes: AccountStateChanges,
    pub state_commit_artifact: Option<StateCommitArtifact>,
}

/// The state that keeps minimal context to support simple forking.
#[derive(Default)]
pub struct SimpleForkState {
    /// The header hash of the last finalized block.
    pub last_finalized: Option<BlockHeaderHash>,
    /// The collection of blocks that are staged but not committed or dropped yet.
    pub staged_blocks: HashMap<BlockHeaderHash, StagedBlock>,
}

impl SimpleForkState {
    pub fn last_finalized(&self) -> Option<&BlockHeaderHash> {
        self.last_finalized.as_ref()
    }

    pub fn set_last_finalized(&mut self, last_finalized: BlockHeaderHash) {
        self.last_finalized = Some(last_finalized);
    }

    pub fn insert_staged_block(&mut self, header_hash: BlockHeaderHash, block: StagedBlock) {
        self.staged_blocks.insert(header_hash, block);
    }

    pub fn take_staged_block(&mut self, header_hash: &BlockHeaderHash) -> Option<StagedBlock> {
        self.staged_blocks.remove(header_hash)
    }
}
