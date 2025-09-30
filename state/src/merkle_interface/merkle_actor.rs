#![allow(dead_code)]
use crate::{
    cache::CacheEntry, error::StateManagerError, merkle_interface::merkle_manager::MerkleManager,
};
use fr_common::{MerkleRoot, StateKey};
use fr_state_merkle_v2::{
    merkle_change_set::StateDBWrite,
    types::{LeafNodeData, StateMerkleError},
};
use tokio::sync::{mpsc, oneshot};

pub(crate) enum MerkleCommand {
    GetMerkleRoot {
        resp: oneshot::Sender<MerkleRoot>,
    },
    Retrieve {
        state_key: StateKey,
        resp: oneshot::Sender<Result<Option<LeafNodeData>, StateMerkleError>>,
    },
    CommitDirtyCache {
        dirty_entries: Vec<(StateKey, CacheEntry)>,
        resp: oneshot::Sender<Result<Vec<StateDBWrite>, StateMerkleError>>,
    },
}

#[derive(Clone)]
pub(crate) struct MerkleManagerHandle {
    pub(crate) sender: mpsc::Sender<MerkleCommand>,
}

impl MerkleManagerHandle {
    pub(crate) async fn get_merkle_root(&self) -> Result<MerkleRoot, StateManagerError> {
        let (resp, recv) = oneshot::channel();
        let command = MerkleCommand::GetMerkleRoot { resp };
        self.sender
            .send(command)
            .await
            .map_err(|_| StateManagerError::MerkleActorClosed)?;
        recv.await.map_err(|_| StateManagerError::MerkleActorClosed)
    }

    pub(crate) async fn retrieve_state(
        &self,
        state_key: StateKey,
    ) -> Result<Option<LeafNodeData>, StateManagerError> {
        let (resp, recv) = oneshot::channel();
        let command = MerkleCommand::Retrieve { state_key, resp };
        self.sender
            .send(command)
            .await
            .map_err(|_| StateManagerError::MerkleActorClosed)?;
        Ok(recv
            .await
            .map_err(|_| StateManagerError::MerkleActorClosed)??)
    }

    pub(crate) async fn commit_dirty_cache(
        &self,
        dirty_entries: Vec<(StateKey, CacheEntry)>,
    ) -> Result<Vec<StateDBWrite>, StateManagerError> {
        let (resp, recv) = oneshot::channel();
        let command = MerkleCommand::CommitDirtyCache {
            dirty_entries,
            resp,
        };
        self.sender
            .send(command)
            .await
            .map_err(|_| StateManagerError::MerkleActorClosed)?;
        Ok(recv
            .await
            .map_err(|_| StateManagerError::MerkleActorClosed)??)
    }
}

/// An actor that holds `MerkleManager` and processes `MerkleCommand` requests.
pub(crate) struct MerkleActor {
    manager: MerkleManager,
    receiver: mpsc::Receiver<MerkleCommand>,
}

impl MerkleActor {
    pub(crate) fn new(manager: MerkleManager, receiver: mpsc::Receiver<MerkleCommand>) -> Self {
        Self { manager, receiver }
    }

    pub(crate) async fn run(mut self) {
        while let Some(command) = self.receiver.recv().await {
            match command {
                MerkleCommand::GetMerkleRoot { resp } => {
                    let root = self.manager.merkle_root();
                    let _ = resp.send(root.clone());
                }
                MerkleCommand::Retrieve { state_key, resp } => {
                    let retrieval_result = self.manager.retrieve(&state_key).await;
                    let _ = resp.send(retrieval_result);
                }
                MerkleCommand::CommitDirtyCache {
                    dirty_entries,
                    resp,
                } => {
                    let commit_result = self
                        .manager
                        .commit_dirty_state_cache_to_merkle_db_and_produce_state_db_write_set(
                            &dirty_entries,
                        )
                        .await;
                    let _ = resp.send(commit_result);
                }
            }
        }
    }
}
