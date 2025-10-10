#![allow(dead_code)]
use crate::{
    cache::CacheEntry,
    error::StateManagerError,
    merkle_interface::manager::{DBWriteSetWithRoot, MerkleManager},
};
use fr_common::{MerkleRoot, StateKey};
use fr_state_merkle_v2::{
    merkle_change_set::StateDBWrite,
    types::{LeafNodeData, StateMerkleError},
};
use tokio::sync::{mpsc, oneshot};

pub(crate) enum MerkleCommand {
    /// Get the current Merkle root from the `MerkleDB`.
    GetMerkleRoot { resp: oneshot::Sender<MerkleRoot> },
    /// Retrieves a leaf node data that corresponds to the given state key from the `MerkleDB`, if exists.
    Retrieve {
        state_key: StateKey,
        resp: oneshot::Sender<Result<Option<LeafNodeData>, StateMerkleError>>,
    },
    /// Processes and commits the provided dirty state cache entries directly into the `MerkleDB`.
    /// Equivalent to combination of `PrepareDirtyCacheCommit` & `ApplyDirtyCacheCommit`
    CommitDirtyCache {
        dirty_entries: Vec<(StateKey, CacheEntry)>,
        resp: oneshot::Sender<Result<Vec<StateDBWrite>, StateMerkleError>>,
    },
    /// Prepares `DBWriteSetWithRoot` by processing the provided dirty state cache entries.
    PrepareDirtyCacheCommit {
        dirty_entries: Vec<(StateKey, CacheEntry)>,
        resp: oneshot::Sender<Result<Option<DBWriteSetWithRoot>, StateMerkleError>>,
    },
    /// Commits the prepared `DBWriteSetWithRoot` into the `MerkleDB`.
    ApplyDirtyCacheCommit {
        prepared: DBWriteSetWithRoot,
        resp: oneshot::Sender<Result<(), StateMerkleError>>,
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

    pub(crate) async fn prepare_dirty_cache_commit(
        &self,
        dirty_entries: Vec<(StateKey, CacheEntry)>,
    ) -> Result<Option<DBWriteSetWithRoot>, StateManagerError> {
        let (resp, recv) = oneshot::channel();
        let command = MerkleCommand::PrepareDirtyCacheCommit {
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

    pub(crate) async fn apply_dirty_cache_commit(
        &self,
        prepared: DBWriteSetWithRoot,
    ) -> Result<(), StateManagerError> {
        let (resp, recv) = oneshot::channel();
        let command = MerkleCommand::ApplyDirtyCacheCommit { prepared, resp };
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
                MerkleCommand::PrepareDirtyCacheCommit {
                    dirty_entries,
                    resp,
                } => {
                    let prepare_result = self
                        .manager
                        .prepare_dirty_cache_commit(&dirty_entries)
                        .await;
                    let _ = resp.send(prepare_result);
                }
                MerkleCommand::ApplyDirtyCacheCommit { prepared, resp } => {
                    let apply_result = self.manager.apply_dirty_cache_commit(prepared).await;
                    let _ = resp.send(apply_result);
                }
            }
        }
    }
}
