use anyhow::{anyhow, Result};
use jmt::SimpleHasher;
use jmt::{
    self,
    storage::{NodeBatch, TreeReader, TreeUpdateBatch, TreeWriter},
    JellyfishMerkleTree, KeyHash, RootHash,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub const SPARSE_MERKLE_PLACEHOLDER_HASH: Digest =
    Digest::new(*b"SPARSE_MERKLE_PLACEHOLDER_HASH__");

#[derive(Debug, Clone, Default)]
pub struct Hasher(sha2::Sha256);

impl Hasher {
    pub fn new() -> Self {
        Self(sha2::Sha256::new())
    }

    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    pub fn finalize(self) -> [u8; 32] {
        self.0.finalize()
    }
}

impl SimpleHasher for Hasher {
    fn new() -> Self {
        Self::new()
    }

    fn update(&mut self, data: &[u8]) {
        self.update(data);
    }

    fn finalize(self) -> [u8; 32] {
        self.finalize()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Copy)]
pub struct Digest(pub [u8; 32]);

impl Digest {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Digest(bytes)
    }

    pub fn hash(data: impl AsRef<[u8]>) -> Self {
        let mut hasher = Hasher::new();
        hasher.update(data.as_ref());
        Self(hasher.finalize())
    }

    pub fn hash_items(items: &[impl AsRef<[u8]>]) -> Self {
        let mut hasher = Hasher::new();
        for item in items {
            hasher.update(item.as_ref());
        }
        Self(hasher.finalize())
    }

    pub const fn zero() -> Self {
        Self([0u8; 32])
    }
}

impl From<Digest> for RootHash {
    fn from(val: Digest) -> RootHash {
        RootHash::from(val.0)
    }
}

impl From<RootHash> for Digest {
    fn from(val: RootHash) -> Digest {
        Digest(val.0)
    }
}

/// Wraps a [`JellyfishMerkleTree`] to provide a key-value store for [`Hashchain`]s with batched insertions.
/// This is prism's primary data structure for storing and retrieving [`Hashchain`]s.
pub struct KeyDirectoryTree<S>
where
    S: TreeReader + TreeWriter,
{
    pub(crate) jmt: JellyfishMerkleTree<Arc<S>, Hasher>,
    pub(crate) epoch: u64,
    pending_batch: Option<NodeBatch>,
    db: Arc<S>,
}

impl<S> KeyDirectoryTree<S>
where
    S: TreeReader + TreeWriter,
{
    pub fn new(store: Arc<S>) -> Self {
        let tree = Self {
            db: store.clone(),
            jmt: JellyfishMerkleTree::<Arc<S>, Hasher>::new(store),
            pending_batch: None,
            epoch: 0,
        };
        let (_, batch) = tree
            .jmt
            .put_value_set(vec![(KeyHash(SPARSE_MERKLE_PLACEHOLDER_HASH.0), None)], 0)
            .unwrap();
        tree.db.write_node_batch(&batch.node_batch).unwrap();
        tree
    }

    pub fn load(store: Arc<S>, epoch: u64) -> Self {
        if epoch == 0 {
            return KeyDirectoryTree::new(store);
        }
        Self {
            db: store.clone(),
            jmt: JellyfishMerkleTree::<Arc<S>, Hasher>::new(store),
            pending_batch: None,
            epoch,
        }
    }

    pub fn get_commitment(&self) -> Result<Digest> {
        let root = self.get_current_root()?;
        Ok(Digest::new(root.0))
    }

    pub(crate) fn queue_batch(&mut self, batch: TreeUpdateBatch) {
        match self.pending_batch {
            Some(ref mut pending_batch) => pending_batch.merge(batch.node_batch),
            None => self.pending_batch = Some(batch.node_batch),
        }
    }

    pub(crate) fn write_batch(&mut self) -> Result<()> {
        if let Some(batch) = self.pending_batch.take() {
            self.db.write_node_batch(&batch)?;
            self.epoch += 1;
        }
        Ok(())
    }

    pub fn get_current_root(&self) -> Result<RootHash> {
        self.jmt
            .get_root_hash(self.epoch)
            .map_err(|e| anyhow!("Failed to get root hash: {}", e))
    }
}
