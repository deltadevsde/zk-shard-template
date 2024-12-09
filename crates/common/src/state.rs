use std::sync::Arc;

use crate::{
    tree::KeyDirectoryTree,
    tx::{Transaction, TransactionType},
};
use anyhow::{anyhow, Result};
use jmt::storage::{TreeReader, TreeWriter};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct Account {
    nonce: u64,
}

impl Account {
    pub fn apply_tx(&mut self, tx: &Transaction) -> Result<()> {
        if tx.nonce != self.nonce {
            return Err(anyhow!("Invalid nonce"));
        }
        match tx.tx_type {
            TransactionType::Noop => {}
        }
        self.nonce += 1;
        Ok(())
    }
}

pub struct State<S>
where
    S: TreeReader + TreeWriter,
{
    jmt: KeyDirectoryTree<S>,
}

impl<S> State<S>
where
    S: TreeReader + TreeWriter,
{
    pub fn new(store: Arc<S>) -> Self {
        State {
            jmt: KeyDirectoryTree::new(store),
        }
    }

    /// Validates a transaction against the current chain state.
    /// Called during [`process_tx`], but can also be used independently, for
    /// example when queuing transactions to be batched.
    pub(crate) fn validate_tx(&self, tx: Transaction) -> Result<()> {
        tx.verify()?;
        match tx.tx_type {
            TransactionType::Noop => Ok(()),
        }
    }

    /// Processes a transaction by validating it and updating the state.
    pub(crate) fn process_tx(&mut self, tx: Transaction) -> Result<()> {
        self.validate_tx(tx.clone())?;
        match tx.tx_type {
            TransactionType::Noop => Ok(()),
        }
    }
}
