use anyhow::{Context, Result};
use jmt::{proof::SparseMerkleProof, KeyHash};

use crate::{
    state::Account,
    tree::{Digest, Hasher},
    tx::Transaction,
};

/// Represents a contiguous stream of [`Proof`]s leading from [`Batch::prev_root`] to [`Batch::new_root`].
/// Used as the input to the circuit.
pub struct Batch {
    pub prev_root: Digest,
    pub new_root: Digest,

    pub proofs: Vec<Proof>,
}

pub enum Proof {
    Insert(InsertProof),
    Update(UpdateProof),
}

pub struct InsertProof {
    /// Proof that the key does not already exist in the tree (i.e. it's not overwriting an existing key)
    pub non_membership_proof: SparseMerkleProof<Hasher>,
    pub old_root: Digest,

    /// Proof that the new account is correctly inserted into the tree
    pub membership_proof: SparseMerkleProof<Hasher>,
    pub new_root: Digest,

    /// The transaction matching the new account (vk = key)
    pub tx: Transaction,
}

impl InsertProof {
    pub fn verify(&self) -> Result<()> {
        let key = KeyHash::with::<Hasher>(self.tx.vk.as_bytes());

        self.non_membership_proof
            .verify_nonexistence(self.old_root.into(), key)
            .context("Invalid NonMembershipProof")?;

        // verify that the account is correct
        let mut new_account = Account::default();
        new_account
            .apply_tx(&self.tx)
            .context("Transaction could not be applied to account")?;

        let value = bincode::serialize(&new_account)?;

        self.membership_proof
            .verify_existence(self.new_root.into(), key, value)
            .context("Invalid MembershipProof")?;

        Ok(())
    }
}

pub struct UpdateProof {
    /// Proof that [`old_account`] account is in the tree under [`old_root`]
    pub old_membership_proof: SparseMerkleProof<Hasher>,
    pub old_root: Digest,
    pub old_account: Account,

    /// Proof that [`new_account`] account is now in the tree under [`new_root`]
    pub membership_proof: SparseMerkleProof<Hasher>,
    pub new_root: Digest,

    /// The transaction that verifies the state transition from [`old_account`].
    pub tx: Transaction,
}

impl UpdateProof {
    pub fn verify(&self) -> Result<()> {
        let key = KeyHash::with::<Hasher>(self.tx.vk.as_bytes());
        let old_value = bincode::serialize(&self.old_account)?;
        self.old_membership_proof
            .verify_existence(self.old_root.into(), key, old_value)
            .context("Invalid OldMembershipProof")?;

        let mut new_account = self.old_account.clone();
        new_account
            .apply_tx(&self.tx)
            .context("Transaction could not be applied to account")?;

        let new_value = bincode::serialize(&new_account)?;
        self.membership_proof
            .verify_existence(self.new_root.into(), key, new_value)
            .context("Invalid MembershipProof")?;

        Ok(())
    }
}
