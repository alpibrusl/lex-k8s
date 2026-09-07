//! The running ledger, as the server holds it (alpibrusl/lex-k8s#13).
//!
//! [`crate::ledger`] is the vocabulary and the reconciliation rule, and
//! is pure. This is the part that owns one for the life of a process:
//! a lock, a file, and a signed checkpoint on every append.
//!
//! # Why a checkpoint per append rather than a timer
//!
//! A checkpoint is one Ed25519 signature over `(domain, len, head)` —
//! cheap enough that "every decision" costs less than deciding when to
//! do it. And a periodic checkpoint has a window: every decision made
//! since the last one can be truncated without contradicting anything.
//!
//! Each checkpoint goes to **stdout**, which is the one place a log
//! collector already keeps things this pod does not own. That is the
//! whole mechanism, and it is not cryptographic: a checkpoint kept
//! beside the ledger it commits to proves nothing, because whoever
//! truncates one can replace the other.

use std::path::PathBuf;
use std::sync::Mutex;

use crate::{Ledger as Chain, LedgerEvent, SigningKey};

/// One ledger, one lock, one file.
pub struct Ledger {
    inner: Mutex<Chain>,
    path: Option<PathBuf>,
    /// Signs the checkpoints. The chain seals its own entries; this is
    /// the same key, kept so a commitment can be made without reaching
    /// back into the chain for it.
    key: Option<SigningKey>,
}

#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    #[error("the ledger lock was poisoned by a panic in another request")]
    Poisoned,
    #[error("could not write the ledger to {path}: {source}")]
    Write {
        path: String,
        source: std::io::Error,
    },
    #[error("could not serialise the ledger: {0}")]
    Serialise(String),
}

impl Ledger {
    /// Start a ledger, sealed if a key was supplied, and witness the
    /// start.
    ///
    /// The `WallStarted` entry is first in every ledger so a reader can
    /// tell a fresh ledger from one that lost its head: a ledger not
    /// beginning here has been truncated from the front, whatever its
    /// hashes say. (The chain catches deletion from the *middle*; the
    /// first entry is the one place it cannot.)
    pub fn start(
        path: Option<PathBuf>,
        key: Option<SigningKey>,
        audit_dir: Option<String>,
    ) -> Result<Self, LedgerError> {
        let chain = match &key {
            Some(k) => Chain::new().sealed_with(k.clone()),
            None => Chain::new(),
        };
        let ledger = Self {
            inner: Mutex::new(chain),
            path,
            key,
        };
        ledger.witness(LedgerEvent::WallStarted {
            signer: ledger
                .key
                .as_ref()
                .map(|k| hex::encode(k.verifying_key().to_bytes())),
            audit_dir,
        })?;
        Ok(ledger)
    }

    /// Append one witness, persist, and publish a signed commitment.
    ///
    /// The order is deliberate: append, write, *then* announce. A
    /// checkpoint naming a length that never reached the disk would be
    /// a commitment to a ledger nobody has.
    pub fn witness(&self, event: LedgerEvent) -> Result<(), LedgerError> {
        let mut chain = self.inner.lock().map_err(|_| LedgerError::Poisoned)?;
        let subject = event.subject();
        chain.append(event);

        if let Some(path) = &self.path {
            let json = chain
                .to_json()
                .map_err(|e| LedgerError::Serialise(e.to_string()))?;
            // Whole-file rewrite. The ledger is one small chain and this
            // keeps it a single valid JSON document at every instant —
            // an appended-to file that a reader can catch mid-write is
            // a ledger that reports corruption it does not have.
            std::fs::write(path, json).map_err(|e| LedgerError::Write {
                path: path.display().to_string(),
                source: e,
            })?;
        }

        match &self.key {
            Some(k) => {
                let cp = chain.checkpoint(k, now_secs());
                // Structured, so a collector can pick the fields out
                // without parsing prose. This line is the artifact that
                // outlives the pod.
                tracing::info!(
                    ledger_len = cp.len,
                    ledger_head = %cp.head,
                    at = cp.at,
                    signer = %cp.signer,
                    signature = %cp.signature,
                    domain = %cp.domain,
                    witnessed = %subject,
                    "ledger checkpoint"
                );
            }
            None => tracing::info!(
                ledger_len = chain.len(),
                ledger_head = %chain.head(),
                witnessed = %subject,
                "ledger appended (UNSIGNED — no --audit-key-file, so this commits to nothing)"
            ),
        }
        Ok(())
    }

    /// The current length and head, for `/readyz` and tests.
    pub fn state(&self) -> Result<(usize, String), LedgerError> {
        let chain = self.inner.lock().map_err(|_| LedgerError::Poisoned)?;
        Ok((chain.len(), chain.head()))
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
