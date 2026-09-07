//! A running ledger of decision heads (alpibrusl/lex-k8s#13).
//!
//! Sealing (#12) closed half of the audit gap: after it, nobody without
//! the key can *rewrite* a decision. This is the other half, and it is
//! the half a seal structurally cannot reach.
//!
//! # Why a second chain
//!
//! Each admission gets its own `Chain<AdmissionEvent>`, written as its
//! own file. That has two consequences, and the second is the problem:
//!
//! 1. There is no tail to truncate, so a checkpoint over one decision
//!    commits to nothing worth committing to.
//! 2. **Deleting a whole decision file leaves no gap to notice.**
//!    Nothing counts the files, so nothing can say one is missing —
//!    and `rm` is the easiest thing anyone with the volume can do.
//!
//! A ledger is one long-lived chain the wall appends to after every
//! decision, carrying just enough to prove a decision existed: its
//! subject, its verdict, and the head of its own chain. That turns a
//! deleted file into a **visible gap** — the ledger names a head with
//! no file behind it — and it restores what checkpoints are for, since
//! a ledger *does* have a tail.
//!
//! # It is a witness, not a copy
//!
//! The ledger deliberately does not carry the decision's reasoning,
//! its effect rows, or its refusals. Those live in the decision chain,
//! which is sealed. Duplicating them here would mean two records that
//! can disagree, and then a question about which one is true. The
//! ledger answers exactly one question — *did this decision happen, and
//! what did it say* — and points at the record that answers the rest.
//!
//! # What it still does not fix
//!
//! A ledger on the same volume dies with the same pod. It is worth
//! having anyway, because it makes *silent* deletion into *detectable*
//! deletion for anyone holding a checkpoint — and the wall emits a
//! signed checkpoint to stdout on every append, which is the one place
//! a log collector already keeps things the pod does not own. Durable
//! storage is a separate decision; see the README's cautions.

use lex_os_audit::{Chain, ChainPayload};
use serde::{Deserialize, Serialize};

/// One decision, witnessed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LedgerEvent {
    /// The wall started, and with which sealing identity.
    ///
    /// First in every ledger, so a reader can tell a fresh ledger from
    /// a truncated one: a ledger that does not begin here has lost its
    /// head, whatever its hashes say.
    WallStarted {
        /// Hex Ed25519 public key sealing this ledger, when sealed.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signer: Option<String>,
        /// Where the decision chains are being written, if anywhere.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        audit_dir: Option<String>,
    },
    /// A pod admission, and the chain that records it.
    PodDecided {
        uid: String,
        namespace: String,
        name: String,
        /// `admitted` or `refused`.
        verdict: String,
        /// The head of that decision's own chain — the handle that
        /// makes a missing file detectable.
        decision_head: String,
        decision_entries: u64,
        /// The cluster state the verdict depended on.
        snapshot_sha256: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signer: Option<String>,
    },
    /// A `LexManifest` narrowing check.
    ///
    /// `/narrow` writes no chain of its own, so before this its
    /// verdicts reached the log and never the record — and a manifest
    /// that widens its parent is the more consequential of the two
    /// decisions this wall makes. Here it has one.
    ManifestDecided {
        uid: String,
        /// `<namespace>/<name>` of the child under review.
        child: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        parent: Option<String>,
        /// `narrows` or `widens`.
        verdict: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signer: Option<String>,
    },
}

impl ChainPayload for LedgerEvent {
    /// Distinct from `lex.k8s.audit.v1`, so a decision entry can never
    /// be replayed as a ledger entry or the reverse. The domain is
    /// hashed into every entry, which is what makes that structural
    /// rather than a naming convention.
    const DOMAIN: &'static [u8] = b"lex.k8s.ledger.v1";
}

/// The ledger: a chain of [`LedgerEvent`].
pub type Ledger = Chain<LedgerEvent>;

impl LedgerEvent {
    /// The decision chain head this entry witnesses, if it witnesses
    /// one.
    pub fn decision_head(&self) -> Option<&str> {
        match self {
            LedgerEvent::PodDecided { decision_head, .. } => Some(decision_head),
            _ => None,
        }
    }

    /// A one-line description for a reconciliation report.
    pub fn subject(&self) -> String {
        match self {
            LedgerEvent::WallStarted { .. } => "wall started".to_string(),
            LedgerEvent::PodDecided {
                namespace,
                name,
                verdict,
                ..
            } => format!("{namespace}/{name} {verdict}"),
            LedgerEvent::ManifestDecided { child, verdict, .. } => format!("{child} {verdict}"),
        }
    }
}

/// What a ledger and a directory of decision chains say about each
/// other.
///
/// Both directions, because they catch different things. A head the
/// ledger names with no file behind it is a **deleted decision** — the
/// attack this exists for. A file the ledger does not name is a
/// **planted decision**, or a ledger that lost its tail; either way the
/// two records disagree and a reader must be told rather than shown the
/// friendlier one.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Reconciliation {
    /// Heads the ledger witnesses that no file provides.
    pub missing: Vec<String>,
    /// Files present that the ledger never witnessed.
    pub unwitnessed: Vec<String>,
    /// Decisions matched in both directions.
    pub matched: usize,
}

impl Reconciliation {
    pub fn is_clean(&self) -> bool {
        self.missing.is_empty() && self.unwitnessed.is_empty()
    }
}

/// Reconcile a ledger against the decision-chain heads actually found.
///
/// Pure: the caller reads the directory, this decides. Same reason
/// `ClusterSnapshot` is an input — every case here is reachable from a
/// test without a filesystem.
pub fn reconcile(ledger: &Ledger, found_heads: &[String]) -> Reconciliation {
    let witnessed: Vec<&str> = ledger
        .entries()
        .iter()
        .filter_map(|e| e.event.decision_head())
        .collect();

    let missing = witnessed
        .iter()
        .filter(|h| !found_heads.iter().any(|f| f == *h))
        .map(|h| h.to_string())
        .collect::<Vec<_>>();

    let unwitnessed = found_heads
        .iter()
        .filter(|f| !witnessed.iter().any(|w| w == f))
        .cloned()
        .collect::<Vec<_>>();

    Reconciliation {
        matched: witnessed.len() - missing.len(),
        missing,
        unwitnessed,
    }
}
