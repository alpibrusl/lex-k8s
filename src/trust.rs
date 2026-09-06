//! Who submitted the plan, and what their track record says.
//!
//! The gate's other inputs are all *supplied*, never looked up: the
//! plan, the cost estimate, the manifest. Trust is the same. lex-iac
//! does not open lex-lang's attestation store, hold a network
//! connection, or learn what an attestation is — the caller runs
//!
//! ```sh
//! lex producer-trust keyring --min-trust 700 --out trusted.json
//! ```
//!
//! and passes the resulting file in. That is the identical
//! `{"trusted":[…]}` artifact `lex-os capsule install --trusted-keys`
//! and `lex-iac check --trusted-keys` already consume; this crate is
//! its fourth reader, not a new format.
//!
//! # The signer is authenticated, not asserted
//!
//! Unlike lex-iac, this wall takes no `--signer`. The identity comes
//! from the `AdmissionReview`'s `userInfo.username`, which the API
//! server fills in after authenticating the requester. A webhook that
//! let its caller name the submitter would let any submitter spend
//! another's record.
//!
//! # The loop this closes
//!
//! ```text
//! admit --audit-out log.json
//!   → lex attest import-apply --audit log.json --gate kubernetes
//!         --accepted pod_admitted --refused pod_refused
//!   → lex producer-trust recompute --tool system:serviceaccount:payments:deployer
//!   → lex producer-trust keyring --min-trust 700 --out trusted.json
//!   → admit --trusted-keys trusted.json
//! ```
//!
//! A submitter's own record decides how much rope it gets next time.
//!
//! # Trust narrows; it never widens
//!
//! A high score waives nothing the manifest did not already allow. All
//! standing does is decide whether a **waiver the manifest already
//! granted** applies to this submitter. A manifest that names no
//! `imagePrefixes` has declared no image policy; a scored submitter is
//! admitted under that silence, and an unscored one is not. An unknown
//! submitter is held to the narrower reading of the same manifest —
//! never to a wider one. If a score could ever admit an effect the
//! manifest does not, that would be a second source of authority,
//! which is the one thing this project forbids.

use serde::{Deserialize, Serialize};

/// The `{"trusted":[…]}` keyring `lex producer-trust keyring` writes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Keyring {
    #[serde(default)]
    pub trusted: Vec<String>,
}

/// The keyring would not parse.
#[derive(Debug, thiserror::Error)]
pub enum TrustError {
    #[error("the keyring is not readable JSON: {0}")]
    Json(#[from] serde_json::Error),
}

impl Keyring {
    pub fn new(trusted: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Keyring {
            trusted: trusted.into_iter().map(Into::into).collect(),
        }
    }

    /// Parse `lex producer-trust keyring --out`'s output.
    ///
    /// An **empty** keyring is a keyring that trusts nobody, not one
    /// that trusts everybody — the same rule the manifest's allow-list
    /// follows, for the same reason. A file with no `trusted` array at
    /// all reads the same way: absent evidence is not evidence of
    /// absence (#8), and the direction that flatters a submitter is the
    /// wrong one to guess in.
    pub fn from_json(src: &str) -> Result<Self, TrustError> {
        Ok(serde_json::from_str(src)?)
    }

    pub fn admits(&self, signer: &str) -> bool {
        self.trusted.iter().any(|t| t == signer)
    }

    /// What this keyring says about `signer`.
    pub fn standing_of(&self, signer: &str) -> Standing {
        if self.admits(signer) {
            Standing::Trusted
        } else {
            Standing::Unknown
        }
    }
}

/// What the keyring says about a submitter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Standing {
    /// No keyring was supplied, so trust was not consulted. Distinct
    /// from [`Standing::Unknown`] on purpose: "we did not ask" and "we
    /// asked and they are not on it" are different facts, and a gate
    /// that reported them alike would be lying in one of the two cases.
    NotConsulted,
    /// In the keyring: scored at or above the threshold the operator
    /// exported at.
    Trusted,
    /// Not in the keyring — either never scored, or scored below the
    /// threshold. The gate cannot tell those apart from a keyring
    /// alone, and deliberately does not guess.
    Unknown,
}

impl Standing {
    /// Does this standing hold the submitter to the narrower reading of
    /// the manifest — no waivers for unchecked dimensions?
    pub fn needs_the_verb_named(self) -> bool {
        matches!(self, Standing::Unknown)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Standing::NotConsulted => "not-consulted",
            Standing::Trusted => "trusted",
            Standing::Unknown => "unknown",
        }
    }
}

/// Who submitted this pod.
///
/// A ServiceAccount or an agent key, as the API server authenticated
/// it. The wall records it and, when a keyring was supplied, consults
/// it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Submitter {
    pub signer: String,
    pub standing: Standing,
}

impl Submitter {
    /// A submitter whose trust was not consulted, because no keyring
    /// was supplied.
    pub fn unconsulted(signer: impl Into<String>) -> Self {
        Submitter {
            signer: signer.into(),
            standing: Standing::NotConsulted,
        }
    }

    /// A submitter checked against a keyring.
    pub fn against(signer: impl Into<String>, keyring: &Keyring) -> Self {
        let signer = signer.into();
        let standing = keyring.standing_of(&signer);
        Submitter { signer, standing }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_keyring_reads_the_shape_lex_lang_writes() {
        let k = Keyring::from_json(r#"{"trusted":["system:serviceaccount:payments:deployer"]}"#)
            .unwrap();
        assert!(k.admits("system:serviceaccount:payments:deployer"));
        assert!(!k.admits("system:serviceaccount:payments:other"));
    }

    /// The mirror of the allow-list rule: an empty list grants nothing.
    #[test]
    fn an_empty_keyring_trusts_nobody() {
        let k = Keyring::from_json(r#"{"trusted":[]}"#).unwrap();
        assert_eq!(
            k.standing_of("system:serviceaccount:payments:deployer"),
            Standing::Unknown
        );
    }

    /// A file with no `trusted` key is not a file that trusts everyone.
    #[test]
    fn a_keyring_without_the_field_trusts_nobody() {
        let k = Keyring::from_json("{}").unwrap();
        assert_eq!(
            k.standing_of("system:serviceaccount:payments:deployer"),
            Standing::Unknown
        );
    }

    #[test]
    fn a_malformed_keyring_is_an_error_not_an_empty_one() {
        assert!(Keyring::from_json("{not json").is_err());
    }

    /// "We did not ask" is not "we asked and they are not on it".
    #[test]
    fn not_consulted_is_not_the_same_as_unknown() {
        assert!(!Standing::NotConsulted.needs_the_verb_named());
        assert!(Standing::Unknown.needs_the_verb_named());
        assert!(!Standing::Trusted.needs_the_verb_named());
    }

    #[test]
    fn standing_comes_from_the_keyring() {
        let k = Keyring::new(["system:serviceaccount:payments:deployer"]);
        assert_eq!(
            Submitter::against("system:serviceaccount:payments:deployer", &k).standing,
            Standing::Trusted
        );
        assert_eq!(
            Submitter::against("system:serviceaccount:payments:other", &k).standing,
            Standing::Unknown
        );
        assert_eq!(
            Submitter::unconsulted("system:serviceaccount:payments:deployer").standing,
            Standing::NotConsulted
        );
    }
}
