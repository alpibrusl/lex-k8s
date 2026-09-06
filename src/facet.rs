//! The `pod` facet: authority the trust lattice cannot name
//! (alpibrusl/lex-k8s#3).
//!
//! Milestone 1 compiles a pod to a [`Grant`] and the wall is one
//! comparison. That catches *how much* a pod reaches for, and it is
//! blind to *what*: `network: allowlist` says a pod may reach named
//! destinations, not which ones; `filesystem: read-only` says it may
//! read a Secret, not which Secret.
//!
//! Those live here, as a facet on the same [`Manifest`] — the pattern
//! lex-os#71 opened the slot for and lex-iac's `infra` facet was the
//! first user of.
//!
//! # Every field is a lattice, and there is no deny list
//!
//! | field | shape | narrows by |
//! | --- | --- | --- |
//! | `egress` | allow-list | subset |
//! | `secrets` | allow-list | subset |
//! | `capabilities` | allow-list | subset |
//! | `host_path` | ordered boolean | `false ≤ true` |
//! | `privileged` | ordered boolean | `false ≤ true` |
//! | `host_namespaces` | ordered boolean | `false ≤ true` |
//!
//! A deny list would not narrow: a child that omits one of its parent's
//! deny entries has *widened*. The claim against Gatekeeper is that we
//! narrow where it enumerates, so shipping one would concede the
//! argument. Same rule, same reason, as lex-iac's `infra` facet.
//!
//! # An empty allow-list grants nothing
//!
//! Not "unconstrained". A facet that omits `secrets` authorises no
//! Secret at all, which is the reading that fails safe — and the one an
//! operator writing their first manifest expects least, so it is said
//! plainly here and in the README.

use lex_os_manifest::{
    facet::{narrow_allowlist, Facet, FacetError},
    Level,
};
use serde::{Deserialize, Serialize};

use crate::effect::{Effect, Reach};

/// What a namespace's pods may reach, by name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PodFacet {
    /// Hosts, `host:port` entries or in-cluster selectors a pod may
    /// egress to. Empty grants none.
    #[serde(default)]
    pub egress: Vec<String>,
    /// Secrets a pod may mount or read into its environment. Empty
    /// grants none.
    #[serde(default)]
    pub secrets: Vec<String>,
    /// Linux capabilities a pod may add beyond the default set.
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// May a pod mount a path from the node?
    #[serde(default)]
    pub host_path: bool,
    /// May a pod run privileged?
    #[serde(default)]
    pub privileged: bool,
    /// May a pod share the node's PID or IPC namespace?
    #[serde(default)]
    pub host_namespaces: bool,
    /// Image prefixes this namespace accepts. Empty means the wall does
    /// not check provenance — distinct from `secrets`, because an empty
    /// image list cannot mean "no images" without refusing every pod.
    /// Recorded rather than silently permissive: see [`PodFacet::admits`].
    #[serde(default)]
    pub image_prefixes: Vec<String>,
    /// What `budget.max_money_cents` is denominated in.
    ///
    /// lex-os's budget is a bare integer, so nothing in it says which
    /// currency. A spend report in another one is refused rather than
    /// converted: EUR against a ceiling sized in USD is wrong by
    /// whatever the rate is that day, silently and in whichever
    /// direction.
    ///
    /// It lives on the facet rather than in webhook configuration
    /// because a child namespace that redenominated its budget would
    /// have widened it — ¥5000 is not $50 — so it has to narrow with
    /// everything else. Same reasoning, same field, as lex-iac's
    /// `infra` facet.
    #[serde(default = "default_currency")]
    pub currency: String,
}

fn default_currency() -> String {
    "USD".to_string()
}

impl Default for PodFacet {
    fn default() -> Self {
        PodFacet {
            egress: Vec::new(),
            secrets: Vec::new(),
            capabilities: Vec::new(),
            host_path: false,
            privileged: false,
            host_namespaces: false,
            image_prefixes: Vec::new(),
            currency: default_currency(),
        }
    }
}

/// Why a pod's effect is not authorised by the facet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Denial {
    /// A named thing the facet does not list.
    NotGranted { what: String, granted: Vec<String> },
    /// A boolean the facet withholds.
    Withheld { what: String },
}

impl std::fmt::Display for Denial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Denial::NotGranted { what, granted } if granted.is_empty() => {
                write!(f, "the manifest grants none, so `{what}` is not among them")
            }
            Denial::NotGranted { what, granted } => write!(
                f,
                "`{what}` is not among the {} the manifest grants: {}",
                granted.len(),
                granted.join(", ")
            ),
            Denial::Withheld { what } => {
                write!(f, "the manifest does not grant {what}")
            }
        }
    }
}

impl Facet for PodFacet {
    const NAME: &'static str = "pod";

    fn validate_narrowing(parent: &Self, child: &Self) -> Result<(), FacetError> {
        narrow_allowlist(
            Self::NAME,
            "egress",
            parent.egress.iter().map(String::as_str),
            child.egress.iter().map(String::as_str),
        )?;
        narrow_allowlist(
            Self::NAME,
            "secrets",
            parent.secrets.iter().map(String::as_str),
            child.secrets.iter().map(String::as_str),
        )?;
        narrow_allowlist(
            Self::NAME,
            "capabilities",
            parent.capabilities.iter().map(String::as_str),
            child.capabilities.iter().map(String::as_str),
        )?;
        // An empty parent list is the *tightest* image policy a facet
        // can express here, so a child that adds prefixes has widened.
        narrow_allowlist(
            Self::NAME,
            "imagePrefixes",
            parent.image_prefixes.iter().map(String::as_str),
            child.image_prefixes.iter().map(String::as_str),
        )?;

        // A child may not redenominate its budget: the ceiling is an
        // integer, so changing the unit changes the ceiling.
        if !parent.currency.eq_ignore_ascii_case(&child.currency) {
            return Err(FacetError::new(
                Self::NAME,
                format!(
                    "currency: child is denominated in `{}` but the parent grants \
                     `{}` — a budget in another unit is a different budget",
                    child.currency, parent.currency
                ),
            ));
        }

        // Ordered booleans: `false ≤ true`.
        for (field, p, c) in [
            ("hostPath", parent.host_path, child.host_path),
            ("privileged", parent.privileged, child.privileged),
            (
                "hostNamespaces",
                parent.host_namespaces,
                child.host_namespaces,
            ),
        ] {
            if c && !p {
                return Err(FacetError::new(
                    Self::NAME,
                    format!(
                        "{field}: child claims it, and the parent does not grant it \
                         (a team lead hands out authority they hold, never authority \
                         they do not)"
                    ),
                ));
            }
        }
        Ok(())
    }
}

impl PodFacet {
    /// Is this effect authorised by name?
    ///
    /// Only the effects the lattice cannot describe are checked here.
    /// The rest — `Grant`-level reach — is milestone 1's wall, and
    /// running both is the point: one bounds how far, the other bounds
    /// where.
    pub fn admits(&self, effect: &Effect) -> Result<(), Denial> {
        match effect {
            Effect::Secret { name, .. } => self.named("Secret", name, &self.secrets),
            Effect::Capability { name, .. } => {
                // Normalised the way the pod spec might spell it:
                // `CAP_NET_ADMIN` and `NET_ADMIN` are one capability.
                let wanted = strip_cap(name);
                if self
                    .capabilities
                    .iter()
                    .any(|g| strip_cap(g).eq_ignore_ascii_case(&wanted))
                {
                    Ok(())
                } else {
                    Err(Denial::NotGranted {
                        what: name.clone(),
                        granted: self.capabilities.clone(),
                    })
                }
            }
            Effect::HostPath { path, .. } => {
                if self.host_path {
                    Ok(())
                } else {
                    Err(Denial::NotGranted {
                        what: path.clone(),
                        granted: Vec::new(),
                    })
                }
            }
            Effect::Privileged => self.boolean("privileged containers", self.privileged),
            Effect::HostNamespace { which } => self.boolean(
                &format!("the node's {which} namespace"),
                self.host_namespaces,
            ),
            // `hostNetwork` is the node's network namespace, which is
            // strictly more than any egress allow-list can describe:
            // it reaches every interface the node has, including the
            // ones no policy selects. Governed by `hostNamespaces`
            // rather than by `egress`, because listing hosts would
            // imply a bound that does not exist.
            Effect::HostNetwork => {
                self.boolean("the node's network namespace", self.host_namespaces)
            }
            Effect::Egress { reach, .. } => match reach {
                // Nothing named to check: the pod is denied egress, or
                // restricted to destinations the policy already bounds.
                Reach::None => Ok(()),
                Reach::Allowlist => Ok(()),
                // Unbounded reach cannot be admitted by an allow-list
                // of hosts — that is the mismatch this wall exists for.
                Reach::Unrestricted | Reach::NoPolicy => Err(Denial::NotGranted {
                    what: "0.0.0.0/0".to_string(),
                    granted: self.egress.clone(),
                }),
            },
            Effect::UntrustedImage { image, .. } => {
                if self.image_prefixes.is_empty() {
                    // No policy declared. Recorded by the caller as an
                    // unchecked dimension rather than treated as a pass
                    // — see `AdmissionDecision::unchecked`.
                    return Ok(());
                }
                if self
                    .image_prefixes
                    .iter()
                    .any(|p| !p.is_empty() && image.starts_with(p.as_str()))
                {
                    Ok(())
                } else {
                    Err(Denial::NotGranted {
                        what: image.clone(),
                        granted: self.image_prefixes.clone(),
                    })
                }
            }
            // Escalation and API reach are lattice-level: milestone 1
            // already lifts them into `Grant`, and naming them here
            // would check the same thing twice with two answers.
            Effect::PrivilegeEscalation | Effect::ApiAccess { .. } => Ok(()),
            // Refuse, don't downgrade — but the lattice already demands
            // everything for this, so the `Grant` wall refuses it first
            // and with a better message.
            Effect::Unreadable { .. } => Ok(()),
        }
    }

    fn named(&self, what: &str, name: &str, granted: &[String]) -> Result<(), Denial> {
        if granted.iter().any(|g| g == name) {
            Ok(())
        } else {
            Err(Denial::NotGranted {
                what: format!("{what} `{name}`"),
                granted: granted.to_vec(),
            })
        }
    }

    fn boolean(&self, what: &str, granted: bool) -> Result<(), Denial> {
        if granted {
            Ok(())
        } else {
            Err(Denial::Withheld {
                what: what.to_string(),
            })
        }
    }

    /// The `Grant` this facet implies on its own.
    ///
    /// Used to build a manifest from a `LexManifest` spec: an operator
    /// writes what pods may do, and the lattice ceiling follows from it
    /// rather than being restated. Two places to keep in step is one
    /// too many.
    pub fn implied_grant(&self, exec: Level) -> lex_os_manifest::Grant {
        use Level::*;
        let filesystem = if self.privileged || self.host_path {
            // A writable node path, or privileged, is the node's
            // filesystem. `host_path` alone cannot distinguish a
            // read-only mount at manifest level, so it grants the
            // ceiling that allows either.
            Full
        } else if !self.secrets.is_empty() {
            ReadOnly
        } else {
            Level::None
        };
        let network = if self.host_namespaces {
            Full
        } else if self.egress.is_empty() {
            Level::None
        } else {
            Allowlist
        };
        let exec = if self.privileged || self.host_namespaces {
            Full
        } else if self.capabilities.is_empty() {
            exec
        } else {
            exec.join(Sandboxed)
        };
        lex_os_manifest::Grant::new(filesystem, network, exec)
    }
}

fn strip_cap(name: &str) -> String {
    let n = name.trim().to_ascii_uppercase();
    n.strip_prefix("CAP_").unwrap_or(&n).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::effect::SecretVia;

    fn facet() -> PodFacet {
        PodFacet {
            egress: vec!["postgres.payments.svc".into(), "api.stripe.com:443".into()],
            secrets: vec!["stripe-live-key".into()],
            capabilities: vec!["NET_BIND_SERVICE".into()],
            ..Default::default()
        }
    }

    #[test]
    fn a_named_secret_is_admitted_and_an_unnamed_one_is_not() {
        let f = facet();
        assert!(f
            .admits(&Effect::Secret {
                name: "stripe-live-key".into(),
                via: SecretVia::Volume
            })
            .is_ok());

        let denial = f
            .admits(&Effect::Secret {
                name: "root-ca-key".into(),
                via: SecretVia::Env,
            })
            .unwrap_err();
        assert!(denial.to_string().contains("root-ca-key"));
        assert!(denial.to_string().contains("stripe-live-key"));
    }

    /// `CAP_NET_ADMIN` and `NET_ADMIN` are one capability, and a wall
    /// that matched only one spelling would be trivially bypassed.
    #[test]
    fn capabilities_match_however_either_side_spells_them() {
        let f = PodFacet {
            capabilities: vec!["CAP_NET_BIND_SERVICE".into()],
            ..Default::default()
        };
        for spelling in [
            "NET_BIND_SERVICE",
            "CAP_NET_BIND_SERVICE",
            "net_bind_service",
        ] {
            assert!(
                f.admits(&Effect::Capability {
                    name: spelling.into(),
                    dangerous: false
                })
                .is_ok(),
                "{spelling}"
            );
        }
        assert!(f
            .admits(&Effect::Capability {
                name: "SYS_ADMIN".into(),
                dangerous: true
            })
            .is_err());
    }

    /// The demo's wall. An allow-list of hosts cannot admit unbounded
    /// reach — that is the mismatch the whole milestone exists to
    /// refuse.
    #[test]
    fn an_allowlist_cannot_admit_unbounded_egress() {
        let f = facet();
        assert!(f
            .admits(&Effect::Egress {
                reach: Reach::Allowlist,
                policies: vec!["payments-egress".into()]
            })
            .is_ok());

        for open in [Reach::Unrestricted, Reach::NoPolicy] {
            let denial = f
                .admits(&Effect::Egress {
                    reach: open,
                    policies: vec![],
                })
                .unwrap_err();
            assert!(
                denial.to_string().contains("api.stripe.com:443"),
                "the refusal names what the manifest does grant: {denial}"
            );
        }
    }

    /// `hostNetwork` is not an egress question. Listing hosts beside it
    /// would imply a bound that does not exist.
    #[test]
    fn host_network_is_governed_by_namespaces_not_egress() {
        let generous_egress = PodFacet {
            egress: vec!["0.0.0.0/0".into()],
            ..Default::default()
        };
        assert!(generous_egress.admits(&Effect::HostNetwork).is_err());

        let allows = PodFacet {
            host_namespaces: true,
            ..Default::default()
        };
        assert!(allows.admits(&Effect::HostNetwork).is_ok());
    }

    #[test]
    fn an_empty_allowlist_grants_nothing_rather_than_everything() {
        let f = PodFacet::default();
        let denial = f
            .admits(&Effect::Secret {
                name: "anything".into(),
                via: SecretVia::Env,
            })
            .unwrap_err();
        assert!(denial.to_string().contains("grants none"), "{denial}");
        assert!(f.admits(&Effect::Privileged).is_err());
        assert!(f
            .admits(&Effect::HostPath {
                path: "/".into(),
                writable: true
            })
            .is_err());
    }

    /// The narrowing wall on manifests themselves — the piece
    /// Gatekeeper structurally lacks.
    #[test]
    fn a_child_manifest_cannot_hand_itself_what_its_parent_lacks() {
        let parent = facet();

        let tighter = PodFacet {
            egress: vec!["postgres.payments.svc".into()],
            secrets: vec![],
            capabilities: vec![],
            ..Default::default()
        };
        assert!(PodFacet::validate_narrowing(&parent, &tighter).is_ok());

        for (label, child) in [
            (
                "an egress host the parent never held",
                PodFacet {
                    egress: vec!["evil.example.com:443".into()],
                    ..parent.clone()
                },
            ),
            (
                "a Secret the parent never held",
                PodFacet {
                    secrets: vec!["root-ca-key".into()],
                    ..parent.clone()
                },
            ),
            (
                "privileged, which the parent withholds",
                PodFacet {
                    privileged: true,
                    ..parent.clone()
                },
            ),
            (
                "hostPath, which the parent withholds",
                PodFacet {
                    host_path: true,
                    ..parent.clone()
                },
            ),
            (
                "the node's namespaces",
                PodFacet {
                    host_namespaces: true,
                    ..parent.clone()
                },
            ),
        ] {
            assert!(
                PodFacet::validate_narrowing(&parent, &child).is_err(),
                "{label} must be refused"
            );
        }
    }

    /// The ceiling follows from what pods may do, rather than being
    /// restated beside it — two places to keep in step is one too many.
    #[test]
    fn the_lattice_ceiling_follows_from_the_facet() {
        let modest = facet().implied_grant(Level::Sandboxed);
        assert_eq!(modest.filesystem, Level::ReadOnly, "one Secret");
        assert_eq!(modest.network, Level::Allowlist, "two named hosts");
        assert_eq!(modest.exec, Level::Sandboxed, "one capability");

        let nothing = PodFacet::default().implied_grant(Level::None);
        assert_eq!(
            nothing.network,
            Level::None,
            "no egress named, none granted"
        );
        assert_eq!(nothing.filesystem, Level::None);

        let permissive = PodFacet {
            privileged: true,
            ..facet()
        }
        .implied_grant(Level::Sandboxed);
        assert_eq!(permissive.filesystem, Level::Full);
        assert_eq!(permissive.exec, Level::Full);
    }
}
