//! What a pod asks for, in the vocabulary the grant is written in.
//!
//! `lex-os-check` compiles a `.lex` program to a set of effects and
//! refuses it when those exceed the manifest's [`Grant`]. This module
//! does the same for a `PodSpec`: every authority-bearing field becomes
//! an [`Effect`], every effect carries the [`Grant`] it demands, and a
//! pod's total demand is their join. The wall is then one comparison —
//! `Grant::narrow(manifest, demanded)` — rather than a rule list.
//!
//! # The mapping is a judgement call, and it is written down
//!
//! | pod declares | filesystem | network | exec |
//! | --- | --- | --- | --- |
//! | secret mounted or in env | `read-only` | — | — |
//! | `hostPath`, read-only | `read-write` | — | — |
//! | `hostPath`, writable | `full` | — | — |
//! | `privileged: true` | `full` | — | `full` |
//! | `hostPID` / `hostIPC` | — | — | `full` |
//! | `allowPrivilegeEscalation: true` | — | — | `full` |
//! | dangerous capability | — | — | `full` |
//! | other added capability | — | — | `sandboxed` |
//! | `hostNetwork: true` | — | `full` | — |
//! | egress policy permitting `0.0.0.0/0` | — | `full` | — |
//! | **no egress policy at all** | — | `full` | — |
//! | egress policy with rules | — | `allowlist` | — |
//! | egress deny-all | — | `none` | — |
//! | any RBAC binding | — | `allowlist` | — |
//! | unreadable field | *the widest it could imply* | | |
//!
//! There is deliberately **no baseline row**: a pod that declares nothing
//! demands nothing, so an ordinary container costs no authority at all.
//! Charging every pod a floor would make the interesting ones harder to
//! see, which is the opposite of the point.
//!
//! Two rows deserve their reasoning in the open.
//!
//! **A read-only `hostPath` is `read-write`, not `read-only`.** The
//! level describes reach, not the mount flag. Reading `/var/lib/kubelet`
//! or a node's certificates is not the same kind of act as reading your
//! own container filesystem, and grading it at rank 1 alongside a
//! mounted Secret would let a grant that meant the second authorise the
//! first.
//!
//! **No egress policy is `full`.** In Kubernetes a pod that no
//! `NetworkPolicy` selects has unrestricted egress. Reading absence as
//! "nothing declared, so nothing granted" would have the default
//! backwards on the most common cluster there is — and it is the same
//! mistake, in a new place, that alpibrusl/lex-iac#8 fixed.

use lex_os_manifest::{Grant, Level, Reversibility};
use serde::{Deserialize, Serialize};

use crate::spec::ContainerKind;

/// Where an effect came from, so a refusal names one line of YAML.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Source {
    /// `None` for pod-level fields.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<ContainerKind>,
    /// The field path, as an operator would grep for it.
    pub field: String,
}

impl Source {
    pub fn pod(field: impl Into<String>) -> Self {
        Source {
            container: None,
            kind: None,
            field: field.into(),
        }
    }

    pub fn container(kind: ContainerKind, name: &str, field: impl Into<String>) -> Self {
        Source {
            container: Some(name.to_string()),
            kind: Some(kind),
            field: field.into(),
        }
    }
}

impl std::fmt::Display for Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (&self.kind, &self.container) {
            (Some(k), Some(c)) => write!(f, "{}[{}].{}", k.as_str(), c, self.field),
            _ => write!(f, "spec.{}", self.field),
        }
    }
}

/// One thing a pod asks to be able to do.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "effect", rename_all = "snake_case")]
pub enum Effect {
    /// Shares the node's network namespace: every interface, and the
    /// node's own identity on the network.
    HostNetwork,
    /// Shares the node's PID or IPC namespace — visibility into, and
    /// signalling of, every other process on the node.
    HostNamespace { which: String },
    /// Effectively root on the node.
    Privileged,
    /// A process may gain privileges its parent did not have.
    PrivilegeEscalation,
    /// A Linux capability added beyond the default set.
    Capability { name: String, dangerous: bool },
    /// A path on the node, mounted into the pod.
    HostPath { path: String, writable: bool },
    /// A Secret reachable from inside the container.
    Secret { name: String, via: SecretVia },
    /// Reach outside the pod.
    Egress { reach: Reach, policies: Vec<String> },
    /// What the pod's ServiceAccount may do against the API.
    ApiAccess {
        resource: String,
        verbs: Vec<String>,
        cluster_wide: bool,
        /// Set when this permission is a route to authority the pod was
        /// not granted directly.
        escalation: Option<String>,
    },
    /// The image is not pinned by digest, or comes from a source the
    /// snapshot does not vouch for.
    UntrustedImage { image: String, why: ImageDoubt },
    /// A field this build could not read. Never harmless — see the
    /// module docs.
    Unreadable { detail: String },
}

/// How far a pod can reach off-pod.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Reach {
    /// A policy selects the pod and permits nothing.
    None,
    /// A policy selects the pod and permits specific destinations.
    Allowlist,
    /// A policy permits `0.0.0.0/0`.
    Unrestricted,
    /// **No policy selects the pod**, which in Kubernetes means
    /// unrestricted. Distinct from `Unrestricted` because the remedy
    /// differs: one is a policy to tighten, the other a policy to
    /// write.
    NoPolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecretVia {
    Volume,
    Projected,
    Env,
    EnvFrom,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ImageDoubt {
    /// A tag, not a digest. Tags are mutable: what was admitted is not
    /// necessarily what runs.
    NotPinned,
    /// `:latest`, or no tag at all — mutable and unnamed.
    Floating,
    /// Pinned, but from a prefix the snapshot does not vouch for.
    UntrustedSource,
}

/// Capabilities that are a full escape rather than a specific power.
///
/// Not exhaustive, and deliberately conservative in the *other*
/// direction from the usual list: anything not here is still an added
/// capability and still raises `exec`, just to `sandboxed` rather than
/// `full`. Getting this list wrong understates one pod; getting the
/// default wrong understates all of them.
const DANGEROUS_CAPABILITIES: &[&str] = &[
    "ALL",
    "SYS_ADMIN",
    "SYS_PTRACE",
    "SYS_MODULE",
    "SYS_RAWIO",
    "SYS_BOOT",
    "SYS_CHROOT",
    "DAC_READ_SEARCH",
    "DAC_OVERRIDE",
    "NET_ADMIN",
    "NET_RAW",
    "BPF",
    "PERFMON",
    "SETUID",
    "SETGID",
];

/// Is this capability an escape? Case- and prefix-insensitive, because
/// `CAP_SYS_ADMIN` and `sys_admin` are the same capability and a wall
/// that only matched one spelling is not a wall.
pub fn is_dangerous_capability(name: &str) -> bool {
    let n = name.trim().to_ascii_uppercase();
    let n = n.strip_prefix("CAP_").unwrap_or(&n);
    DANGEROUS_CAPABILITIES.contains(&n)
}

impl Effect {
    /// The grant this effect requires. A pod's demand is the join of
    /// these over every row.
    pub fn demands(&self) -> Grant {
        use Level::*;
        let (fs, net, exec) = match self {
            Effect::HostNetwork => (None, Full, None),
            Effect::HostNamespace { .. } => (None, None, Full),
            Effect::Privileged => (Full, None, Full),
            Effect::PrivilegeEscalation => (None, None, Full),
            Effect::Capability { dangerous, .. } => {
                (None, None, if *dangerous { Full } else { Sandboxed })
            }
            // Reach beyond the box, so rank 2 even read-only; writable
            // is the node's filesystem, which is rank 3. See the module
            // docs for why a read-only hostPath is not `read-only`.
            Effect::HostPath { writable, .. } => {
                (if *writable { Full } else { ReadWrite }, None, None)
            }
            Effect::Secret { .. } => (ReadOnly, None, None),
            Effect::Egress { reach, .. } => (
                None,
                match reach {
                    Reach::None => Level::None,
                    Reach::Allowlist => Allowlist,
                    Reach::Unrestricted | Reach::NoPolicy => Full,
                },
                None,
            ),
            // Reaching the API server is network reach; *what* it may
            // do there is facet material, checked in milestone 2. An
            // escalation path is exec-equivalent because creating a
            // privileged pod is privilege, one step removed.
            Effect::ApiAccess { escalation, .. } => (
                None,
                Allowlist,
                if escalation.is_some() { Full } else { None },
            ),
            // An image nobody vouches for could contain anything, but
            // it is still confined by everything else the pod declares.
            // Raising a level here would double-count; the row exists
            // so a policy can refuse on it explicitly.
            Effect::UntrustedImage { .. } => (None, None, None),
            // Refuse, don't downgrade: we could not read it, so assume
            // the most it could have meant.
            Effect::Unreadable { .. } => (Full, Full, Full),
        };
        Grant::new(fs, net, exec)
    }

    /// How hard this is to walk back, in lex-os's own vocabulary.
    ///
    /// Admission is the reversible moment — refusing a pod costs a
    /// retry. What is *not* reversible is what a pod does once it has
    /// the node: a privileged container or a writable `hostPath` can
    /// persist past its own lifetime, and evicting it afterwards does
    /// not undo that.
    pub fn reversibility(&self) -> Reversibility {
        match self {
            Effect::Privileged
            | Effect::HostNamespace { .. }
            | Effect::Capability {
                dangerous: true, ..
            }
            | Effect::HostPath { writable: true, .. }
            | Effect::Unreadable { .. } => Reversibility::IrreversibleConsequential,

            Effect::HostNetwork
            | Effect::PrivilegeEscalation
            | Effect::HostPath { .. }
            | Effect::Capability { .. }
            | Effect::Secret { .. }
            | Effect::UntrustedImage { .. } => Reversibility::IrreversibleBounded,

            Effect::ApiAccess { escalation, .. } => {
                if escalation.is_some() {
                    Reversibility::IrreversibleConsequential
                } else {
                    Reversibility::IrreversibleBounded
                }
            }
            Effect::Egress { reach, .. } => match reach {
                Reach::None => Reversibility::ReversibleCheap,
                Reach::Allowlist => Reversibility::IrreversibleBounded,
                // Data leaving the cluster does not come back.
                Reach::Unrestricted | Reach::NoPolicy => Reversibility::IrreversibleConsequential,
            },
        }
    }

    /// A short, stable name for logs and refusals.
    pub fn name(&self) -> String {
        match self {
            Effect::HostNetwork => "host-network".into(),
            Effect::HostNamespace { which } => format!("host-{which}"),
            Effect::Privileged => "privileged".into(),
            Effect::PrivilegeEscalation => "privilege-escalation".into(),
            Effect::Capability { name, .. } => format!("capability:{name}"),
            Effect::HostPath { path, writable } => {
                format!("host-path:{path}{}", if *writable { ":rw" } else { ":ro" })
            }
            Effect::Secret { name, .. } => format!("secret:{name}"),
            Effect::Egress { reach, .. } => format!("egress:{}", reach.as_str()),
            Effect::ApiAccess {
                resource,
                cluster_wide,
                ..
            } => format!(
                "api:{resource}{}",
                if *cluster_wide { ":cluster" } else { "" }
            ),
            Effect::UntrustedImage { image, .. } => format!("image:{image}"),
            Effect::Unreadable { .. } => "unreadable".into(),
        }
    }

    /// One sentence an operator can act on.
    pub fn explain(&self) -> String {
        match self {
            Effect::HostNetwork => {
                "shares the node's network namespace, so every interface and the node's \
                 own network identity are reachable"
                    .into()
            }
            Effect::HostNamespace { which } => format!(
                "shares the node's {which} namespace, so every other process on the node \
                 is visible and signallable"
            ),
            Effect::Privileged => "runs privileged, which is effectively root on the node".into(),
            Effect::PrivilegeEscalation => {
                "permits a process to gain privileges its parent did not have".into()
            }
            Effect::Capability { name, dangerous } => {
                if *dangerous {
                    format!("adds {name}, which is a route out of the container")
                } else {
                    format!("adds the capability {name}")
                }
            }
            Effect::HostPath { path, writable } => format!(
                "mounts the node's `{path}`{}",
                if *writable {
                    " with write access — changes outlive the pod"
                } else {
                    " read-only, which still reads files outside the pod"
                }
            ),
            Effect::Secret { name, via } => {
                format!("reaches the Secret `{name}` (via {})", via.as_str())
            }
            Effect::Egress { reach, policies } => match reach {
                Reach::NoPolicy => "no NetworkPolicy selects this pod, so its egress is \
                                    unrestricted — Kubernetes' default is open"
                    .into(),
                Reach::Unrestricted => match policies.as_slice() {
                    [] => "egress is unrestricted: a policy permits 0.0.0.0/0".into(),
                    [one] => format!("egress is unrestricted: `{one}` permits 0.0.0.0/0"),
                    many => format!(
                        "egress is unrestricted: one of `{}` permits 0.0.0.0/0",
                        many.join("`, `")
                    ),
                },
                Reach::Allowlist => "egress is restricted to named destinations".into(),
                Reach::None => "egress is denied entirely".into(),
            },
            Effect::ApiAccess {
                resource,
                verbs,
                cluster_wide,
                escalation,
            } => {
                let scope = if *cluster_wide {
                    "cluster-wide"
                } else {
                    "in its namespace"
                };
                match escalation {
                    Some(why) => format!("{} on `{resource}` {scope} — {why}", verbs.join("/")),
                    None => format!("{} on `{resource}` {scope}", verbs.join("/")),
                }
            }
            Effect::UntrustedImage { image, why } => match why {
                ImageDoubt::NotPinned => format!(
                    "`{image}` is pinned by tag, not digest — a tag can be repointed after \
                     admission, so what was admitted is not necessarily what runs"
                ),
                ImageDoubt::Floating => format!(
                    "`{image}` has a floating or absent tag, so the admitted image is not \
                     identified at all"
                ),
                ImageDoubt::UntrustedSource => {
                    format!("`{image}` is not from a source this snapshot vouches for")
                }
            },
            Effect::Unreadable { detail } => format!(
                "{detail} — this build cannot read it, so it is treated as the widest \
                 thing it could mean"
            ),
        }
    }
}

impl Reach {
    pub fn as_str(self) -> &'static str {
        match self {
            Reach::None => "none",
            Reach::Allowlist => "allowlist",
            Reach::Unrestricted => "unrestricted",
            Reach::NoPolicy => "no-policy",
        }
    }
}

impl SecretVia {
    pub fn as_str(self) -> &'static str {
        match self {
            SecretVia::Volume => "volume",
            SecretVia::Projected => "projected volume",
            SecretVia::Env => "env",
            SecretVia::EnvFrom => "envFrom",
        }
    }
}

/// The join of two grants, per axis. A pod's demand is the join over
/// all its effects: it needs the most that any one of them needs.
pub fn join(a: Grant, b: Grant) -> Grant {
    Grant::new(
        a.filesystem.join(b.filesystem),
        a.network.join(b.network),
        a.exec.join(b.exec),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_names_match_however_they_are_spelled() {
        for spelling in ["SYS_ADMIN", "CAP_SYS_ADMIN", "cap_sys_admin", " sys_admin "] {
            assert!(is_dangerous_capability(spelling), "{spelling}");
        }
        assert!(!is_dangerous_capability("NET_BIND_SERVICE"));
        assert!(!is_dangerous_capability("CHOWN"));
    }

    /// The row from the module docs that most needs defending: reach,
    /// not the mount flag, decides the level.
    #[test]
    fn a_read_only_host_path_outranks_a_mounted_secret() {
        let secret = Effect::Secret {
            name: "db".into(),
            via: SecretVia::Volume,
        }
        .demands();
        let host_ro = Effect::HostPath {
            path: "/var/lib/kubelet".into(),
            writable: false,
        }
        .demands();
        let host_rw = Effect::HostPath {
            path: "/".into(),
            writable: true,
        }
        .demands();

        assert!(secret.filesystem.rank() < host_ro.filesystem.rank());
        assert!(host_ro.filesystem.rank() < host_rw.filesystem.rank());
        assert_eq!(host_rw.filesystem, Level::Full);
    }

    /// Kubernetes' default is open. A wall that read "no policy" as
    /// "no reach" would pass every pod on the most common cluster
    /// there is.
    #[test]
    fn no_network_policy_demands_full_network() {
        let none = Effect::Egress {
            reach: Reach::NoPolicy,
            policies: vec![],
        };
        assert_eq!(none.demands().network, Level::Full);
        assert_eq!(
            none.reversibility(),
            Reversibility::IrreversibleConsequential
        );
        assert!(none.explain().contains("default is open"));

        // ...and it is distinguishable from a policy that permits
        // everything, because the fix is different.
        let open = Effect::Egress {
            reach: Reach::Unrestricted,
            policies: vec!["allow-all".into()],
        };
        assert_eq!(open.demands().network, Level::Full);
        assert_ne!(none.name(), open.name());
    }

    #[test]
    fn an_unreadable_field_demands_everything() {
        let d = Effect::Unreadable {
            detail: "securityContext is not an object".into(),
        }
        .demands();
        assert_eq!(d, Grant::new(Level::Full, Level::Full, Level::Full));
    }

    #[test]
    fn a_pods_demand_is_the_join_of_its_effects() {
        let demanded = [
            Effect::Secret {
                name: "db".into(),
                via: SecretVia::Env,
            },
            Effect::Egress {
                reach: Reach::Allowlist,
                policies: vec!["egress-api".into()],
            },
            Effect::Capability {
                name: "NET_BIND_SERVICE".into(),
                dangerous: false,
            },
        ]
        .iter()
        .map(Effect::demands)
        .fold(Grant::new(Level::None, Level::None, Level::None), join);

        assert_eq!(
            demanded,
            Grant::new(Level::ReadOnly, Level::Allowlist, Level::Sandboxed)
        );
    }

    #[test]
    fn a_source_reads_like_something_you_can_grep_for() {
        assert_eq!(Source::pod("hostNetwork").to_string(), "spec.hostNetwork");
        assert_eq!(
            Source::container(
                ContainerKind::Sidecar,
                "proxy",
                "securityContext.privileged"
            )
            .to_string(),
            "initContainers(sidecar)[proxy].securityContext.privileged"
        );
    }
}
