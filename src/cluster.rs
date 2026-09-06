//! What the pod's authority depends on but its spec does not contain.
//!
//! A `PodSpec` alone does not say what the pod can reach. Its egress is
//! decided by the `NetworkPolicy` objects that select it; its API reach
//! by the RoleBindings attached to its ServiceAccount. Both live
//! elsewhere in the cluster.
//!
//! # This is an input, not a lookup
//!
//! alpibrusl/lex-k8s#2 asks for the decision to be made early, so:
//! **the compiler takes a snapshot.** [`compile`](crate::compile) is a
//! pure function of `(PodSpec, ClusterSnapshot)` and never talks to an
//! API server.
//!
//! Three reasons, in order of how much they matter:
//!
//! 1. A wall that queries mid-admission is a wall whose verdict depends
//!    on when it ran. The snapshot is part of what gets attested — a
//!    decision you cannot reproduce is a decision you cannot audit.
//! 2. Every case below is reachable from a fixture, so the interesting
//!    ones get tested rather than described.
//! 3. The API server is calling *us*, inside its request path. Calling
//!    back into it to decide is a deadlock waiting for a bad afternoon.
//!
//! The webhook in milestone 2 builds the snapshot from informer caches
//! before it decides. That is where staleness gets handled, and it is a
//! separate problem from this one.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// The cluster state a verdict depends on, captured at one instant.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterSnapshot {
    /// Egress as the cluster will actually enforce it.
    ///
    /// `None` is the case that matters: **no policy selects this pod**,
    /// which in Kubernetes means unrestricted egress. Absence of a
    /// policy is not absence of reach, and a wall that read it as
    /// "nothing declared, so nothing granted" would have the default
    /// exactly backwards on the most common cluster there is.
    #[serde(default)]
    pub egress: Option<EgressPolicy>,
    /// What the pod's ServiceAccount may do, already resolved through
    /// its Role and ClusterRole bindings.
    #[serde(default)]
    pub rbac: Vec<RbacRule>,
    /// Image references this cluster will accept as signed, by prefix.
    /// Empty means nothing is known to be signed — see
    /// [`ClusterSnapshot::trusts_image`].
    #[serde(default)]
    pub trusted_image_prefixes: Vec<String>,
    /// Anything else the caller wants folded into the snapshot's
    /// identity. Not interpreted; it exists so a webhook can pin the
    /// resource versions it read without this crate learning what a
    /// resource version is.
    #[serde(default)]
    pub provenance: BTreeMap<String, String>,
}

/// The egress a NetworkPolicy permits, flattened.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressPolicy {
    /// The policies that produced this, for a refusal to name.
    #[serde(default)]
    pub policy_names: Vec<String>,
    /// CIDRs the pod may reach. `0.0.0.0/0` (or `::/0`) is unrestricted
    /// and is recognised as such.
    #[serde(default)]
    pub cidrs: Vec<String>,
    /// In-cluster destinations, as human-legible selectors. Not parsed:
    /// they narrow reach within the cluster, which the lattice models
    /// as an allowlist either way.
    #[serde(default)]
    pub selectors: Vec<String>,
    /// True when a policy selects the pod for `Egress` but permits
    /// nothing — a deny-all, which is the tightest a pod can be.
    #[serde(default)]
    pub deny_all: bool,
}

impl EgressPolicy {
    /// Does this policy permit reaching anything at all outside the
    /// cluster?
    ///
    /// A `/0` CIDR is unrestricted however it is spelled, and however
    /// many narrower rules sit beside it: NetworkPolicy rules are a
    /// union, so one open rule opens the pod.
    pub fn is_unrestricted(&self) -> bool {
        self.cidrs.iter().any(|c| {
            let c = c.trim();
            c == "0.0.0.0/0" || c == "::/0"
        })
    }

    /// Nothing permitted at all.
    pub fn permits_nothing(&self) -> bool {
        self.deny_all || (self.cidrs.is_empty() && self.selectors.is_empty())
    }
}

/// One resolved RBAC permission.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RbacRule {
    /// Where it came from, for a refusal to name.
    #[serde(default)]
    pub binding: String,
    /// `""` is the core API group, as in Kubernetes itself.
    #[serde(default)]
    pub api_group: String,
    #[serde(default)]
    pub resource: String,
    #[serde(default)]
    pub verbs: Vec<String>,
    /// `None` means cluster-wide — a ClusterRoleBinding, not a
    /// RoleBinding. The distinction is most of the blast radius.
    #[serde(default)]
    pub namespace: Option<String>,
}

impl RbacRule {
    pub fn cluster_wide(&self) -> bool {
        self.namespace.is_none()
    }

    /// Does this rule permit `verb`? `*` permits everything, which is
    /// the point of checking rather than string-matching.
    pub fn permits(&self, verb: &str) -> bool {
        self.verbs.iter().any(|v| v == "*" || v == verb)
    }

    /// Verbs that change the cluster, as opposed to reading it.
    pub fn is_write(&self) -> bool {
        [
            "create",
            "update",
            "patch",
            "delete",
            "deletecollection",
            "*",
        ]
        .iter()
        .any(|v| self.permits(v))
    }

    /// Does this rule hand its holder a route to authority it was not
    /// granted directly?
    ///
    /// Three well-known ones, and they are worth naming individually
    /// because each is a complete escape rather than a broad
    /// permission:
    ///
    /// - **reading secrets** is reading every credential in scope,
    ///   including other ServiceAccounts' tokens;
    /// - **creating pods** (or anything that creates pods) is creating
    ///   a *privileged* pod, so it is `privileged: true` at one
    ///   remove;
    /// - **bindings and escalate/impersonate** are the API's own
    ///   privilege-escalation verbs.
    ///
    /// A wall that scored these the same as `get configmaps` would
    /// report the wrong pod as the dangerous one.
    pub fn escalation_path(&self) -> Option<&'static str> {
        let core = self.api_group.is_empty();
        if core && self.resource == "secrets" && (self.permits("get") || self.permits("list")) {
            return Some("can read Secrets, which includes other ServiceAccounts' tokens");
        }
        if core && self.resource == "pods" && self.permits("create") {
            return Some("can create Pods, and so can create a privileged one");
        }
        if matches!(
            self.resource.as_str(),
            "deployments" | "daemonsets" | "statefulsets" | "jobs" | "cronjobs" | "replicasets"
        ) && self.is_write()
        {
            return Some("can write workloads, which create Pods on its behalf");
        }
        if self.permits("escalate") || self.permits("bind") || self.permits("impersonate") {
            return Some("holds an API privilege-escalation verb (escalate/bind/impersonate)");
        }
        if self.resource == "*" && self.permits("*") {
            return Some("holds `*` on `*` — unrestricted API authority");
        }
        None
    }
}

impl ClusterSnapshot {
    /// Is this image reference one the cluster is known to accept?
    ///
    /// Prefix matching, deliberately: this crate does not verify
    /// signatures — it has no keys, no registry access and no business
    /// doing crypto in an admission path. It records what the snapshot
    /// asserts. Milestone 3 turns accepted admissions into attestations
    /// and *that* is where trust gets earned rather than declared.
    ///
    /// An empty list means nothing is trusted, not that everything is.
    pub fn trusts_image(&self, image: &str) -> bool {
        self.trusted_image_prefixes
            .iter()
            .any(|p| !p.is_empty() && image.starts_with(p.as_str()))
    }

    /// Hex SHA-256 over the canonical form. The handle an audit record
    /// pins, so a verdict can be reproduced against the cluster state
    /// it was actually made on.
    pub fn content_id(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"lex.k8s.snapshot.v1");
        h.update(
            serde_json::to_string(self)
                .expect("snapshot is serializable")
                .as_bytes(),
        );
        hex::encode(h.finalize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_slash_zero_cidr_is_unrestricted_however_it_is_spelled() {
        for cidr in ["0.0.0.0/0", "::/0", " 0.0.0.0/0 "] {
            let p = EgressPolicy {
                cidrs: vec![cidr.into()],
                ..Default::default()
            };
            assert!(p.is_unrestricted(), "{cidr}");
        }
        let narrow = EgressPolicy {
            cidrs: vec!["10.0.0.0/8".into()],
            ..Default::default()
        };
        assert!(!narrow.is_unrestricted());
    }

    /// NetworkPolicy rules are a union, so one open rule opens the pod
    /// however many narrow ones sit beside it. A wall that took the
    /// *first* rule, or the narrowest, would read this backwards.
    #[test]
    fn one_open_rule_opens_the_pod() {
        let p = EgressPolicy {
            cidrs: vec![
                "10.0.0.0/8".into(),
                "192.168.0.0/16".into(),
                "0.0.0.0/0".into(),
            ],
            ..Default::default()
        };
        assert!(p.is_unrestricted());
    }

    #[test]
    fn a_policy_permitting_nothing_is_a_deny_all() {
        assert!(EgressPolicy::default().permits_nothing());
        assert!(EgressPolicy {
            deny_all: true,
            cidrs: vec!["10.0.0.0/8".into()],
            ..Default::default()
        }
        .permits_nothing());
    }

    #[test]
    fn escalation_paths_are_named_individually() {
        let secrets = RbacRule {
            resource: "secrets".into(),
            verbs: vec!["get".into()],
            namespace: Some("prod".into()),
            ..Default::default()
        };
        assert!(secrets.escalation_path().unwrap().contains("Secrets"));

        let pods = RbacRule {
            resource: "pods".into(),
            verbs: vec!["create".into()],
            ..Default::default()
        };
        assert!(pods.escalation_path().unwrap().contains("privileged"));

        let star = RbacRule {
            resource: "*".into(),
            verbs: vec!["*".into()],
            ..Default::default()
        };
        assert!(star.escalation_path().is_some());

        // ...and an ordinary read is not one.
        let benign = RbacRule {
            resource: "configmaps".into(),
            verbs: vec!["get".into(), "list".into()],
            namespace: Some("prod".into()),
            ..Default::default()
        };
        assert_eq!(benign.escalation_path(), None);
        assert!(!benign.is_write());
    }

    /// `*` is not a resource named `*`; it permits every verb, and a
    /// wall that string-matched would miss it.
    #[test]
    fn a_star_verb_permits_everything() {
        let r = RbacRule {
            resource: "secrets".into(),
            verbs: vec!["*".into()],
            ..Default::default()
        };
        assert!(r.permits("get") && r.permits("delete") && r.is_write());
    }

    #[test]
    fn an_empty_trust_list_trusts_nothing() {
        let snap = ClusterSnapshot::default();
        assert!(!snap.trusts_image("registry.internal/app@sha256:abc"));

        let with = ClusterSnapshot {
            trusted_image_prefixes: vec!["registry.internal/".into()],
            ..Default::default()
        };
        assert!(with.trusts_image("registry.internal/app@sha256:abc"));
        assert!(!with.trusts_image("docker.io/library/nginx:latest"));
    }

    #[test]
    fn the_snapshot_id_changes_with_the_state() {
        let a = ClusterSnapshot::default();
        let b = ClusterSnapshot {
            rbac: vec![RbacRule {
                resource: "pods".into(),
                verbs: vec!["create".into()],
                ..Default::default()
            }],
            ..Default::default()
        };
        assert_ne!(a.content_id(), b.content_id());
        assert_eq!(a.content_id().len(), 64);
    }
}
