//! Building a [`ClusterSnapshot`] from what the caches hold
//! (alpibrusl/lex-k8s#10).
//!
//! # Why this is a pure module
//!
//! `src/cluster.rs` settled the shape: the snapshot is an **input**,
//! not a lookup, because the API server is calling us inside its own
//! request path and calling back into it to decide is a deadlock
//! waiting for a bad afternoon. So the server watches, and every
//! function here turns *already-cached objects* into the snapshot the
//! compiler takes. Nothing in this file does I/O, which is also why
//! every rule below is reachable from a test without a cluster.
//!
//! # The two absences point in opposite directions
//!
//! - **No NetworkPolicy selects the pod** → `egress: None`, which the
//!   compiler reads as unrestricted egress. That is what Kubernetes
//!   actually does, and reading it as "nothing declared, so nothing
//!   granted" would have the default backwards on the most common
//!   cluster there is.
//! - **No RBAC binding names the ServiceAccount** → no rules, which
//!   grants nothing.
//!
//! Both are correct and they are not the same rule. A helper that
//! flattened them into one "empty means empty" would be wrong half the
//! time.

use std::collections::{BTreeMap, BTreeSet};

use k8s_openapi::api::networking::v1::NetworkPolicy;
use k8s_openapi::api::rbac::v1::{ClusterRole, ClusterRoleBinding, Role, RoleBinding};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;

use crate::cluster::{ClusterSnapshot, EgressPolicy, RbacRule};

/// The pod facts a snapshot depends on, lifted out of the spec.
///
/// A `PodSpec` decides *which* NetworkPolicies and bindings apply to
/// it; taking these three fields rather than the whole object keeps
/// this module free of the admission types.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PodSubject {
    pub namespace: String,
    pub labels: BTreeMap<String, String>,
    /// Kubernetes' own default when the spec names none.
    pub service_account: String,
}

impl PodSubject {
    /// Read the three fields out of a whole `Pod` object as the API
    /// server sends it.
    pub fn from_object(namespace: &str, object: &serde_json::Value) -> Self {
        let labels = object
            .pointer("/metadata/labels")
            .and_then(|v| v.as_object())
            .map(|m| {
                m.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect()
            })
            .unwrap_or_default();
        // `serviceAccount` is the deprecated alias, still populated by
        // the API server. Reading only the modern name would miss a
        // binding on a cluster that sets the old one.
        let service_account = object
            .pointer("/spec/serviceAccountName")
            .or_else(|| object.pointer("/spec/serviceAccount"))
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or("default")
            .to_string();
        Self {
            namespace: namespace.to_string(),
            labels,
            service_account,
        }
    }
}

/// Does a `LabelSelector` select these labels?
///
/// An **empty** selector selects everything — that is Kubernetes' rule,
/// and it is the one that matters here: `podSelector: {}` is how a
/// cluster-wide deny-all is written, and a wall that read it as
/// "selects nothing" would report every pod as unrestricted at exactly
/// the moment the operator had locked the namespace down.
pub fn selects(selector: &LabelSelector, labels: &BTreeMap<String, String>) -> bool {
    let match_labels = selector.match_labels.as_ref();
    let exprs = selector.match_expressions.as_deref().unwrap_or(&[]);

    if let Some(m) = match_labels {
        for (k, v) in m {
            if labels.get(k) != Some(v) {
                return false;
            }
        }
    }
    for e in exprs {
        let present = labels.get(&e.key);
        let values: BTreeSet<&str> = e
            .values
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(String::as_str)
            .collect();
        let ok = match e.operator.as_str() {
            "In" => present.is_some_and(|v| values.contains(v.as_str())),
            "NotIn" => present.is_none_or(|v| !values.contains(v.as_str())),
            "Exists" => present.is_some(),
            "DoesNotExist" => present.is_none(),
            // An operator this build does not know is not a match it
            // can assert. Selecting the pod is the safe direction: it
            // brings the policy's restrictions to bear rather than
            // dropping them.
            _ => true,
        };
        if !ok {
            return false;
        }
    }
    true
}

/// Does this policy govern egress at all?
///
/// A policy with no `policyTypes` governs `Egress` only if it has
/// `egress` rules — Kubernetes' own defaulting. A policy that governs
/// Ingress alone says nothing about where the pod may reach, and
/// folding it in would manufacture a restriction the cluster does not
/// enforce.
fn governs_egress(p: &NetworkPolicy) -> bool {
    let spec = match &p.spec {
        Some(s) => s,
        None => return false,
    };
    match &spec.policy_types {
        Some(types) if !types.is_empty() => types.iter().any(|t| t == "Egress"),
        _ => spec.egress.is_some(),
    }
}

/// Does this policy govern this pod's egress?
///
/// One predicate, used by both the egress build and the provenance
/// record — two copies of a selection rule is two chances to disagree
/// about what the verdict was made on.
fn policy_selects(subject: &PodSubject, p: &NetworkPolicy) -> bool {
    let ns = p.metadata.namespace.as_deref().unwrap_or_default();
    if ns != subject.namespace || !governs_egress(p) {
        return false;
    }
    let spec = p.spec.as_ref().expect("governs_egress checked it");
    // `podSelector` is required by the API and optional in the
    // generated type. Absent is read as the empty selector, which
    // selects **every** pod in the namespace — the same direction the
    // empty selector itself goes, and the one that brings the policy's
    // restrictions to bear rather than dropping them.
    match &spec.pod_selector {
        Some(sel) => selects(sel, &subject.labels),
        None => true,
    }
}

/// `<namespace>/<name>@<resourceVersion>` for every policy that selects
/// the pod.
///
/// The `resourceVersion` is the point: it is what makes a cached read
/// reproducible. Without it the record says which policies applied but
/// not *which revision* of them, and a verdict you cannot reproduce is
/// a verdict you cannot audit.
pub fn pinned(subject: &PodSubject, policies: &[NetworkPolicy]) -> Vec<String> {
    let mut out: Vec<String> = policies
        .iter()
        .filter(|p| policy_selects(subject, p))
        .map(|p| {
            format!(
                "{}/{}@{}",
                p.metadata.namespace.as_deref().unwrap_or_default(),
                p.metadata.name.as_deref().unwrap_or("<unnamed>"),
                p.metadata.resource_version.as_deref().unwrap_or("?")
            )
        })
        .collect();
    out.sort();
    out
}

/// The egress the cluster will actually enforce on this pod.
///
/// `None` when **no policy selects it**, which is unrestricted egress.
/// The union rule is Kubernetes': every selecting policy's rules add
/// together, so one open rule opens the pod — [`EgressPolicy::is_unrestricted`]
/// is what reads that back out.
pub fn egress_for(subject: &PodSubject, policies: &[NetworkPolicy]) -> Option<EgressPolicy> {
    let mut out = EgressPolicy::default();
    let mut selected = false;

    for p in policies {
        if !policy_selects(subject, p) {
            continue;
        }
        let spec = p.spec.as_ref().expect("policy_selects checked it");
        selected = true;
        out.policy_names.push(format!(
            "{}/{}",
            p.metadata.namespace.as_deref().unwrap_or_default(),
            p.metadata.name.as_deref().unwrap_or("<unnamed>")
        ));

        for rule in spec.egress.as_deref().unwrap_or(&[]) {
            // A rule with no `to` permits every destination — the
            // "allow all egress" idiom. It is the open case, spelled
            // as an absence, which is exactly the shape this repo
            // refuses to read as benign anywhere else.
            let tos = match rule.to.as_deref() {
                None | Some([]) => {
                    out.cidrs.push("0.0.0.0/0".to_string());
                    continue;
                }
                Some(tos) => tos,
            };
            for to in tos {
                if let Some(block) = &to.ip_block {
                    out.cidrs.push(block.cidr.clone());
                    // `except` narrows a CIDR; it does not add reach,
                    // and the lattice has nowhere to put a hole. Named
                    // in the selectors so a refusal can still say the
                    // policy was more complicated than the row shows.
                    for e in block.except.as_deref().unwrap_or(&[]) {
                        out.selectors.push(format!("except {e}"));
                    }
                }
                if let Some(sel) = &to.pod_selector {
                    out.selectors.push(format!("pods {}", describe(sel)));
                }
                if let Some(sel) = &to.namespace_selector {
                    out.selectors.push(format!("namespaces {}", describe(sel)));
                }
            }
        }
    }

    if !selected {
        return None;
    }
    // Selected, with nothing permitted, is a deny-all — the tightest a
    // pod can be, and a different fact from "no policy selects it".
    out.deny_all = out.cidrs.is_empty() && out.selectors.is_empty();
    out.cidrs.sort();
    out.cidrs.dedup();
    out.selectors.sort();
    out.selectors.dedup();
    out.policy_names.sort();
    Some(out)
}

fn describe(sel: &LabelSelector) -> String {
    match sel.match_labels.as_ref() {
        Some(m) if !m.is_empty() => m
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(","),
        // The empty selector again: it means *all* of them, and
        // printing `{}` in a refusal would tell an operator nothing.
        _ => "(all)".to_string(),
    }
}

/// Rules the pod's ServiceAccount holds, resolved through its bindings.
///
/// Both binding kinds are followed, and the distinction between them
/// survives into [`RbacRule::namespace`]: a `ClusterRoleBinding` is
/// cluster-wide (`None`) and a `RoleBinding` is scoped to its own
/// namespace. That difference is most of the blast radius, which is
/// why it is a field rather than a comment.
pub fn rbac_for(
    subject: &PodSubject,
    roles: &[Role],
    cluster_roles: &[ClusterRole],
    role_bindings: &[RoleBinding],
    cluster_role_bindings: &[ClusterRoleBinding],
) -> Vec<RbacRule> {
    let mut out: Vec<RbacRule> = Vec::new();

    let names_subject = |subjects: &Option<Vec<k8s_openapi::api::rbac::v1::Subject>>| -> bool {
        subjects.as_deref().unwrap_or(&[]).iter().any(|s| {
            (s.kind == "ServiceAccount"
                && s.name == subject.service_account
                && s.namespace.as_deref().unwrap_or(&subject.namespace) == subject.namespace)
                // A binding on a group covers every account in it, and
                // `system:serviceaccounts` is every account in the
                // cluster. Missing these would under-report the reach
                // of exactly the bindings that grant the most.
                || (s.kind == "Group"
                    && (s.name == "system:serviceaccounts"
                        || s.name == format!("system:serviceaccounts:{}", subject.namespace)))
        })
    };

    // RoleBindings in the pod's namespace. A RoleBinding may point at
    // a ClusterRole, which is how a cluster-wide role gets applied
    // namespace-scoped — the rules are the ClusterRole's, the scope is
    // the binding's.
    for b in role_bindings {
        if b.metadata.namespace.as_deref().unwrap_or_default() != subject.namespace {
            continue;
        }
        if !names_subject(&b.subjects) {
            continue;
        }
        let binding = format!(
            "RoleBinding {}/{}",
            subject.namespace,
            b.metadata.name.as_deref().unwrap_or("<unnamed>")
        );
        let rules = match b.role_ref.kind.as_str() {
            "Role" => roles
                .iter()
                .find(|r| {
                    r.metadata.name.as_deref() == Some(b.role_ref.name.as_str())
                        && r.metadata.namespace.as_deref().unwrap_or_default() == subject.namespace
                })
                .and_then(|r| r.rules.clone()),
            "ClusterRole" => cluster_roles
                .iter()
                .find(|r| r.metadata.name.as_deref() == Some(b.role_ref.name.as_str()))
                .and_then(|r| r.rules.clone()),
            _ => None,
        };
        push_rules(
            &mut out,
            &binding,
            Some(subject.namespace.clone()),
            rules,
            &b.role_ref.name,
        );
    }

    for b in cluster_role_bindings {
        if !names_subject(&b.subjects) {
            continue;
        }
        let binding = format!(
            "ClusterRoleBinding {}",
            b.metadata.name.as_deref().unwrap_or("<unnamed>")
        );
        let rules = cluster_roles
            .iter()
            .find(|r| r.metadata.name.as_deref() == Some(b.role_ref.name.as_str()))
            .and_then(|r| r.rules.clone());
        push_rules(&mut out, &binding, None, rules, &b.role_ref.name);
    }

    out.sort();
    out.dedup();
    out
}

/// A binding whose role is missing from the cache is recorded, not
/// dropped.
///
/// The rules are unknown, so the row carries no verbs — but the row
/// exists, and its `resource` says why. Silently omitting it would
/// report a pod as holding less authority than it might, which is the
/// one direction this wall must never round in.
fn push_rules(
    out: &mut Vec<RbacRule>,
    binding: &str,
    namespace: Option<String>,
    rules: Option<Vec<k8s_openapi::api::rbac::v1::PolicyRule>>,
    role_name: &str,
) {
    let Some(rules) = rules else {
        out.push(RbacRule {
            binding: format!("{binding} -> {role_name} (not in cache)"),
            api_group: String::new(),
            resource: "<unresolved>".to_string(),
            verbs: Vec::new(),
            namespace,
        });
        return;
    };
    for r in rules {
        for group in r.api_groups.as_deref().unwrap_or(&[String::new()]) {
            for resource in r.resources.as_deref().unwrap_or(&[]) {
                out.push(RbacRule {
                    binding: binding.to_string(),
                    api_group: group.clone(),
                    resource: resource.clone(),
                    verbs: r.verbs.clone(),
                    namespace: namespace.clone(),
                });
            }
        }
    }
}

/// Everything the caches hold about one pod, at one instant.
///
/// `provenance` carries the `resourceVersion` of every object read.
/// [`ClusterSnapshot`] keeps that slot uninterpreted precisely so the
/// webhook can pin what it read without this crate learning what a
/// resource version is — and it is folded into the snapshot hash, so a
/// verdict names the cluster state it was made on.
#[allow(clippy::too_many_arguments)]
pub fn build(
    subject: &PodSubject,
    policies: &[NetworkPolicy],
    roles: &[Role],
    cluster_roles: &[ClusterRole],
    role_bindings: &[RoleBinding],
    cluster_role_bindings: &[ClusterRoleBinding],
    trusted_image_prefixes: Vec<String>,
) -> ClusterSnapshot {
    let egress = egress_for(subject, policies);
    let rbac = rbac_for(
        subject,
        roles,
        cluster_roles,
        role_bindings,
        cluster_role_bindings,
    );

    let mut provenance = BTreeMap::new();
    provenance.insert(
        "serviceAccount".to_string(),
        subject.service_account.clone(),
    );
    if egress.is_some() {
        provenance.insert(
            "networkPolicies".to_string(),
            pinned(subject, policies).join(","),
        );
    } else {
        // Said out loud, in the record: an operator reading the audit
        // log should be able to tell "no policy selected this pod"
        // from "the webhook did not look".
        provenance.insert("networkPolicies".to_string(), "none selected".to_string());
    }
    provenance.insert(
        "rbacBindings".to_string(),
        rbac.iter()
            .map(|r| r.binding.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
            .join(","),
    );

    ClusterSnapshot {
        egress,
        rbac,
        trusted_image_prefixes,
        provenance,
    }
}
