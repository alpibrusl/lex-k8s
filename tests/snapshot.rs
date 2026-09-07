//! The snapshot the webhook builds from its caches (alpibrusl/lex-k8s#10).
//!
//! Every rule here is reachable without a cluster, which is the reason
//! `src/serve/snapshot.rs` is a pure module: the kind demo proves the
//! wiring, and this proves the reading. The two are different claims,
//! and only one of them can be held on every PR.
//!
//! The property under test throughout:
//!
//! > **The two absences point in opposite directions.** No
//! > NetworkPolicy selecting a pod means unrestricted egress; no RBAC
//! > binding naming its ServiceAccount means no API reach. A helper
//! > that flattened them into one "empty means empty" would be wrong
//! > half the time — and it would be wrong in the admitting direction.

#![cfg(feature = "serve")]

use std::collections::BTreeMap;

use k8s_openapi::api::networking::v1::NetworkPolicy;
use k8s_openapi::api::rbac::v1::{ClusterRole, ClusterRoleBinding, Role, RoleBinding};
use lex_k8s::serve::snapshot::{self, PodSubject};

fn subject(labels: &[(&str, &str)]) -> PodSubject {
    PodSubject {
        namespace: "payments".into(),
        labels: labels
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        service_account: "api".into(),
    }
}

fn policy(yaml: serde_json::Value) -> NetworkPolicy {
    serde_json::from_value(yaml).expect("a NetworkPolicy")
}

fn np(name: &str, selector: serde_json::Value, egress: serde_json::Value) -> NetworkPolicy {
    policy(serde_json::json!({
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": name, "namespace": "payments", "resourceVersion": "42"},
        "spec": {"podSelector": selector, "policyTypes": ["Egress"], "egress": egress},
    }))
}

// ---------------------------------------------------------------- egress

/// The default that matters most, and the one a naive implementation
/// gets backwards.
#[test]
fn no_policy_selecting_the_pod_is_unrestricted_not_empty() {
    let elsewhere = np(
        "other-app",
        serde_json::json!({"matchLabels": {"app": "web"}}),
        serde_json::json!([{"to": [{"ipBlock": {"cidr": "10.0.0.0/8"}}]}]),
    );
    assert_eq!(
        snapshot::egress_for(&subject(&[("app", "api")]), &[elsewhere]),
        None,
        "a policy that does not select the pod must leave it unrestricted"
    );
}

/// `podSelector: {}` is how a namespace-wide deny-all is written. A
/// wall that read the empty selector as "selects nothing" would report
/// every pod as unrestricted at exactly the moment the operator had
/// locked the namespace down.
#[test]
fn an_empty_selector_selects_every_pod() {
    let deny_all = np("default-deny", serde_json::json!({}), serde_json::json!([]));
    let e = snapshot::egress_for(&subject(&[("app", "api")]), &[deny_all])
        .expect("the empty selector selects this pod");
    assert!(e.deny_all, "selected with nothing permitted is a deny-all");
    assert!(e.permits_nothing());
}

/// A policy that governs Ingress only says nothing about where the pod
/// may reach. Folding it in would manufacture a restriction the cluster
/// does not enforce.
#[test]
fn an_ingress_only_policy_does_not_govern_egress() {
    let ingress = policy(serde_json::json!({
        "metadata": {"name": "web-in", "namespace": "payments"},
        "spec": {"podSelector": {}, "policyTypes": ["Ingress"],
                 "ingress": [{"from": [{"ipBlock": {"cidr": "10.0.0.0/8"}}]}]},
    }));
    assert_eq!(snapshot::egress_for(&subject(&[]), &[ingress]), None);
}

/// The "allow all egress" idiom is an *absence*: a rule with no `to`.
/// This repo refuses to read absence as benignity everywhere else, and
/// this is the same rule pointed the other way — absence here means
/// wide open, so it must be read as wide open.
#[test]
fn a_rule_with_no_destination_is_wide_open() {
    let open = np("allow-all", serde_json::json!({}), serde_json::json!([{}]));
    let e = snapshot::egress_for(&subject(&[]), &[open]).expect("selected");
    assert!(
        e.is_unrestricted(),
        "a rule with no `to` permits everything"
    );
    assert!(!e.deny_all);
}

/// NetworkPolicy rules are a union, so one open rule opens the pod
/// however many narrow ones sit beside it — across policies, not just
/// within one.
#[test]
fn one_open_rule_in_any_policy_opens_the_pod() {
    let narrow = np(
        "db-only",
        serde_json::json!({}),
        serde_json::json!([{"to": [{"ipBlock": {"cidr": "10.0.0.0/8"}}]}]),
    );
    let open = np(
        "debug",
        serde_json::json!({}),
        serde_json::json!([{"to": [{"ipBlock": {"cidr": "0.0.0.0/0"}}]}]),
    );
    let e = snapshot::egress_for(&subject(&[]), &[narrow, open]).expect("selected");
    assert!(e.is_unrestricted());
    assert_eq!(
        e.policy_names.len(),
        2,
        "both policies are named in the record"
    );
}

/// Negative control for the union test above: without the open rule the
/// same inputs must *not* be unrestricted. A suite that only ever
/// asserted `is_unrestricted()` would pass on a function that returned
/// it unconditionally.
#[test]
fn narrow_rules_alone_are_not_unrestricted() {
    let narrow = np(
        "db-only",
        serde_json::json!({}),
        serde_json::json!([{"to": [{"ipBlock": {"cidr": "10.0.0.0/8"}}]}]),
    );
    let e = snapshot::egress_for(&subject(&[]), &[narrow]).expect("selected");
    assert!(!e.is_unrestricted());
    assert!(!e.permits_nothing());
}

#[test]
fn match_expressions_are_honoured() {
    let labels: BTreeMap<String, String> = [
        ("app".to_string(), "api".to_string()),
        ("tier".to_string(), "backend".to_string()),
    ]
    .into_iter()
    .collect();
    let sel = |op: &str, key: &str, values: serde_json::Value| {
        serde_json::from_value(serde_json::json!({
            "matchExpressions": [{"key": key, "operator": op, "values": values}]
        }))
        .expect("a LabelSelector")
    };

    assert!(snapshot::selects(
        &sel("In", "app", serde_json::json!(["api", "web"])),
        &labels
    ));
    assert!(!snapshot::selects(
        &sel("In", "app", serde_json::json!(["web"])),
        &labels
    ));
    assert!(snapshot::selects(
        &sel("NotIn", "app", serde_json::json!(["web"])),
        &labels
    ));
    assert!(!snapshot::selects(
        &sel("NotIn", "app", serde_json::json!(["api"])),
        &labels
    ));
    assert!(snapshot::selects(
        &sel("Exists", "tier", serde_json::json!(null)),
        &labels
    ));
    assert!(!snapshot::selects(
        &sel("Exists", "zone", serde_json::json!(null)),
        &labels
    ));
    assert!(snapshot::selects(
        &sel("DoesNotExist", "zone", serde_json::json!(null)),
        &labels
    ));
    assert!(!snapshot::selects(
        &sel("DoesNotExist", "app", serde_json::json!(null)),
        &labels
    ));
}

// ------------------------------------------------------------------ rbac

fn role(name: &str, resource: &str, verbs: &[&str]) -> Role {
    serde_json::from_value(serde_json::json!({
        "metadata": {"name": name, "namespace": "payments"},
        "rules": [{"apiGroups": [""], "resources": [resource], "verbs": verbs}],
    }))
    .expect("a Role")
}

fn cluster_role(name: &str, resource: &str, verbs: &[&str]) -> ClusterRole {
    serde_json::from_value(serde_json::json!({
        "metadata": {"name": name},
        "rules": [{"apiGroups": [""], "resources": [resource], "verbs": verbs}],
    }))
    .expect("a ClusterRole")
}

fn binding(name: &str, kind: &str, role: &str, subject_name: &str) -> RoleBinding {
    serde_json::from_value(serde_json::json!({
        "metadata": {"name": name, "namespace": "payments"},
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": kind, "name": role},
        "subjects": [{"kind": "ServiceAccount", "name": subject_name, "namespace": "payments"}],
    }))
    .expect("a RoleBinding")
}

#[test]
fn a_binding_that_does_not_name_the_account_grants_nothing() {
    let rules = snapshot::rbac_for(
        &subject(&[]),
        &[role("reader", "configmaps", &["get"])],
        &[],
        &[binding("other", "Role", "reader", "someone-else")],
        &[],
    );
    assert!(rules.is_empty(), "no binding names this ServiceAccount");
}

#[test]
fn a_rolebinding_is_namespaced_and_a_clusterrolebinding_is_not() {
    let crb: ClusterRoleBinding = serde_json::from_value(serde_json::json!({
        "metadata": {"name": "cluster-reader"},
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "secret-reader"},
        "subjects": [{"kind": "ServiceAccount", "name": "api", "namespace": "payments"}],
    }))
    .expect("a ClusterRoleBinding");

    let rules = snapshot::rbac_for(
        &subject(&[]),
        &[role("reader", "configmaps", &["get"])],
        &[cluster_role("secret-reader", "secrets", &["get"])],
        &[binding("local", "Role", "reader", "api")],
        &[crb],
    );

    let scoped = rules
        .iter()
        .find(|r| r.resource == "configmaps")
        .expect("the RoleBinding's rule");
    assert_eq!(scoped.namespace.as_deref(), Some("payments"));
    assert!(!scoped.cluster_wide());

    let wide = rules
        .iter()
        .find(|r| r.resource == "secrets")
        .expect("the ClusterRoleBinding's rule");
    assert!(wide.cluster_wide(), "a ClusterRoleBinding is cluster-wide");
    // ...and this is the one the wall must notice.
    assert!(wide.escalation_path().is_some());
}

/// A RoleBinding may point at a ClusterRole: the rules are the
/// ClusterRole's, the scope is the binding's. Reading the scope from
/// the role rather than the binding would over-report the blast radius
/// of the single most common RBAC idiom there is.
#[test]
fn a_rolebinding_to_a_clusterrole_keeps_the_bindings_scope() {
    let rules = snapshot::rbac_for(
        &subject(&[]),
        &[],
        &[cluster_role("view", "pods", &["get", "list"])],
        &[binding("view-here", "ClusterRole", "view", "api")],
        &[],
    );
    let r = rules.first().expect("one rule");
    assert_eq!(r.resource, "pods");
    assert_eq!(
        r.namespace.as_deref(),
        Some("payments"),
        "scoped by the binding"
    );
}

/// A binding on `system:serviceaccounts:<ns>` covers every account in
/// the namespace, this pod's included. Missing it would under-report
/// exactly the bindings that grant the most.
#[test]
fn a_group_binding_covers_the_accounts_in_it() {
    let crb: ClusterRoleBinding = serde_json::from_value(serde_json::json!({
        "metadata": {"name": "everyone"},
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "admin"},
        "subjects": [{"kind": "Group", "name": "system:serviceaccounts:payments"}],
    }))
    .expect("a ClusterRoleBinding");
    let rules = snapshot::rbac_for(
        &subject(&[]),
        &[],
        &[cluster_role("admin", "*", &["*"])],
        &[],
        &[crb],
    );
    assert_eq!(rules.len(), 1);
    assert!(
        rules[0].escalation_path().is_some(),
        "`*` on `*` is unrestricted authority"
    );
}

/// A binding whose role is not in the cache is **recorded, not
/// dropped**. Omitting it would report the pod as holding less
/// authority than it might, which is the one direction this wall must
/// never round in.
#[test]
fn an_unresolvable_role_is_recorded_rather_than_dropped() {
    let rules = snapshot::rbac_for(
        &subject(&[]),
        &[],
        &[],
        &[binding("dangling", "Role", "gone", "api")],
        &[],
    );
    let r = rules.first().expect("the binding is still recorded");
    assert_eq!(r.resource, "<unresolved>");
    assert!(r.binding.contains("not in cache"));
    assert!(r.verbs.is_empty(), "unknown rules are not invented");
}

// ------------------------------------------------------------- provenance

#[test]
fn the_service_account_defaults_the_way_kubernetes_does() {
    let none = PodSubject::from_object("payments", &serde_json::json!({"spec": {}}));
    assert_eq!(none.service_account, "default");

    let modern = PodSubject::from_object(
        "payments",
        &serde_json::json!({"spec": {"serviceAccountName": "api"}}),
    );
    assert_eq!(modern.service_account, "api");

    // The deprecated alias is still populated by the API server, and a
    // reader that ignored it would miss a binding on a cluster that
    // sets it.
    let legacy = PodSubject::from_object(
        "payments",
        &serde_json::json!({"spec": {"serviceAccount": "api"}}),
    );
    assert_eq!(legacy.service_account, "api");
}

/// A verdict names the cluster state it was made on. Two revisions of
/// the same policy are different state, so they must hash differently —
/// otherwise a decision cannot be reproduced against what it actually
/// saw.
#[test]
fn the_snapshot_pins_the_revision_it_read() {
    let mut older = np(
        "db-only",
        serde_json::json!({}),
        serde_json::json!([{"to": [{"ipBlock": {"cidr": "10.0.0.0/8"}}]}]),
    );
    let newer = {
        let mut p = older.clone();
        p.metadata.resource_version = Some("99".into());
        p
    };
    older.metadata.resource_version = Some("42".into());

    let s = &subject(&[]);
    let a = snapshot::build(s, std::slice::from_ref(&older), &[], &[], &[], &[], vec![]);
    let b = snapshot::build(s, std::slice::from_ref(&newer), &[], &[], &[], &[], vec![]);

    assert!(a.provenance["networkPolicies"].ends_with("@42"));
    assert!(b.provenance["networkPolicies"].ends_with("@99"));
    assert_ne!(
        a.content_id(),
        b.content_id(),
        "a different revision is different state"
    );
}

/// The record distinguishes "no policy selected this pod" from "the
/// webhook did not look". They are the same empty egress and completely
/// different facts.
#[test]
fn the_record_says_when_nothing_selected_the_pod() {
    let s = snapshot::build(&subject(&[]), &[], &[], &[], &[], &[], vec![]);
    assert_eq!(s.egress, None);
    assert_eq!(s.provenance["networkPolicies"], "none selected");
}
