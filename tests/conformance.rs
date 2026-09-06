//! Conformance for the effect compiler (alpibrusl/lex-k8s#2), over
//! fixtures rather than inline JSON.
//!
//! The fixtures are pods and snapshots in the shape an operator or an
//! admission review actually carries — whole `Pod` objects with
//! metadata, not the trimmed structs this crate models. A compiler that
//! works on hand-built structs and not on what `kubectl get -o json`
//! emits is not a compiler anyone can use.

use lex_k8s::{compile_str, ClusterSnapshot, ContainerKind, Effect, Level, Reach, Reversibility};

fn fixture(name: &str) -> String {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/");
    std::fs::read_to_string(format!("{path}{name}"))
        .unwrap_or_else(|e| panic!("reading fixture {name}: {e}"))
}

fn snapshot(name: &str) -> ClusterSnapshot {
    serde_json::from_str(&fixture(name)).unwrap_or_else(|e| panic!("parsing snapshot {name}: {e}"))
}

/// The baseline every other case is measured against: a pod that does
/// everything right, on a cluster that does too.
#[test]
fn a_well_behaved_pod_asks_for_very_little() {
    let pod = compile_str(
        &fixture("benign.json"),
        &snapshot("snapshot_locked_down.json"),
    )
    .unwrap();

    assert_eq!(pod.demands.filesystem, Level::ReadOnly, "one Secret in env");
    assert_eq!(
        pod.demands.network,
        Level::Allowlist,
        "a real egress policy"
    );
    assert_eq!(pod.demands.exec, Level::None, "no capabilities, no escapes");
    assert!(!pod.has_consequential());
    assert!(pod.unreadable().is_empty());
}

/// **The demo for milestone 2.** The pod annotates itself with a narrow
/// egress and its spec is otherwise exemplary — but a `legacy-allow-all`
/// NetworkPolicy also selects it, so what the cluster *enforces* is
/// `0.0.0.0/0`.
///
/// The compiler reports the enforced reach, not the claimed one. An
/// annotation is a claim; a NetworkPolicy is the wall.
#[test]
fn a_pod_that_lies_about_its_egress_is_compiled_on_what_the_cluster_enforces() {
    let claimed = compile_str(
        &fixture("lying_about_egress.json"),
        &snapshot("snapshot_locked_down.json"),
    )
    .unwrap();
    let enforced = compile_str(
        &fixture("lying_about_egress.json"),
        &snapshot("snapshot_policy_is_a_lie.json"),
    )
    .unwrap();

    // Same bytes of spec. Different cluster. Different answer.
    assert_eq!(claimed.spec_sha256, enforced.spec_sha256);
    assert_ne!(claimed.snapshot_sha256, enforced.snapshot_sha256);

    assert_eq!(claimed.demands.network, Level::Allowlist);
    assert_eq!(enforced.demands.network, Level::Full);

    let row = enforced
        .rows
        .iter()
        .find(|r| matches!(r.effect, Effect::Egress { .. }))
        .expect("an egress row is always emitted");
    assert_eq!(
        row.reversibility,
        Reversibility::IrreversibleConsequential,
        "data that leaves the cluster does not come back"
    );
    assert!(
        row.effect.explain().contains("legacy-allow-all"),
        "the refusal must name the policy that opened it: {}",
        row.effect.explain()
    );
}

/// Kubernetes' default is open. On a cluster with no NetworkPolicy at
/// all, the same exemplary pod is asking for the whole network — and
/// the remedy is a policy to write, not one to tighten.
#[test]
fn no_network_policy_is_not_no_reach() {
    let pod = compile_str(
        &fixture("benign.json"),
        &snapshot("snapshot_no_policy.json"),
    )
    .unwrap();
    assert_eq!(pod.demands.network, Level::Full);

    let row = pod
        .rows
        .iter()
        .find(|r| matches!(r.effect, Effect::Egress { .. }))
        .unwrap();
    assert!(
        matches!(
            row.effect,
            Effect::Egress {
                reach: Reach::NoPolicy,
                ..
            }
        ),
        "distinguishable from a policy that permits everything"
    );
    assert!(row.effect.explain().contains("default is open"));
}

/// Reading only `containers[0]` would call this pod unremarkable. The
/// init container has already been root on the node by the time the app
/// container starts.
#[test]
fn a_privileged_init_container_decides_the_pods_demand() {
    let pod = compile_str(
        &fixture("privileged_init.json"),
        &snapshot("snapshot_locked_down.json"),
    )
    .unwrap();

    assert_eq!(pod.demands.exec, Level::Full);
    assert_eq!(pod.demands.filesystem, Level::Full);

    let row = pod
        .rows
        .iter()
        .find(|r| matches!(r.effect, Effect::Privileged))
        .expect("the init container is privileged");
    assert_eq!(row.source.kind, Some(ContainerKind::Init));
    assert_eq!(row.source.container.as_deref(), Some("sysctl-tuner"));
    assert_eq!(
        row.reversibility,
        Reversibility::IrreversibleConsequential,
        "what it did to the node outlives the pod"
    );
}

/// An ephemeral container is a live escalation path into a pod that was
/// admitted long ago, and it never appears in the create request.
#[test]
fn an_ephemeral_debug_container_carries_its_own_authority() {
    let pod = compile_str(
        &fixture("debug_container.json"),
        &snapshot("snapshot_locked_down.json"),
    )
    .unwrap();

    let row = pod
        .rows
        .iter()
        .find(|r| matches!(&r.effect, Effect::Capability { name, .. } if name == "SYS_PTRACE"))
        .expect("SYS_PTRACE on the debug container");
    assert_eq!(row.source.kind, Some(ContainerKind::Ephemeral));
    assert_eq!(pod.demands.exec, Level::Full, "SYS_PTRACE is an escape");

    // ...and its `:latest` image is not identified either.
    assert!(pod
        .rows
        .iter()
        .any(|r| matches!(r.effect, Effect::UntrustedImage { .. })));
}

/// A read-only `hostPath` still reads files outside the pod. It sits
/// above a mounted Secret and below a writable mount, which is the
/// judgement the module docs commit to.
#[test]
fn a_log_shipper_reaches_the_node_read_only() {
    let pod = compile_str(
        &fixture("node_filesystem.json"),
        &snapshot("snapshot_locked_down.json"),
    )
    .unwrap();

    assert_eq!(
        pod.demands.filesystem,
        Level::ReadWrite,
        "read-only, but off-pod"
    );
    assert_eq!(pod.demands.network, Level::Full, "hostNetwork");

    let paths: Vec<String> = pod
        .rows
        .iter()
        .filter_map(|r| match &r.effect {
            Effect::HostPath { path, writable } => {
                assert!(!writable, "both mounts are readOnly: {path}");
                Some(path.clone())
            }
            _ => None,
        })
        .collect();
    assert_eq!(paths, ["/var/log", "/var/lib/docker/containers"]);

    // The image is from docker.io, which this snapshot does not vouch
    // for, and is tagged rather than pinned.
    assert!(pod
        .rows
        .iter()
        .any(|r| matches!(r.effect, Effect::UntrustedImage { .. })));
}

/// RBAC reach is resolved from the snapshot, never looked up. A
/// ServiceAccount that can write Deployments can create Pods on its
/// behalf, and so is holding privilege at one remove.
#[test]
fn a_service_accounts_reach_comes_from_the_snapshot() {
    let pod = compile_str(
        &fixture("benign.json"),
        &snapshot("snapshot_ci_serviceaccount.json"),
    )
    .unwrap();

    let api: Vec<&lex_k8s::EffectRow> = pod
        .rows
        .iter()
        .filter(|r| matches!(r.effect, Effect::ApiAccess { .. }))
        .collect();
    assert_eq!(api.len(), 2);

    let escalating = api
        .iter()
        .find(|r| {
            matches!(
                &r.effect,
                Effect::ApiAccess {
                    escalation: Some(_),
                    ..
                }
            )
        })
        .expect("writing Deployments is an escalation path");
    assert!(escalating.source.to_string().contains("ci-deployer"));
    assert!(escalating.effect.explain().contains("create Pods"));
    assert_eq!(pod.demands.exec, Level::Full);

    // ...and the plain configmap read is not scored as one.
    assert!(api.iter().any(|r| matches!(
        &r.effect,
        Effect::ApiAccess {
            escalation: None,
            ..
        }
    )));
}

/// A spec from a future Kubernetes must compile. Fields this build does
/// not know are ignored; a capability it does not recognise is still an
/// added capability and still raises `exec`.
#[test]
fn a_future_spec_compiles_and_an_unknown_capability_is_still_a_capability() {
    let pod = compile_str(
        &fixture("future_shape.json"),
        &snapshot("snapshot_locked_down.json"),
    )
    .unwrap();

    let row = pod
        .rows
        .iter()
        .find(|r| matches!(r.effect, Effect::Capability { .. }))
        .expect("CAP_UNKNOWN_FUTURE is still an added capability");
    assert!(
        matches!(
            &row.effect,
            Effect::Capability {
                dangerous: false,
                ..
            }
        ),
        "not on the dangerous list, so sandboxed rather than full"
    );
    assert_eq!(pod.demands.exec, Level::Sandboxed);
}

/// Compilation is a pure function of its two inputs, and both are
/// pinned. An admission is an admission of *these* bytes against *that*
/// cluster state.
#[test]
fn compilation_is_deterministic_and_both_inputs_are_pinned() {
    let a = compile_str(
        &fixture("benign.json"),
        &snapshot("snapshot_locked_down.json"),
    )
    .unwrap();
    let b = compile_str(
        &fixture("benign.json"),
        &snapshot("snapshot_locked_down.json"),
    )
    .unwrap();
    assert_eq!(a, b);

    let c = compile_str(
        &fixture("benign.json"),
        &snapshot("snapshot_no_policy.json"),
    )
    .unwrap();
    assert_eq!(a.spec_sha256, c.spec_sha256);
    assert_ne!(a.snapshot_sha256, c.snapshot_sha256);
    assert_ne!(a.demands, c.demands);
}

/// Stands in for the fuzz target until one is wired up — and asserts
/// the safety property, not merely the absence of a crash. lex-iac#8
/// is the cautionary tale: a suite that only checked "never panics"
/// let a document that was not a plan be approved.
#[test]
fn malformed_input_never_panics_and_is_never_harmless() {
    let snap = snapshot("snapshot_locked_down.json");
    for case in [
        "",
        "{",
        "[]",
        "null",
        "3",
        r#""a string""#,
        r#"{"containers":null}"#,
        r#"{"containers":"not a list"}"#,
        r#"{"containers":[{}]}"#,
        r#"{"containers":[{"securityContext":{"capabilities":{"add":["","CAP_","-"]}}}]}"#,
        r#"{"volumes":[{"name":"h","hostPath":{}}],"containers":[]}"#,
        r#"{"spec":{"spec":{"containers":[]}}}"#,
        r#"{"containers":[{"image":"@sha256:"}]}"#,
    ] {
        let _ = compile_str(case, &snap);
    }

    // A document that is JSON but not a pod spec is refused outright,
    // never read as a pod with nothing in it.
    for not_a_pod in ["{}", "[]", r#"{"kind":"ConfigMap","data":{}}"#] {
        assert!(
            compile_str(not_a_pod, &snap).is_err(),
            "{not_a_pod} must not compile to an empty, admissible pod"
        );
    }

    // And a container with nothing in it is not thereby harmless: its
    // image is unidentified.
    let pod = compile_str(r#"{"containers":[{}]}"#, &snap).unwrap();
    assert!(pod
        .rows
        .iter()
        .any(|r| matches!(r.effect, Effect::UntrustedImage { .. })));
}
