//! Conformance for the admission wall (alpibrusl/lex-k8s#3).
//!
//! Over real `AdmissionReview` documents and real `LexManifest` CRDs,
//! rather than hand-built structs. A wall that works on structs and not
//! on what the API server actually POSTs is not a wall anyone can
//! deploy.
//!
//! The kind demo #3 asks for is not runnable here — there is no cluster
//! in this environment — so this suite stands in for it as far as it
//! can: the same decision, from the same bytes, with the response the
//! API server would receive.

use lex_k8s::{
    admit, narrow, respond, AdmissionReview, ClusterSnapshot, LexManifest, Verdict, Wall,
};

fn fixture(name: &str) -> String {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/");
    std::fs::read_to_string(format!("{path}{name}"))
        .unwrap_or_else(|e| panic!("reading fixture {name}: {e}"))
}

fn manifest(name: &str) -> lex_os_manifest::Manifest {
    LexManifest::read(&fixture(name))
        .unwrap_or_else(|e| panic!("reading manifest {name}: {e}"))
        .1
}

fn snapshot(name: &str) -> ClusterSnapshot {
    serde_json::from_str(&fixture(name)).unwrap_or_else(|e| panic!("parsing snapshot {name}: {e}"))
}

/// Decide one review, the way the CLI does.
fn decide(review: &str, m: &str, snap: &ClusterSnapshot) -> (String, lex_k8s::Decision) {
    let review = AdmissionReview::from_json(&fixture(review)).expect("a real review");
    let req = review.request().expect("with a request").clone();
    let d = admit(&req.object_json(), &manifest(m), snap, &req.meta()).expect("the wall runs");
    (req.uid, d)
}

/// **The demo.** The pod is exemplary — capabilities dropped, image
/// pinned by digest, an annotation claiming narrow egress. A forgotten
/// `legacy-allow-all` NetworkPolicy also selects it, so what the cluster
/// enforces is `0.0.0.0/0`, and the wall refuses it before it schedules.
#[test]
fn a_pod_that_lies_about_its_egress_is_refused() {
    let (uid, d) = decide(
        "review_lying_about_egress.json",
        "manifest_payments.json",
        &snapshot("snapshot_policy_is_a_lie.json"),
    );
    assert_eq!(d.exit_code(), 8);

    let Verdict::Deny { all, .. } = &d.verdict else {
        panic!("expected a refusal, got {:?}", d.verdict);
    };
    // Both walls catch it, and they catch different things.
    assert!(
        all.iter().any(|r| r.wall == Wall::TypeCheck),
        "the lattice: `full` exceeds `allowlist`"
    );
    assert!(
        all.iter().any(|r| r.wall == Wall::Narrowing),
        "the facet: 0.0.0.0/0 is not one of the named hosts"
    );

    // ...and the response is what the API server would act on.
    let out = respond(&uid, &d);
    let resp = out.response.expect("a response");
    assert_eq!(
        resp.uid, uid,
        "the uid must echo or the API server drops it"
    );
    assert!(!resp.allowed);
    let status = resp.status.expect("a status");
    assert_eq!(status.code, 403);

    let causes = status.details.expect("details").causes;
    assert_eq!(causes.len(), 2);
    assert!(causes.iter().any(|c| c.reason == "type-check"));
    let narrowing = causes.iter().find(|c| c.reason == "narrowing").unwrap();
    assert!(
        narrowing
            .grant_allows
            .contains(&"api.stripe.com:443".to_string()),
        "what the manifest does grant, as data: {:?}",
        narrowing.grant_allows
    );
}

/// The same pod, the same manifest, on a cluster whose policy is what it
/// claims to be. Nothing about the spec changed.
#[test]
fn the_same_pod_is_admitted_when_the_cluster_is_what_it_claims() {
    let (uid, d) = decide(
        "review_lying_about_egress.json",
        "manifest_payments.json",
        &snapshot("snapshot_locked_down.json"),
    );
    assert!(d.verdict.allowed(), "{:?}", d.verdict);
    assert_eq!(d.exit_code(), 0);

    let resp = respond(&uid, &d).response.expect("a response");
    assert!(resp.allowed);
    assert!(
        resp.status.is_none(),
        "an admission carries no error status"
    );
}

/// A `LexManifest` that widens its parent is itself refused — the piece
/// a constraint language structurally lacks.
#[test]
fn a_namespace_lead_cannot_mint_authority_the_platform_never_gave_them() {
    let platform = manifest("manifest_platform.json");
    let payments = manifest("manifest_payments.json");
    assert!(
        narrow(&platform, &payments).is_ok(),
        "a genuine narrowing is accepted"
    );

    let root = manifest("manifest_mints_itself_root.json");
    let err = narrow(&platform, &root).unwrap_err();
    let said = err.to_string();
    assert!(
        said.contains("widening") || said.contains("widens"),
        "the refusal says what happened: {said}"
    );
}

/// Each of the four things that manifest tries to mint is refused on its
/// own, so the test cannot pass for the wrong reason.
#[test]
fn each_widening_is_refused_individually() {
    let platform = manifest("manifest_platform.json");
    let base = r#"{"spec":{"grant":{"egress":["postgres.payments.svc"],"#;

    for (label, grant) in [
        ("an egress host", r#""egress":["exfil.example.com:443"]"#),
        ("a Secret", r#""secrets":["cluster-root-ca"]"#),
        ("hostPath", r#""hostPath":true"#),
        ("privileged", r#""privileged":true"#),
        ("the node's namespaces", r#""hostNamespaces":true"#),
        ("a capability", r#""capabilities":["SYS_ADMIN"]"#),
    ] {
        let src = format!(r#"{{"spec":{{"grant":{{{grant}}}}}}}"#);
        let child = LexManifest::read(&src).unwrap().1;
        assert!(
            narrow(&platform, &child).is_err(),
            "{label} must be refused; base was {base}"
        );
    }
}

/// The audit chain verifies across a run of admissions and refusals, and
/// the request is recorded before the verdict in every one.
#[test]
fn the_chain_verifies_across_admissions_and_refusals() {
    for (snap, expect_allowed) in [
        ("snapshot_locked_down.json", true),
        ("snapshot_policy_is_a_lie.json", false),
        ("snapshot_no_policy.json", false),
    ] {
        let (_, d) = decide(
            "review_lying_about_egress.json",
            "manifest_payments.json",
            &snapshot(snap),
        );
        assert_eq!(d.verdict.allowed(), expect_allowed, "{snap}");
        assert_eq!(d.audit.len(), 2, "{snap}: request then decision");
        d.audit
            .verify()
            .unwrap_or_else(|e| panic!("{snap}: chain broken: {e}"));
        assert_eq!(d.audit.entries()[1].prev_hash, d.audit.entries()[0].hash);
        assert!(
            matches!(
                d.audit.entries()[0].event,
                lex_k8s::AdmissionEvent::PodRequested { .. }
            ),
            "{snap}: the request is recorded first, refused or not"
        );
    }
}

/// Kubernetes' default is open, and a namespace with no NetworkPolicy is
/// the common case rather than an exotic one. The wall says so.
#[test]
fn a_namespace_with_no_network_policy_is_refused_not_waved_through() {
    let (_, d) = decide(
        "review_lying_about_egress.json",
        "manifest_payments.json",
        &snapshot("snapshot_no_policy.json"),
    );
    let Verdict::Deny { all, .. } = &d.verdict else {
        panic!("expected a refusal, got {:?}", d.verdict);
    };
    assert!(all.iter().any(|r| r.reason.contains("default is open")
        || r.effect.contains("no-policy")
        || r.wall == Wall::TypeCheck));
}

/// "We did not look" and "we looked and it was fine" are different
/// facts, and an admitted pod says which it got.
///
/// Two things can vouch for an image: the manifest's `imagePrefixes`,
/// and the cluster snapshot's. The warning fires only when *neither*
/// did — reporting it while the snapshot vouched would be telling an
/// operator nobody checked when somebody had.
#[test]
fn an_admission_reports_the_dimensions_nobody_declared_a_policy_for() {
    // A manifest that names no imagePrefixes.
    let permissive = LexManifest::read(
        r#"{"spec":{"grant":{"egress":["postgres.payments.svc"],"secrets":["payments-db"]}}}"#,
    )
    .unwrap()
    .1;
    let review = AdmissionReview::from_json(&fixture("review_lying_about_egress.json")).unwrap();
    let req = review.request().unwrap();

    // ...and a cluster that vouches for nothing either. Nobody looked.
    let unvouched = ClusterSnapshot {
        trusted_image_prefixes: vec![],
        ..snapshot("snapshot_locked_down.json")
    };
    let d = admit(&req.object_json(), &permissive, &unvouched, &req.meta()).unwrap();
    assert!(d.verdict.allowed(), "{:?}", d.verdict);
    let resp = respond(&req.uid, &d).response.unwrap();
    assert!(
        resp.warnings.iter().any(|w| w.contains("image provenance")),
        "nobody checked the image, and the admission says so: {:?}",
        resp.warnings
    );

    // When the snapshot does vouch, something checked it, and there is
    // nothing to warn about.
    let vouched = admit(
        &req.object_json(),
        &permissive,
        &snapshot("snapshot_locked_down.json"),
        &req.meta(),
    )
    .unwrap();
    assert!(vouched.verdict.allowed());
    assert!(
        vouched.unchecked.is_empty(),
        "the snapshot vouched, so the wall must not claim nobody looked: {:?}",
        vouched.unchecked
    );
}

/// The wall could not run is not the wall said no, and the response says
/// which. `failurePolicy: Fail` turns both into a rejected pod — but
/// only one of them is a decision this code made.
#[test]
fn a_document_that_is_not_a_review_is_refused_to_be_read() {
    for bad in [
        r#"{}"#,
        r#"[]"#,
        r#"{"response":{"allowed":true}}"#,
        r#"{"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview"}"#,
        "not json at all",
    ] {
        assert!(
            AdmissionReview::from_json(bad).is_err(),
            "{bad} must not read as a request"
        );
    }
}

/// ...and the same rule one level in: a review whose object is not a pod
/// stops the wall rather than being admitted as a pod with nothing in it.
#[test]
fn a_review_whose_object_is_not_a_pod_stops_the_wall() {
    let review = r#"{"request":{"uid":"u1","namespace":"payments","name":"x",
        "operation":"CREATE","object":{"kind":"ConfigMap","data":{"a":"b"}}}}"#;
    let review = AdmissionReview::from_json(review).unwrap();
    let req = review.request().unwrap();

    let err = admit(
        &req.object_json(),
        &manifest("manifest_payments.json"),
        &snapshot("snapshot_locked_down.json"),
        &req.meta(),
    )
    .unwrap_err();
    assert!(matches!(err, lex_k8s::AdmissionError::Spec(_)), "{err}");
}

/// An unnamed pod is still traceable: `generateName` is what CREATE
/// carries, and a record nobody can trace back is not an audit record.
#[test]
fn an_unnamed_pod_is_still_named_in_the_record() {
    let (_, d) = decide(
        "review_lying_about_egress.json",
        "manifest_payments.json",
        &snapshot("snapshot_locked_down.json"),
    );
    let lex_k8s::AdmissionEvent::PodRequested { name, uid, .. } = &d.audit.entries()[0].event
    else {
        panic!("the first entry is the request")
    };
    assert_eq!(name, "exporter-7d9f-");
    assert!(!uid.is_empty());
}

/// A floor nothing here enforces is refused rather than accepted
/// silently — an operator must not come away believing a boundary
/// exists that does not.
#[test]
fn a_manifest_declaring_an_unenforceable_isolation_floor_is_refused() {
    let asking = r#"{"spec":{"grant":{"egress":["a"]},"isolationFloor":"microvm"}}"#;
    assert!(matches!(
        LexManifest::read(asking),
        Err(lex_k8s::ManifestReadError::UnenforceableFloor { .. })
    ));

    // ...and there is a way to say yes on purpose.
    let knowing = r#"{"spec":{"grant":{"egress":["a"]},"isolationFloor":"unenforced-microvm"}}"#;
    assert!(LexManifest::read(knowing).is_ok());
}
