//! Milestone 3: accepted admissions become earned trust, and earned
//! trust narrows the manifest (alpibrusl/lex-k8s#4,
//! alpibrusl/lex-lang#794).
//!
//! Two halves of one loop, as in lex-iac. **What a decision leaves
//! behind**: a log `lex attest import-apply` can promote, keyed under
//! the submitter the API server authenticated. And **what the keyring
//! does to the next decision**: a submitter nobody has scored does not
//! get the waivers this manifest hands out.
//!
//! The promotion tests assert against the *serialised* log, not the
//! Rust enum. lex-lang reads this as JSON and has never heard of
//! `AdmissionEvent`; a rename that kept the enum compiling and broke
//! the field names would break promotion silently.
//!
//! # Why the waiver, and not something else
//!
//! Trust may only ever *narrow*. A pod facet has no wildcards to
//! withdraw — `secrets` and `egress` are allow-lists, `privileged` and
//! `hostPath` ordered booleans — so the thing standing can decide is
//! the one place this manifest already declines to check: a dimension
//! it names no policy for. Milestone 2 admits those with a warning that
//! nobody looked. For an unscored submitter the warning becomes the
//! refusal. The manifest is still the ceiling: this wall can only
//! refuse what the other two let through, never admit what they
//! refused.

use lex_k8s::{
    admit, AdmissionReview, ClusterSnapshot, Decision, Keyring, LexManifest, Standing, Verdict,
    Wall,
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

const DEPLOYER: &str = "system:serviceaccount:payments:deployer";
const STRANGER: &str = "system:serviceaccount:payments:intern";

fn keyring() -> Keyring {
    Keyring::new([DEPLOYER])
}

/// Wrap a pod fixture in the `AdmissionReview` the API server posts,
/// under a given authenticated identity.
///
/// Built here rather than stored as a fixture because the identity is
/// the variable under test, and a suite whose reviews differ only in
/// `userInfo` reads better as one function than as six near-identical
/// files.
fn review(pod: &str, username: Option<&str>) -> String {
    let object: serde_json::Value =
        serde_json::from_str(&fixture(pod)).expect("the pod fixture parses");
    let mut request = serde_json::json!({
        "uid": "705ab4f5-6393-11e8-b7cc-42010a800002",
        "namespace": "payments",
        "name": "api",
        "operation": "CREATE",
        "object": object,
    });
    if let Some(u) = username {
        request["userInfo"] = serde_json::json!({ "username": u });
    }
    serde_json::json!({
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "request": request,
    })
    .to_string()
}

fn decide(pod: &str, username: Option<&str>, m: &str, keyring: Option<&Keyring>) -> Decision {
    let raw = review(pod, username);
    let r = AdmissionReview::from_json(&raw).expect("a real review");
    let req = r.request().expect("with a request").clone();
    admit(
        &req.object_json(),
        &manifest(m),
        &snapshot("snapshot_locked_down.json"),
        &req.meta(),
        keyring,
    )
    .expect("the wall runs")
}

/// The manifest that declares an image policy, and the one that waives
/// it by saying nothing.
const POLICY: &str = "manifest_payments.json";
const WAIVES_IMAGES: &str = "manifest_no_image_policy.json";

/// A pod whose image provenance is genuinely in doubt —
/// `docker.io/library/redis:latest`, a floating tag from a registry the
/// cluster snapshot does not vouch for. Otherwise there is no waiver to
/// withhold: the benign pod is pinned by digest from a vouched-for
/// prefix, so nobody has to take anyone's word for it.
const DOUBTFUL: &str = "unvouched_image.json";

// ---------------------------------------------------------------- the wall

/// The baseline this suite turns on: under a manifest that names no
/// `imagePrefixes`, an exemplary pod is admitted and the wall says out
/// loud that nobody checked its provenance.
#[test]
fn a_waived_dimension_is_admitted_and_reported() {
    let d = decide(DOUBTFUL, Some(DEPLOYER), WAIVES_IMAGES, None);
    assert!(d.verdict.allowed(), "{:?}", d.verdict);
    assert_eq!(d.standing, Standing::NotConsulted);
    assert!(
        d.unchecked.iter().any(|u| u.contains("image provenance")),
        "the waiver has to be reported: {:?}",
        d.unchecked
    );
}

/// The headline: the same pod, the same manifest, refused because
/// nobody has scored the submitter — so the waiver does not reach it.
#[test]
fn an_unscored_submitter_gets_no_waiver() {
    let d = decide(DOUBTFUL, Some(STRANGER), WAIVES_IMAGES, Some(&keyring()));
    assert_eq!(d.standing, Standing::Unknown);
    let Verdict::Deny { first, .. } = &d.verdict else {
        panic!("expected a refusal, got {:?}", d.verdict);
    };
    assert_eq!(first.wall, Wall::Trust);
    assert_eq!(d.exit_code(), 8);
    assert!(
        first.reason.contains(STRANGER),
        "the refusal names who was refused: {}",
        first.reason
    );
    // Both remedies, and neither of them is "widen the manifest".
    assert!(first.reason.contains("declare the policy"));
    assert!(first.reason.contains("earn a score"));
}

/// The same call by a submitter with a record.
#[test]
fn a_scored_submitter_keeps_the_waiver() {
    let d = decide(DOUBTFUL, Some(DEPLOYER), WAIVES_IMAGES, Some(&keyring()));
    assert_eq!(d.standing, Standing::Trusted);
    assert!(d.verdict.allowed(), "{:?}", d.verdict);
}

/// A review the API server did not authenticate is not a submitter with
/// a poor record — it is no submitter at all, and the narrower reading
/// is the safe one. The wall does not invent an identity for it.
#[test]
fn an_unauthenticated_review_gets_no_waiver_either() {
    let d = decide(DOUBTFUL, None, WAIVES_IMAGES, Some(&keyring()));
    assert_eq!(d.signer, None);
    assert_eq!(d.standing, Standing::Unknown);
    assert!(!d.verdict.allowed(), "{:?}", d.verdict);
}

/// Without a keyring nothing is consulted and nothing tightens — the
/// wall behaves exactly as it did before this milestone. Otherwise
/// every existing deployment would have silently changed its answers on
/// upgrade.
#[test]
fn no_keyring_changes_nothing() {
    for who in [Some(DEPLOYER), Some(STRANGER), None] {
        let d = decide(DOUBTFUL, who, WAIVES_IMAGES, None);
        assert!(
            d.verdict.allowed(),
            "an unconsulted wall admits as before ({who:?}): {:?}",
            d.verdict
        );
        assert_eq!(d.standing, Standing::NotConsulted);
    }
}

/// A manifest that *declares* its image policy has waived nothing, so
/// standing has nothing to withhold. An unscored submitter is admitted
/// on exactly the same terms as a scored one.
#[test]
fn a_manifest_that_declares_its_policy_has_no_waiver_to_withhold() {
    for who in [DEPLOYER, STRANGER] {
        let d = decide("benign.json", Some(who), POLICY, Some(&keyring()));
        assert!(
            d.verdict.allowed(),
            "a declared policy is checked for everyone alike ({who}): {:?}",
            d.verdict
        );
        assert!(
            d.unchecked.is_empty(),
            "nothing was waived: {:?}",
            d.unchecked
        );
    }
}

/// The direction that must never invert. A pod the other walls refuse
/// is refused whoever submits it, and the wall reported is theirs — a
/// scored submitter does not get a different answer, only the same one.
#[test]
fn trust_never_widens_the_manifest() {
    for who in [DEPLOYER, STRANGER] {
        let d = decide(
            "privileged_init.json",
            Some(who),
            WAIVES_IMAGES,
            Some(&keyring()),
        );
        let Verdict::Deny { first, .. } = &d.verdict else {
            panic!("a privileged pod must not be admitted for {who}: {d:?}");
        };
        assert_ne!(
            first.wall,
            Wall::Trust,
            "the lattice refuses this before standing is even asked ({who})"
        );
    }
}

// -------------------------------------------------- the promotion contract

fn as_json(d: &Decision) -> Vec<serde_json::Value> {
    let raw = d.audit.to_json().expect("the chain serialises");
    serde_json::from_str(&raw).expect("the log is a JSON array")
}

fn event_of<'a>(entries: &'a [serde_json::Value], kind: &str) -> &'a serde_json::Value {
    entries
        .iter()
        .map(|e| &e["event"])
        .find(|e| e["kind"] == kind)
        .unwrap_or_else(|| panic!("no `{kind}` event in the log"))
}

/// What `lex attest import-apply` requires of a promotable event.
fn assert_promotable(event: &serde_json::Value, signer: &str) {
    let sha = event["artifact_sha256"]
        .as_str()
        .expect("a promotable event names the decided bytes");
    assert_eq!(sha.len(), 64, "artifact_sha256 must be a full SHA-256");
    assert!(
        sha.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "artifact_sha256 must be lowercase hex, got `{sha}`"
    );
    assert!(
        event["manifest"].as_str().is_some_and(|m| !m.is_empty()),
        "a promotable event names the ceiling it was checked against"
    );
    assert_eq!(
        event["signer"].as_str(),
        Some(signer),
        "a promotable event names who authorised it"
    );
}

#[test]
fn an_admission_is_promotable() {
    let d = decide("benign.json", Some(DEPLOYER), POLICY, Some(&keyring()));
    assert!(d.verdict.allowed());

    let entries = as_json(&d);
    assert_promotable(event_of(&entries, "pod_admitted"), DEPLOYER);
    assert_promotable(event_of(&entries, "pod_requested"), DEPLOYER);
    assert_eq!(
        event_of(&entries, "pod_admitted")["subject"].as_str(),
        Some("payments/api"),
        "the subject is what an operator would grep for"
    );
}

/// Refusals are promoted too, or producer trust is meaningless: it is
/// `passed / (passed + failed)`, and a corpus of admissions alone
/// scores every submitter 1.0 for ever.
#[test]
fn a_refusal_is_promotable_and_carries_why() {
    let d = decide("privileged_init.json", Some(DEPLOYER), POLICY, None);
    assert!(!d.verdict.allowed());

    let entries = as_json(&d);
    let refused = event_of(&entries, "pod_refused");
    assert_promotable(refused, DEPLOYER);
    assert!(
        refused["reason"].as_str().is_some_and(|r| !r.is_empty()),
        "a refusal's detail has to survive promotion: {refused}"
    );
}

/// The wall does not invent an identity for a review nobody
/// authenticated: the field is absent, and `import-apply` asks for its
/// own `--signer` rather than being handed a guess.
#[test]
fn an_unauthenticated_decision_carries_no_signer_at_all() {
    let d = decide("benign.json", None, POLICY, None);
    let entries = as_json(&d);
    let admitted = event_of(&entries, "pod_admitted");
    assert!(
        admitted.get("signer").is_none(),
        "an absent signer is absent, not empty: {admitted}"
    );
    assert_eq!(admitted["artifact_sha256"].as_str().unwrap().len(), 64);
    assert!(admitted["manifest"].as_str().is_some());
}

/// Both gates promote through **one** attestation kind, so a submitter
/// that runs Terraform through lex-iac and pods through this wall has
/// one track record rather than two. That only works if both logs
/// answer the same three questions, which this pins from the
/// Kubernetes side — lex-iac pins the other.
#[test]
fn the_contract_fields_are_the_same_three_lex_iac_emits() {
    let d = decide("benign.json", Some(DEPLOYER), POLICY, Some(&keyring()));
    let entries = as_json(&d);
    let admitted = event_of(&entries, "pod_admitted");
    for field in ["artifact_sha256", "manifest", "signer"] {
        assert!(
            admitted.get(field).is_some(),
            "`{field}` is named by the contract, not by this repo: {admitted}"
        );
    }
    // And the vocabulary stays this repo's: lex-lang is told the kinds
    // on the command line, it does not guess them.
    assert_eq!(admitted["kind"], "pod_admitted");
}

#[test]
fn the_log_records_what_the_keyring_said() {
    for (who, k, expected) in [
        (Some(DEPLOYER), Some(keyring()), "trusted"),
        (Some(STRANGER), Some(keyring()), "unknown"),
        (Some(DEPLOYER), None, "not-consulted"),
        (None, Some(keyring()), "unknown"),
    ] {
        let d = decide("benign.json", who, POLICY, k.as_ref());
        let entries = as_json(&d);
        assert_eq!(
            event_of(&entries, "pod_requested")["trust"].as_str(),
            Some(expected),
            "for {who:?}"
        );
    }
}

/// Promotion reads the log; it does not re-verify the chain. That makes
/// it this wall's job to write one that verifies, with the request
/// still logged before the decision.
#[test]
fn the_promotable_log_is_still_a_verifying_chain() {
    let d = decide(DOUBTFUL, Some(STRANGER), WAIVES_IMAGES, Some(&keyring()));
    d.audit.verify().expect("the chain verifies");

    let entries = as_json(&d);
    assert_eq!(entries[0]["event"]["kind"], "pod_requested");
    assert_eq!(
        entries.last().unwrap()["event"]["kind"],
        "pod_refused",
        "the decision is the last word in the log"
    );
    for (i, e) in entries.iter().enumerate() {
        assert_eq!(e["seq"].as_u64(), Some(i as u64));
    }
}
