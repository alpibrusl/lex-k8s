//! Sealed decision chains (alpibrusl/lex-k8s#12, lex-os#54).
//!
//! This wall writes its audit chains to the **pod's own filesystem**,
//! which is the weakest place any consumer of `Chain<E>` puts one. The
//! chain is tamper-*evident* only against someone who cannot recompute
//! it, and whoever can reach that volume can: the hashes are derived.
//!
//! The property under test is the one that closes:
//!
//! > A decision rewritten and re-hashed passes the chain and fails the
//! > seal.
//!
//! Everything here is a real `AdmissionReview` through the real
//! `admit_sealed`, because a seal over a hand-built struct proves
//! nothing about the wall that actually runs.

use lex_k8s::{
    admit, admit_sealed, AdmissionEvent, AdmissionReview, Chain, ClusterSnapshot, LexManifest,
    SigningKey, Verdict,
};

fn fixture(name: &str) -> String {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/");
    std::fs::read_to_string(format!("{path}{name}"))
        .unwrap_or_else(|e| panic!("reading fixture {name}: {e}"))
}

fn manifest(name: &str) -> lex_os_manifest::Manifest {
    LexManifest::read(&fixture(name)).expect("a LexManifest").1
}

fn snapshot(name: &str) -> ClusterSnapshot {
    serde_json::from_str(&fixture(name)).expect("a snapshot")
}

fn review(name: &str) -> AdmissionReview {
    AdmissionReview::from_json(&fixture(name)).expect("an AdmissionReview")
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

/// A refusal, decided from a real review, with every entry sealed.
fn sealed_refusal(k: &SigningKey) -> Chain<AdmissionEvent> {
    let r = review("review_lying_about_egress.json");
    let request = r.request().expect("a request");
    let d = admit_sealed(
        &request.object_json(),
        &manifest("manifest_payments.json"),
        &snapshot("snapshot_policy_is_a_lie.json"),
        &request.meta(),
        None,
        None,
        k,
    )
    .expect("the wall runs");
    assert!(matches!(d.verdict, Verdict::Deny { .. }), "a refusal");
    d.audit
}

#[test]
fn a_sealed_decision_seals_every_entry() {
    let k = key(1);
    let audit = sealed_refusal(&k);
    assert!(audit.len() >= 2, "request plus verdict at least");
    assert_eq!(
        audit.sealed_count(),
        audit.len(),
        "every entry, not most of them — an unsealed entry is where a forged one goes"
    );
    audit.verify().expect("the chain");
    audit.verify_seals(&[k.verifying_key()]).expect("the seals");

    // The negative control: another key must not do, or this would pass
    // on a `verify_seals` that returned Ok unconditionally.
    assert!(audit.verify_seals(&[key(2).verifying_key()]).is_err());
}

/// **The attack this exists to stop**, performed properly.
///
/// Somebody with the pod's volume turns a refusal into an admission.
/// Editing the payload alone is caught by the chain — so they do the
/// obvious next thing and **rebuild the chain**, which costs nothing
/// because the hashes are derived from the contents. Here that rebuild
/// is done by calling the library itself, which is exactly the tool the
/// forger has.
///
/// The result verifies as a chain. The seals are what refuse it.
#[test]
fn a_rewritten_verdict_passes_the_chain_and_fails_the_seal() {
    let k = key(1);
    let audit = sealed_refusal(&k);

    let raw: Vec<serde_json::Value> =
        serde_json::from_str(&audit.to_json().unwrap()).expect("entries");

    // Rebuild the whole chain, swapping the final refusal for an
    // admission. `append` recomputes every hash correctly, so what
    // comes out is a well-formed chain of the forger's choosing.
    let mut forged: Chain<AdmissionEvent> = Chain::new();
    for (i, entry) in raw.iter().enumerate() {
        let last = i == raw.len() - 1;
        let event: AdmissionEvent = if last {
            assert_eq!(entry["event"]["kind"], "pod_refused");
            serde_json::from_value(serde_json::json!({
                "kind": "pod_admitted",
                "uid": entry["event"]["uid"].clone(),
                "artifact_sha256": entry["event"]["artifact_sha256"].clone(),
                "manifest": entry["event"]["manifest"].clone(),
                "subject": entry["event"]["subject"].clone(),
            }))
            .expect("a pod_admitted event")
        } else {
            serde_json::from_value(entry["event"].clone()).expect("the original event")
        };
        forged.append(event);
    }

    // Carry the original seals across — the forger has them, they came
    // with the file.
    let mut with_seals: Vec<serde_json::Value> =
        serde_json::from_str(&forged.to_json().unwrap()).expect("entries");
    for (i, entry) in with_seals.iter_mut().enumerate() {
        entry["seal"] = raw[i]["seal"].clone();
    }
    let forged: Chain<AdmissionEvent> =
        Chain::from_json(&serde_json::to_string(&with_seals).unwrap()).expect("parses");

    // This is the load-bearing assertion: the chain is *fine*. Nothing
    // inside it says the refusal ever happened.
    forged
        .verify()
        .expect("a recomputed chain verifies — the hashes are derived, not signed");
    assert!(
        matches!(
            forged.entries().last().unwrap().event,
            AdmissionEvent::PodAdmitted { .. }
        ),
        "the refusal is gone from the record"
    );
    assert_ne!(forged.head(), audit.head(), "and it is a different history");

    // The seal is the part they could not recompute.
    let err = forged
        .verify_seals(&[k.verifying_key()])
        .expect_err("the seals must refuse a rewritten decision");
    assert!(format!("{err}").contains("contents"), "{err}");
}

/// Sealing is opt-in, and an unsealed log is reported as unsealed
/// rather than as failing. `admit` writes exactly what it always wrote.
#[test]
fn an_unsealed_decision_is_byte_for_byte_what_it_was() {
    let r = review("review_lying_about_egress.json");
    let request = r.request().expect("a request");
    let d = admit(
        &request.object_json(),
        &manifest("manifest_payments.json"),
        &snapshot("snapshot_policy_is_a_lie.json"),
        &request.meta(),
        None,
        None,
    )
    .expect("the wall runs");
    assert_eq!(d.audit.sealed_count(), 0);
    d.audit.verify().expect("still a valid chain");
    assert!(!d.audit.to_json().unwrap().contains("seal"));
}

/// Sealing must not change the decision, the verdict, or the hashes —
/// or `lex attest import-apply` would see a different artifact for the
/// same pod.
#[test]
fn sealing_changes_nothing_but_the_seal() {
    let r = review("review_lying_about_egress.json");
    let request = r.request().expect("a request");
    let args = (
        request.object_json(),
        manifest("manifest_payments.json"),
        snapshot("snapshot_policy_is_a_lie.json"),
        request.meta(),
    );
    let plain = admit(&args.0, &args.1, &args.2, &args.3, None, None).unwrap();
    let sealed = admit_sealed(&args.0, &args.1, &args.2, &args.3, None, None, &key(1)).unwrap();

    assert_eq!(plain.audit.head(), sealed.audit.head(), "same head");
    assert_eq!(plain.audit.len(), sealed.audit.len());
    assert_eq!(
        plain.pod.spec_sha256, sealed.pod.spec_sha256,
        "and the same artifact, which is what the attestation graph keys on"
    );
    assert_eq!(
        format!("{:?}", plain.verdict),
        format!("{:?}", sealed.verdict)
    );
}

/// A different pod's seal cannot be lifted onto this pod's entry: the
/// seal covers the entry hash, which covers the payload and the
/// position.
#[test]
fn a_seal_does_not_transfer_between_decisions() {
    let k = key(1);
    let a = sealed_refusal(&k);

    let r = review("review_lying_about_egress.json");
    let request = r.request().expect("a request");
    let b = admit_sealed(
        &request.object_json(),
        &manifest("manifest_payments.json"),
        // A different snapshot, so a different decision and a different
        // hash for the same pod.
        &snapshot("snapshot_locked_down.json"),
        &request.meta(),
        None,
        None,
        &k,
    )
    .expect("the wall runs")
    .audit;

    assert_ne!(a.head(), b.head(), "different decisions");

    let mut raw_a: Vec<serde_json::Value> =
        serde_json::from_str(&a.to_json().unwrap()).expect("entries");
    let raw_b: Vec<serde_json::Value> =
        serde_json::from_str(&b.to_json().unwrap()).expect("entries");
    // Graft b's first seal onto a's first entry.
    raw_a[0]["seal"] = raw_b[0]["seal"].clone();

    let grafted: Chain<AdmissionEvent> =
        Chain::from_json(&serde_json::to_string(&raw_a).unwrap()).expect("parses");
    assert!(
        grafted.verify_seals(&[k.verifying_key()]).is_err(),
        "a seal is bound to the entry it covers, not merely to the key"
    );
}
