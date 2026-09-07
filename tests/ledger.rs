//! The ledger of decision heads (alpibrusl/lex-k8s#13).
//!
//! Sealing (#12) proved nobody can *rewrite* a decision. It cannot
//! prove a decision that happened still exists — a seal covers what a
//! record says, never whether the record is still there. Only a second
//! record that counted them can.
//!
//! The property under test:
//!
//! > A deleted decision file leaves a gap the ledger can name.
//!
//! And its mirror, which matters just as much: a decision file the
//! ledger never witnessed is *also* a disagreement, not a bonus.

use lex_k8s::{reconcile, Ledger, LedgerEvent, SigningKey};

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn witness(head: &str, name: &str) -> LedgerEvent {
    LedgerEvent::PodDecided {
        uid: format!("uid-{name}"),
        namespace: "payments".into(),
        name: name.into(),
        verdict: "refused".into(),
        decision_head: head.into(),
        decision_entries: 2,
        snapshot_sha256: "snap".into(),
        signer: Some("system:serviceaccount:payments:deployer".into()),
    }
}

fn ledger_with(heads: &[&str]) -> Ledger {
    let mut l = Ledger::new().sealed_with(key(1));
    l.append(LedgerEvent::WallStarted {
        signer: Some(hex::encode(key(1).verifying_key().to_bytes())),
        audit_dir: Some("/audit".into()),
    });
    for (i, h) in heads.iter().enumerate() {
        l.append(witness(h, &format!("pod-{i}")));
    }
    l
}

#[test]
fn a_ledger_and_its_decisions_agree() {
    let l = ledger_with(&["aaa", "bbb", "ccc"]);
    let r = reconcile(&l, &["aaa".into(), "bbb".into(), "ccc".into()]);
    assert!(r.is_clean());
    assert_eq!(r.matched, 3);
    // The `wall_started` entry is not a decision and must not be
    // counted as one.
    assert_eq!(l.len(), 4);
}

/// **The attack.** Someone with the volume deletes an inconvenient
/// refusal. Nothing in the decision chains can notice — there is no
/// chain left to check.
#[test]
fn a_deleted_decision_leaves_a_gap_the_ledger_names() {
    let l = ledger_with(&["aaa", "bbb", "ccc"]);
    // "bbb" is gone from the directory.
    let r = reconcile(&l, &["aaa".into(), "ccc".into()]);
    assert!(!r.is_clean());
    assert_eq!(r.missing, vec!["bbb".to_string()]);
    assert!(r.unwitnessed.is_empty());
    assert_eq!(r.matched, 2);
}

/// The mirror: a decision nobody witnessed is a disagreement too. It is
/// either planted, or the ledger lost its tail — and a reader must be
/// told rather than shown the friendlier reading.
#[test]
fn a_decision_the_ledger_never_witnessed_is_also_a_disagreement() {
    let l = ledger_with(&["aaa"]);
    let r = reconcile(&l, &["aaa".into(), "zzz".into()]);
    assert!(!r.is_clean());
    assert!(r.missing.is_empty());
    assert_eq!(r.unwitnessed, vec!["zzz".to_string()]);
}

/// Negative control for both directions at once: an empty ledger and an
/// empty directory agree, and a function that always reported a gap
/// would fail here.
#[test]
fn nothing_and_nothing_agree() {
    let l = ledger_with(&[]);
    let r = reconcile(&l, &[]);
    assert!(r.is_clean());
    assert_eq!(r.matched, 0);
}

/// The ledger is itself a sealed chain, so the same rewrite protection
/// applies to the witness as to what it witnesses. Without this, an
/// attacker would delete a decision *and* the ledger entry naming it.
#[test]
fn the_ledger_is_sealed_too() {
    let l = ledger_with(&["aaa", "bbb"]);
    assert_eq!(
        l.sealed_count(),
        l.len(),
        "every entry, including wall_started"
    );
    l.verify().expect("the chain");
    l.verify_seals(&[key(1).verifying_key()])
        .expect("the seals");
    assert!(
        l.verify_seals(&[key(2).verifying_key()]).is_err(),
        "negative control"
    );
}

/// A checkpoint over the ledger catches the attack one level up:
/// truncating the ledger's tail to drop the entries that witness the
/// decisions you also deleted.
#[test]
fn truncating_the_ledger_is_caught_by_a_checkpoint() {
    let k = key(1);
    let l = ledger_with(&["aaa", "bbb", "ccc"]);
    let cp = l
        .checkpoint(&k, 1_757_000_000)
        .verify(&k.verifying_key())
        .unwrap();
    l.verify_against(&cp).expect("the ledger it was taken from");

    // Drop the last witness, and the decision file with it. Both
    // records now agree — with each other, and about a history that did
    // not happen.
    let mut truncated = Ledger::from_json(&l.to_json().unwrap()).unwrap();
    let mut raw: Vec<serde_json::Value> =
        serde_json::from_str(&truncated.to_json().unwrap()).unwrap();
    raw.pop();
    truncated = Ledger::from_json(&serde_json::to_string(&raw).unwrap()).unwrap();

    truncated.verify().expect("a prefix is a valid chain");
    truncated
        .verify_seals(&[k.verifying_key()])
        .expect("and its seals still hold");
    let r = reconcile(&truncated, &["aaa".into(), "bbb".into()]);
    assert!(
        r.is_clean(),
        "the two records agree with each other — which is why a checkpoint is needed"
    );

    // The checkpoint is what refuses it.
    let err = truncated.verify_against(&cp).unwrap_err();
    assert!(format!("{err}").contains("truncated"), "{err}");
}

/// `/narrow` decisions reach the record now. Before #13 they reached
/// the log and nothing else — and a manifest that widens its parent is
/// the more consequential of the two decisions this wall makes.
#[test]
fn manifest_decisions_are_witnessed() {
    let mut l = Ledger::new().sealed_with(key(1));
    l.append(LedgerEvent::WallStarted {
        signer: None,
        audit_dir: None,
    });
    l.append(LedgerEvent::ManifestDecided {
        uid: "uid-1".into(),
        child: "payments/payments-wider".into(),
        parent: Some("cluster/platform-default".into()),
        verdict: "widens".into(),
        reason: Some("trust widening on filesystem".into()),
        signer: Some("kubernetes-admin".into()),
    });
    l.verify().expect("the chain");
    // A manifest verdict witnesses no decision *chain*, because
    // `/narrow` writes none — so it must not be reconciled as one.
    let r = reconcile(&l, &[]);
    assert!(r.is_clean(), "a manifest entry is not a missing decision");
    assert_eq!(r.matched, 0);
}

/// The two vocabularies must not be interchangeable, or a decision
/// entry could be replayed into a ledger.
#[test]
fn the_ledger_domain_is_separate_from_the_decision_domain() {
    use lex_os_audit::ChainPayload;
    assert_ne!(
        LedgerEvent::DOMAIN,
        lex_k8s::AdmissionEvent::DOMAIN,
        "a shared domain would let an entry cross between the two chains"
    );
}
