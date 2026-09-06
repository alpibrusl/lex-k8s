//! Milestone 4: the budget wall (alpibrusl/lex-k8s#1).
//!
//! Per-namespace spend charged against `budget.max_money_cents`.
//!
//! # The property this suite exists to hold
//!
//! > Exceeding the budget refuses new **admissions**, never running
//! > pods.
//!
//! An admission webhook has no eviction path and must never grow one.
//! A namespace already over its ceiling keeps everything it is running;
//! all this wall does is stop the next thing. The failure mode of the
//! alternative is catastrophic and asymmetric — a price list edited by
//! the wrong hand would take down production, to prevent an overspend
//! that had already happened.
//!
//! # And the one it exists to prevent
//!
//! A container that declares no `resources.requests` cannot be charged.
//! Pricing it at zero would make omitting requests the cheapest way
//! past any ceiling, so an unpriceable pod is refused while a budget is
//! being enforced.

use lex_k8s::{
    admission::Spend, admit, AdmissionReview, ClusterSnapshot, Decision, LexManifest, PriceList,
    SpendReport, Verdict, Wall,
};

fn fixture(name: &str) -> String {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/");
    std::fs::read_to_string(format!("{path}{name}"))
        .unwrap_or_else(|e| panic!("reading fixture {name}: {e}"))
}

fn manifest_at(budget_minor: u64) -> lex_os_manifest::Manifest {
    let mut m = LexManifest::read(&fixture("manifest_payments.json"))
        .expect("the manifest reads")
        .1;
    m.budget.max_money_cents = budget_minor;
    m
}

fn snapshot() -> ClusterSnapshot {
    serde_json::from_str(&fixture("snapshot_locked_down.json")).expect("the snapshot parses")
}

/// $30 per core-month and $4 per GiB-month, in cents. Round numbers so
/// the arithmetic in each assertion is checkable by eye.
fn prices() -> PriceList {
    PriceList {
        currency: "USD".into(),
        cpu_core_month_minor: 3_000,
        gib_month_minor: 400,
    }
}

fn spend(committed_minor: u64) -> Spend {
    Spend {
        prices: prices(),
        report: SpendReport {
            currency: "USD".into(),
            namespace_monthly_minor: committed_minor,
        },
    }
}

fn review(pod: &str) -> String {
    let object: serde_json::Value =
        serde_json::from_str(&fixture(pod)).expect("the pod fixture parses");
    serde_json::json!({
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "request": {
            "uid": "705ab4f5-6393-11e8-b7cc-42010a800002",
            "namespace": "payments",
            "name": "api",
            "operation": "CREATE",
            "userInfo": { "username": "system:serviceaccount:payments:deployer" },
            "object": object,
        },
    })
    .to_string()
}

fn decide(pod: &str, budget_minor: u64, spend: Option<&Spend>) -> Decision {
    let raw = review(pod);
    let r = AdmissionReview::from_json(&raw).expect("a real review");
    let req = r.request().expect("with a request").clone();
    admit(
        &req.object_json(),
        &manifest_at(budget_minor),
        &snapshot(),
        &req.meta(),
        None,
        spend,
    )
    .expect("the wall runs")
}

/// The pod every case here uses: a 500m/512Mi app container behind a
/// 2-core/2GiB migration init container.
///
/// Priced by Kubernetes' effective-request rule that is
/// `max(2000m, 500m)` CPU and `max(2Gi, 512Mi)` memory — 2 cores and
/// 2 GiB, so $60 + $8 = **$68.00/month**, or 6800 minor units.
const POD: &str = "priced_with_migration.json";
const POD_MONTHLY: u64 = 6_800;

/// The same pod with no `resources.requests` anywhere.
const UNPRICED: &str = "unpriced.json";

#[test]
fn a_pod_that_fits_is_admitted_and_the_charge_is_recorded() {
    let d = decide(POD, 20_000, Some(&spend(5_000)));
    assert!(d.verdict.allowed(), "{:?}", d.verdict);
    assert_eq!(d.charged, Some(POD_MONTHLY));

    // Recorded whether or not it fits — a budget you can only see once
    // it was exceeded is not one anyone can plan against.
    let entries = as_json(&d);
    let charge = event_of(&entries, "spend_charged");
    assert_eq!(charge["pod_monthly_minor"].as_u64(), Some(POD_MONTHLY));
    assert_eq!(charge["namespace_monthly_minor"].as_u64(), Some(5_000));
    assert_eq!(charge["budget_minor"].as_u64(), Some(20_000));
    assert_eq!(charge["currency"].as_str(), Some("USD"));
}

#[test]
fn a_pod_that_would_exceed_the_ceiling_is_refused() {
    // 5000 committed + 6800 for this pod = 11800, over a 10000 ceiling.
    let d = decide(POD, 10_000, Some(&spend(5_000)));
    let Verdict::Deny { first, .. } = &d.verdict else {
        panic!("expected a refusal, got {:?}", d.verdict);
    };
    assert_eq!(first.wall, Wall::Budget);
    assert_eq!(d.exit_code(), 8);
    // The overage is named, so an operator does not have to do the
    // subtraction themselves.
    assert!(
        first.reason.contains("18.00") && first.reason.contains("100.00"),
        "the refusal states the total and the ceiling: {}",
        first.reason
    );
    // And it says what the number is *not*.
    assert!(first.reason.contains("not the invoice"));

    // The charge is still recorded.
    assert_eq!(d.charged, Some(POD_MONTHLY));
}

/// **The property.** A namespace already over its ceiling refuses the
/// next admission — and that is the entire consequence. There is no
/// eviction, no error, no action on anything already running: the
/// verdict is an ordinary `Deny` about *this* pod.
#[test]
fn an_over_budget_namespace_refuses_admissions_and_nothing_else() {
    let d = decide(POD, 10_000, Some(&spend(50_000)));
    let Verdict::Deny { all, .. } = &d.verdict else {
        panic!("expected a refusal");
    };
    // One refusal, about this pod's spend. Nothing here can name, touch
    // or reach a pod that is already running.
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].wall, Wall::Budget);
    assert_eq!(all[0].source, "resources.requests");
    assert_eq!(d.exit_code(), 8);
}

/// Kubernetes' own effective-request rule, through the whole wall. The
/// pod costs `max(init, app)`, not `init + app` — a pod that fits at
/// 6800 would be refused at 8300 if the migration were summed instead
/// of peaked, and an operator told they cannot afford it would have
/// been told a falsehood.
#[test]
fn the_init_container_is_a_peak_not_a_sum() {
    // Exactly enough for max(2 cores, 500m) + max(2Gi, 512Mi).
    let d = decide(POD, POD_MONTHLY, Some(&spend(0)));
    assert!(
        d.verdict.allowed(),
        "the pod costs max(init, app), not their sum: {:?}",
        d.verdict
    );
    // One cent less and it does not fit, which pins the number rather
    // than merely asserting it is small enough.
    let d = decide(POD, POD_MONTHLY - 1, Some(&spend(0)));
    assert!(!d.verdict.allowed());
}

/// An empty request is not a request for nothing. Charging it at zero
/// would make deleting the `resources` block the cheapest way past any
/// ceiling.
#[test]
fn a_pod_that_cannot_be_priced_is_refused_not_charged_at_zero() {
    let d = decide(UNPRICED, 1_000_000, Some(&spend(0)));
    let Verdict::Deny { first, .. } = &d.verdict else {
        panic!(
            "a huge budget must not admit an unpriceable pod: {:?}",
            d.verdict
        );
    };
    assert_eq!(first.wall, Wall::Budget);
    assert_eq!(first.effect, "unpriced");
    assert!(
        first.reason.contains("not a request for nothing"),
        "{}",
        first.reason
    );
    // It names the container and the field to fix.
    assert!(first.source.contains("resources.requests"));
}

/// Without both inputs no budget wall runs at all, and the same pod is
/// admitted exactly as it was before this milestone. Otherwise every
/// existing deployment would have started refusing pods on upgrade.
#[test]
fn no_price_list_means_no_budget_wall() {
    for pod in [POD, UNPRICED] {
        let d = decide(pod, 0, None);
        assert!(
            d.verdict.allowed(),
            "an unpriced wall admits as before ({pod}): {:?}",
            d.verdict
        );
        assert_eq!(d.charged, None, "None means unpriced, never zero");
    }
    // And no charge event is written, rather than one full of zeroes.
    let d = decide(POD, 0, None);
    assert!(
        !as_json(&d)
            .iter()
            .any(|e| e["event"]["kind"] == "spend_charged"),
        "a wall that did not run records nothing"
    );
}

/// A report in another currency stops the wall rather than being
/// converted: EUR against a ceiling sized in USD is wrong by whatever
/// the rate is that day. That is the wall failing to run, not a
/// refusal — and with `failurePolicy: Fail` the API server turns it
/// into a rejection anyway, which is correct and is not the same thing.
#[test]
fn a_report_in_another_currency_stops_the_wall() {
    let raw = review(POD);
    let r = AdmissionReview::from_json(&raw).unwrap();
    let req = r.request().unwrap().clone();
    let mismatched = Spend {
        prices: prices(),
        report: SpendReport {
            currency: "EUR".into(),
            namespace_monthly_minor: 0,
        },
    };
    let e = admit(
        &req.object_json(),
        &manifest_at(1_000_000),
        &snapshot(),
        &req.meta(),
        None,
        Some(&mismatched),
    )
    .expect_err("a currency mismatch is not a verdict");
    assert!(e.to_string().contains("EUR") && e.to_string().contains("USD"));
}

/// A manifest that declares no `budget` authorises no spend — the same
/// rule as an empty allow-list, applied to money. It is not "no ceiling
/// configured, so anything goes": lex-os's default is
/// `max_money_cents: 0`, and reading that as unlimited would invert the
/// whole invariant.
///
/// The CLI warns loudly when this combination is used, because an
/// operator watching every pod get refused deserves the reason rather
/// than a puzzle.
#[test]
fn a_manifest_with_no_budget_authorises_no_spend() {
    let m = LexManifest::read(&fixture("manifest_payments.json"))
        .expect("the manifest reads")
        .1;
    assert_eq!(
        m.budget.max_money_cents, 0,
        "the fixture declares no budget, so it authorises nothing"
    );

    let d = decide(POD, 0, Some(&spend(0)));
    let Verdict::Deny { first, .. } = &d.verdict else {
        panic!("a zero ceiling admits no priced pod: {:?}", d.verdict);
    };
    assert_eq!(first.wall, Wall::Budget);
}

/// The budget leg sits after the other walls, so a pod refused for
/// reaching too far is still told about that first — the graver
/// finding, and the one raising the ceiling would not fix.
#[test]
fn a_pod_that_trips_an_earlier_wall_is_told_about_that_wall() {
    let raw = review("privileged_init.json");
    let r = AdmissionReview::from_json(&raw).unwrap();
    let req = r.request().unwrap().clone();
    let d = admit(
        &req.object_json(),
        &manifest_at(1),
        &snapshot(),
        &req.meta(),
        None,
        Some(&spend(0)),
    )
    .expect("the wall runs");
    let Verdict::Deny { first, .. } = &d.verdict else {
        panic!("expected a refusal");
    };
    assert_ne!(
        first.wall,
        Wall::Budget,
        "a privileged pod's problem is not its price"
    );
}

// --- the record ------------------------------------------------------

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

/// The new event does not disturb the order the rest of the project
/// depends on: the request is still logged first and the decision is
/// still last, with the charge in between.
#[test]
fn the_charge_sits_between_the_request_and_the_decision() {
    let d = decide(POD, 20_000, Some(&spend(5_000)));
    let entries = as_json(&d);
    let kinds: Vec<&str> = entries
        .iter()
        .map(|e| e["event"]["kind"].as_str().unwrap())
        .collect();
    assert_eq!(
        kinds,
        vec!["pod_requested", "spend_charged", "pod_admitted"]
    );
    d.audit.verify().expect("the chain still verifies");
}

/// And the promotion contract from milestone 3 is untouched: the
/// decision events still carry the three fields `lex attest
/// import-apply` names. A new event kind in the middle of the log must
/// not break the loop that reads it.
#[test]
fn the_promotion_contract_survives_the_new_event() {
    let d = decide(POD, 20_000, Some(&spend(5_000)));
    let entries = as_json(&d);
    let admitted = event_of(&entries, "pod_admitted");
    for field in ["artifact_sha256", "manifest", "signer"] {
        assert!(
            admitted.get(field).is_some(),
            "`{field}` is named by the promotion contract: {admitted}"
        );
    }
    // `spend_charged` is deliberately *not* promotable: it is a
    // measurement, not a decision, and nothing should attribute a
    // number to a submitter as though they chose it.
    let charge = event_of(&entries, "spend_charged");
    assert!(charge.get("signer").is_none());
}
