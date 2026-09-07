//! The two webhook endpoints (alpibrusl/lex-k8s#10).
//!
//! `deploy/webhook.yaml` registers `/admit` for pods and `/narrow` for
//! `LexManifest`s. Both are thin: they resolve the inputs the CLI takes
//! as flags out of the caches, then call the *same* [`crate::admit`] and
//! [`crate::narrow`] the CLI calls. No decision is made in this file,
//! and none should be — the moment a rule lives only in the server, the
//! fixture corpus stops testing the wall that actually runs.
//!
//! # Answering, always
//!
//! With `failurePolicy: Fail` a dead webhook and a 500 look identical
//! to the cluster: both stop admissions. Only one of them says why. So
//! every path that cannot decide returns [`crate::review::cannot_run`]
//! carrying the request's own uid — an untargeted response is one the
//! API server discards, which would turn "we could not decide" into a
//! timeout nobody can read.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;

use crate::admission::Spend;
use crate::review::cannot_run;
use crate::serve::cache::{contents, Caches, ManifestLookup};
use crate::serve::ledger::Ledger;
use crate::serve::snapshot::{self, PodSubject};
use crate::{admit, admit_sealed, narrow, respond, AdmissionReview, Keyring, LexManifest, Verdict};

/// What the server holds for the life of the process.
#[derive(Clone)]
pub struct Wall {
    pub caches: Caches,
    /// The earned keyring, read once at startup from a mounted file.
    ///
    /// Absent means the trust wall is not consulted at all, which is
    /// exactly what the CLI does without `--trusted-keys`. Distinct
    /// from an empty keyring, which trusts nobody — the same
    /// "not asked is not unknown" rule milestone 4 turned on.
    pub keyring: Option<Arc<Keyring>>,
    /// The price list and namespace spend, when the operator mounted
    /// them. Only meaningful together, so they arrive together.
    pub spend: Option<Arc<Spend>>,
    /// Image prefixes the cluster asserts are signed. Empty means
    /// nothing is known to be signed, not that everything is.
    pub trusted_image_prefixes: Vec<String>,
    /// Where each decision's hash chain is written, if anywhere.
    pub audit_dir: Option<std::path::PathBuf>,
    /// Seals every decision's chain, when the operator mounted a key.
    pub audit_key: Option<Arc<crate::SigningKey>>,
    /// The running witness (alpibrusl/lex-k8s#13).
    ///
    /// One chain for the life of the process, appended to after every
    /// decision, so a deleted decision file leaves a gap somebody can
    /// see. A `Mutex` because decisions are concurrent and a chain is
    /// a sequence: two appends racing would be two entries claiming the
    /// same `seq`, which is the one thing `Chain::verify` is entitled
    /// to assume never happens.
    pub ledger: Option<Arc<Ledger>>,
    /// Where `parent: cluster/<name>` looks. See
    /// [`Caches::manifest_by_reference`].
    pub root_namespace: String,
}

/// `GET /healthz` — the process is up. Says nothing about the caches.
pub async fn healthz() -> &'static str {
    "ok\n"
}

/// `GET /readyz` — every cache has completed its first list.
///
/// Not ready is a 503, which keeps this pod out of the Service's
/// endpoints. That is what stops a cold cache from deciding: an empty
/// store reads as "no NetworkPolicy selects this pod", which means
/// *unrestricted egress*, and admitting on it would be admitting on a
/// snapshot of a cluster nobody has looked at yet.
pub async fn readyz(State(wall): State<Wall>) -> Response {
    let cold = wall.caches.cold();
    if cold.is_empty() {
        (StatusCode::OK, "ready\n".to_string()).into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            format!("caches still cold: {}\n", cold.join(", ")),
        )
            .into_response()
    }
}

/// `POST /admit` — a pod, against the grant governing its namespace.
pub async fn admit_pod(State(wall): State<Wall>, body: String) -> Response {
    let review = match AdmissionReview::from_json(&body) {
        Ok(r) => r,
        // No uid to answer to: there is nothing the API server would
        // match this response against, so this is the one case that is
        // an HTTP error rather than a refusal.
        Err(e) => return (StatusCode::BAD_REQUEST, format!("{e}\n")).into_response(),
    };
    let request = match review.request() {
        Ok(r) => r,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("{e}\n")).into_response(),
    };
    let uid = request.uid.clone();

    // A cold cache is not a permissive cache. Readiness keeps this pod
    // out of the Service, but a request that arrives anyway — a stale
    // endpoint, a direct call — must not be decided on absences the
    // wall has not actually read.
    let cold = wall.caches.cold();
    if !cold.is_empty() {
        return failed(
            &uid,
            &format!(
                "the caches this verdict depends on are still cold ({}), so the \
                 cluster state is unknown rather than empty",
                cold.join(", ")
            ),
        );
    }

    let manifest = match wall.caches.manifest_for(&request.namespace) {
        ManifestLookup::One(obj) => {
            let json = match serde_json::to_string(&*obj) {
                Ok(j) => j,
                Err(e) => return failed(&uid, &format!("cached LexManifest is unreadable: {e}")),
            };
            match LexManifest::read(&json) {
                Ok((_, m)) => m,
                Err(e) => {
                    return failed(
                        &uid,
                        &format!(
                            "the LexManifest governing namespace `{}` cannot be read, so \
                             this namespace has no usable ceiling: {e}",
                            request.namespace
                        ),
                    )
                }
            }
        }
        // Absence again, and the answer is the same as everywhere else
        // in this repo: a namespace nobody granted anything to grants
        // nothing. Refusing is the decision, not a malfunction — but it
        // is reported as `cannot_run` because the operator's fix is to
        // create a manifest, not to change the pod.
        ManifestLookup::None => {
            return failed(
                &uid,
                &format!(
                    "no LexManifest governs namespace `{}`. A namespace with no grant \
                     grants nothing; create one, or take this namespace out of the \
                     webhook's namespaceSelector",
                    request.namespace
                ),
            )
        }
        ManifestLookup::Ambiguous(names) => {
            return failed(
                &uid,
                &format!(
                    "namespace `{}` has {} LexManifests ({}), and this wall will not \
                     choose which ceiling applies. Leave exactly one",
                    request.namespace,
                    names.len(),
                    names.join(", ")
                ),
            )
        }
    };

    let subject = PodSubject::from_object(&request.namespace, &request.object);
    let snap = snapshot::build(
        &subject,
        &contents(&wall.caches.policies),
        &contents(&wall.caches.roles),
        &contents(&wall.caches.cluster_roles),
        &contents(&wall.caches.role_bindings),
        &contents(&wall.caches.cluster_role_bindings),
        wall.trusted_image_prefixes.clone(),
    );

    // The submitter is the API server's authenticated
    // `userInfo.username`, carried through `meta()` — never a header, a
    // flag or a body field. A webhook that let its caller name the
    // submitter would let any submitter spend another's record.
    let meta = request.meta();
    let decision = match match &wall.audit_key {
        Some(k) => admit_sealed(
            &request.object_json(),
            &manifest,
            &snap,
            &meta,
            wall.keyring.as_deref(),
            wall.spend.as_deref(),
            k,
        ),
        None => admit(
            &request.object_json(),
            &manifest,
            &snap,
            &meta,
            wall.keyring.as_deref(),
            wall.spend.as_deref(),
        ),
    } {
        Ok(d) => d,
        Err(e) => return failed(&uid, &e.to_string()),
    };

    // Written before the response goes out, and a failure to write is a
    // failure of the wall — the promotion loop downstream reads these
    // files, and a decision nobody can keep is not a record.
    if let Some(dir) = &wall.audit_dir {
        let name = format!("{}-{}.json", chrono_ish(), sanitise(&uid));
        match decision.audit.to_json() {
            Ok(json) => {
                if let Err(e) = std::fs::write(dir.join(&name), json) {
                    return failed(&uid, &format!("could not write the audit record: {e}"));
                }
            }
            Err(e) => return failed(&uid, &format!("could not serialise the audit record: {e}")),
        }
    }

    // The head on stdout on every decision, whatever else happens to
    // the file. It is the one line an external collector can scrape
    // without a volume, and it is the honest half of the persistence
    // gap this milestone does not close (alpibrusl/lex-os#54).
    let verdict = match &decision.verdict {
        Verdict::Admit => "admitted",
        Verdict::Deny { .. } => "refused",
    };

    // Witnessed after the decision is on disk, never before: a ledger
    // entry for a decision whose file was never written would report a
    // gap that is the wall's own fault, and send an auditor looking for
    // a deletion that did not happen.
    if let Some(ledger) = &wall.ledger {
        if let Err(e) = ledger.witness(crate::LedgerEvent::PodDecided {
            uid: uid.clone(),
            namespace: request.namespace.clone(),
            name: meta.name.clone(),
            verdict: verdict.to_string(),
            decision_head: decision.audit.head(),
            decision_entries: decision.audit.len() as u64,
            snapshot_sha256: snap.content_id(),
            signer: meta.signer.clone(),
        }) {
            // A witness nobody can keep is not a witness. Refusing here
            // is the same rule as refusing when the decision chain
            // cannot be written.
            return failed(&uid, &format!("could not witness the decision: {e}"));
        }
    }
    tracing::info!(
        verdict,
        namespace = %request.namespace,
        name = %meta.name,
        submitter = %meta.signer.clone().unwrap_or_else(|| "unauthenticated".into()),
        snapshot = %snap.content_id(),
        audit_head = %decision.audit.head(),
        entries = decision.audit.len(),
        sealed = decision.audit.sealed_count() == decision.audit.len(),
        "decided"
    );

    Json(respond(&uid, &decision)).into_response()
}

/// `POST /narrow` — a `LexManifest`, against the manifest it names as
/// its parent.
///
/// The CLI takes `--parent` and `--child`. Here only the child arrives,
/// and the parent is resolved from the cache by `spec.parent`. A named
/// parent that is not in the cache is a **refusal**: an unresolvable
/// ceiling is not an absent ceiling, and admitting on one would let a
/// child claim any authority by naming a parent that does not exist.
pub async fn narrow_manifest(State(wall): State<Wall>, body: String) -> Response {
    let review = match AdmissionReview::from_json(&body) {
        Ok(r) => r,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("{e}\n")).into_response(),
    };
    let request = match review.request() {
        Ok(r) => r,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("{e}\n")).into_response(),
    };
    let uid = request.uid.clone();

    let child_json = request.object_json();
    let (child_crd, child) = match LexManifest::read(&child_json) {
        Ok(v) => v,
        Err(e) => return refuse(&uid, &e.to_string()),
    };

    let Some(reference) = child_crd.spec.parent.clone() else {
        // No parent named is not a widening: a root manifest is a
        // legitimate thing. The ceiling above it is the cluster's own
        // RBAC, which decides who may write one at all.
        return Json(allow(&uid, "no parent named; nothing to narrow against")).into_response();
    };

    if !wall.caches.manifests.ready() {
        // A cold cache cannot tell "no such parent" from "not listed
        // yet", and those have opposite answers.
        return failed(
            &uid,
            "the LexManifest cache is still cold, so the parent cannot be resolved",
        );
    }

    let Some(parent_obj) = wall
        .caches
        .manifest_by_reference(&reference, &wall.root_namespace)
    else {
        return refuse(
            &uid,
            &format!(
                "parent `{reference}` is not in the cluster. An unresolvable ceiling is \
                 not an absent one: a child that could name a parent nobody can read \
                 would be granting itself whatever it liked"
            ),
        );
    };
    let parent_json = match serde_json::to_string(&*parent_obj) {
        Ok(j) => j,
        Err(e) => return failed(&uid, &format!("cached parent is unreadable: {e}")),
    };
    let (_, parent) = match LexManifest::read(&parent_json) {
        Ok(v) => v,
        Err(e) => return refuse(&uid, &format!("parent `{reference}` cannot be read: {e}")),
    };

    let outcome = narrow(&parent, &child);
    // `/narrow` wrote no record at all before #13 — its verdicts reached
    // the log and nothing else, and a manifest that widens its parent is
    // the more consequential of the two decisions this wall makes.
    if let Some(ledger) = &wall.ledger {
        if let Err(e) = ledger.witness(crate::LedgerEvent::ManifestDecided {
            uid: uid.clone(),
            child: child_crd.reference(),
            parent: Some(reference.clone()),
            verdict: if outcome.is_ok() { "narrows" } else { "widens" }.to_string(),
            reason: outcome.as_ref().err().map(|e| e.to_string()),
            signer: request.meta().signer.clone(),
        }) {
            return failed(&uid, &format!("could not witness the decision: {e}"));
        }
    }
    match outcome {
        Ok(()) => {
            tracing::info!(
                verdict = "narrows",
                parent = %reference,
                child = %child_crd.reference(),
                "manifest admitted"
            );
            Json(allow(&uid, &format!("narrows `{reference}`"))).into_response()
        }
        Err(e) => {
            tracing::info!(
                verdict = "widens",
                parent = %reference,
                child = %child_crd.reference(),
                "manifest refused"
            );
            refuse(
                &uid,
                &format!(
                    "this LexManifest widens its parent `{reference}`: {e}. A team lead \
                     hands out authority they hold, never authority they do not"
                ),
            )
        }
    }
}

/// A verdict the wall reached: refused, with a reason, HTTP 200.
///
/// 200 is not a detail. A refusal is a *decision*, and returning it as
/// an HTTP error would make it indistinguishable from a broken wall —
/// the same 8-versus-2 distinction the CLI's exit codes keep.
fn refuse(uid: &str, why: &str) -> Response {
    let review = AdmissionReview {
        api_version: "admission.k8s.io/v1".into(),
        kind: "AdmissionReview".into(),
        request: None,
        response: Some(crate::review::AdmissionResponse {
            uid: uid.to_string(),
            allowed: false,
            status: Some(crate::review::Status {
                code: 403,
                message: why.to_string(),
                details: None,
            }),
            warnings: Vec::new(),
        }),
    };
    Json(review).into_response()
}

fn allow(uid: &str, note: &str) -> AdmissionReview {
    AdmissionReview {
        api_version: "admission.k8s.io/v1".into(),
        kind: "AdmissionReview".into(),
        request: None,
        response: Some(crate::review::AdmissionResponse {
            uid: uid.to_string(),
            allowed: true,
            status: None,
            warnings: vec![note.to_string()],
        }),
    }
}

/// The wall could not run. Answered, not dropped.
fn failed(uid: &str, why: &str) -> Response {
    tracing::error!(uid, why, "the wall could not run, so it did not decide");
    Json(cannot_run(uid, why)).into_response()
}

/// A sortable filename prefix without pulling in a date library.
///
/// Seconds since the epoch: enough to order a run's records, and the
/// record itself carries what actually matters.
fn chrono_ish() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn sanitise(uid: &str) -> String {
    uid.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect()
}
