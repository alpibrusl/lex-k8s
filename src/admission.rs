//! The wall (alpibrusl/lex-k8s#3): an `AdmissionReview` in, a decision
//! out.
//!
//! ```text
//! pod_requested                    ← logged BEFORE any wall decides
//!   → effects       spec + snapshot → rows                     (#2)
//!   → lattice       pod.demands ≤ manifest.grant
//!   → facet         every named thing is named in the grant
//!   → trust         an unscored submitter gets no waivers
//!   → pod_admitted | pod_refused
//! ```
//!
//! # Two walls, because one cannot say both things
//!
//! The lattice bounds *how far*: `network: allowlist` means named
//! destinations rather than the whole internet. The facet bounds
//! *where*: which hosts, which Secrets, which capabilities. Running one
//! without the other leaves a real hole — a pod reaching
//! `exfil.example.com` passes a lattice check for `allowlist` and fails
//! the facet, and a pod on `hostNetwork` passes any list of hosts and
//! fails the lattice.
//!
//! # The record is written first
//!
//! `pod_requested` lands before either wall runs, so a refusal is
//! exactly as auditable as an admission. That ordering is lex-os's
//! supervisor's, and it is the third repo to inherit it.
//!
//! # A refusal is a typed record, not a string
//!
//! An agent emitting the pod spec gets something it can act on — the
//! effect that tripped, what the grant does allow, the manifest it was
//! judged against — rather than a message to parse. That is the
//! `RepairHint` shape the epic asks for.

use lex_os_audit::{Chain, ChainPayload};
use lex_os_manifest::{Grant, Manifest};
use serde::{Deserialize, Serialize};

use crate::facet::PodFacet;
use crate::manifest::pod_facet;
use crate::trust::{Keyring, Standing};
use crate::{ClusterSnapshot, Effect, EffectRow, PodEffects, SpecError};

/// What this wall records. lex-os knows nothing about any of it — which
/// is why `Chain<E>` is generic (lex-os#67).
///
/// # The promotion contract
///
/// `pod_admitted` and `pod_refused` are shaped to satisfy
/// `lex attest import-apply` (alpibrusl/lex-lang#794), which does not
/// know this repo's vocabulary and so names three fields of its own:
/// **`artifact_sha256`** (the decided bytes), **`manifest`** (the
/// ceiling), and **`signer`** (who authorised it). `subject` is
/// optional and human-facing — the `namespace/name` an operator would
/// grep for.
///
/// That is why the spec hash is spelled `artifact_sha256` in the log
/// while [`PodEffects`] still calls its field `spec_sha256`: the
/// contract name belongs where the contract applies, and nowhere else.
///
/// The variant promoted is `PlanApply` for both gates. lex-iac emits a
/// Terraform plan decision and this wall emits a Kubernetes admission
/// decision, but they are the same fact — a plan-shaped artifact,
/// checked against a manifest, decided under a signer — and a
/// second discriminant would split one submitter's track record in two.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AdmissionEvent {
    /// Written before anything is decided.
    PodRequested {
        uid: String,
        namespace: String,
        name: String,
        artifact_sha256: String,
        snapshot_sha256: String,
        manifest: String,
        demands: Grant,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signer: Option<String>,
        /// What the keyring said — `not-consulted` when none was given.
        trust: String,
    },
    PodAdmitted {
        uid: String,
        artifact_sha256: String,
        manifest: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signer: Option<String>,
        subject: String,
    },
    /// Refused, naming the single effect that tripped the wall.
    ///
    /// `reason` doubles as the contract's failure detail:
    /// `import-apply` reads it into `AttestationResult::Failed`, so a
    /// submitter's record says *why* it was refused, not merely that it
    /// was.
    PodRefused {
        uid: String,
        artifact_sha256: String,
        manifest: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signer: Option<String>,
        subject: String,
        wall: String,
        effect: String,
        source: String,
        reason: String,
    },
}

impl ChainPayload for AdmissionEvent {
    const DOMAIN: &'static [u8] = b"lex.k8s.audit.v1";
}

/// Which wall a refusal hit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Wall {
    /// The pod reaches further than the grant's lattice permits.
    TypeCheck,
    /// The pod names something the grant does not.
    Narrowing,
    /// The manifest waived a check, and the submitter has no earned
    /// standing to be waived for.
    Trust,
}

impl Wall {
    pub fn as_str(self) -> &'static str {
        match self {
            Wall::TypeCheck => "type-check",
            Wall::Narrowing => "narrowing",
            Wall::Trust => "trust",
        }
    }
}

/// One refusal, in the shape an agent can act on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Refusal {
    pub wall: Wall,
    /// The effect that tripped it.
    pub effect: String,
    /// The field it came from, as an operator would grep for it.
    pub source: String,
    pub reason: String,
    /// What the grant does allow, so the answer is actionable rather
    /// than merely negative.
    pub grant_allows: Vec<String>,
}

/// The wall's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Admit,
    Deny { first: Refusal, all: Vec<Refusal> },
}

impl Verdict {
    pub fn allowed(&self) -> bool {
        matches!(self, Verdict::Admit)
    }
}

/// A completed admission: the verdict, the compiled pod, the record.
#[derive(Debug, Clone)]
pub struct Decision {
    pub verdict: Verdict,
    pub pod: PodEffects,
    pub audit: Chain<AdmissionEvent>,
    /// Dimensions this manifest declared no policy for, so the wall did
    /// not check them.
    ///
    /// Reported rather than silently passed: "we did not look" and "we
    /// looked and it was fine" are different facts, and an operator
    /// reading an admission deserves to know which one they got. The
    /// same distinction lex-iac draws between `None` and `Some(0)` for
    /// an unpriced change.
    ///
    /// For an unscored submitter each of these is also a refusal — see
    /// [`Wall::Trust`].
    pub unchecked: Vec<String>,
    /// Who asked, as the API server authenticated them.
    pub signer: Option<String>,
    /// What the keyring said about them.
    pub standing: Standing,
}

impl Decision {
    /// Semantic exit code, following lex-os: 0 admitted, 8 refused.
    pub fn exit_code(&self) -> i32 {
        match self.verdict {
            Verdict::Admit => 0,
            Verdict::Deny { .. } => 8,
        }
    }
}

/// The wall could not run.
///
/// Distinct from a refusal on purpose: a refusal is a decision, and a
/// webhook that conflates the two will eventually read a broken wall as
/// an admission. With `failurePolicy: Fail` the API server turns this
/// into a rejection anyway — which is correct, and is not the same as
/// this code deciding.
#[derive(Debug, thiserror::Error)]
pub enum AdmissionError {
    #[error(transparent)]
    Spec(#[from] SpecError),
    #[error("the manifest's `pod` facet is present but unreadable: {0}")]
    Manifest(String),
}

/// Check one pod against the manifest governing its namespace.
/// `keyring` is the earned `{"trusted":[…]}` list, when the operator
/// supplied one. It never widens anything: all it decides is whether a
/// waiver the manifest *already* granted — an unchecked dimension —
/// applies to this submitter. `None` consults nothing, and behaves
/// exactly as this wall did before the keyring existed.
pub fn admit(
    spec_json: &str,
    manifest: &Manifest,
    snapshot: &ClusterSnapshot,
    request: &RequestMeta,
    keyring: Option<&Keyring>,
) -> Result<Decision, AdmissionError> {
    let pod = crate::compile_str(spec_json, snapshot)?;
    let facet = pod_facet(manifest).map_err(|e| AdmissionError::Manifest(e.to_string()))?;
    let manifest_id = manifest.content_id().0;

    let standing = match (&request.signer, keyring) {
        (_, None) => Standing::NotConsulted,
        // A review nobody authenticated is not a submitter with a bad
        // record; it is no submitter at all, and the narrower reading
        // is the safe one.
        (None, Some(_)) => Standing::Unknown,
        (Some(who), Some(k)) => k.standing_of(who),
    };
    let subject = format!("{}/{}", request.namespace, request.name);

    let mut audit: Chain<AdmissionEvent> = Chain::new();
    audit.append(AdmissionEvent::PodRequested {
        uid: request.uid.clone(),
        namespace: request.namespace.clone(),
        name: request.name.clone(),
        artifact_sha256: pod.spec_sha256.clone(),
        snapshot_sha256: pod.snapshot_sha256.clone(),
        manifest: manifest_id.clone(),
        demands: pod.demands,
        signer: request.signer.clone(),
        trust: standing.as_str().to_string(),
    });

    let mut refusals: Vec<Refusal> = Vec::new();

    // Wall 1 — the lattice. How far the pod reaches, against the
    // ceiling. One comparison, the same one `lex-os-check` makes.
    if let Err(e) = pod.within(&manifest.grant) {
        // Name the row that pushed the demand there, so the refusal
        // points at a line of YAML rather than at an abstract level.
        let culprit = worst_row(&pod, &manifest.grant);
        refusals.push(Refusal {
            wall: Wall::TypeCheck,
            effect: culprit
                .map(|r| r.effect.name())
                .unwrap_or_else(|| "grant".into()),
            source: culprit
                .map(|r| r.source.to_string())
                .unwrap_or_else(|| "spec".into()),
            reason: e.to_string(),
            grant_allows: describe(&manifest.grant),
        });
    }

    // Wall 2 — the facet. What the pod names, against what the grant
    // names.
    for row in &pod.rows {
        if let Err(denial) = facet.admits(&row.effect) {
            refusals.push(Refusal {
                wall: Wall::Narrowing,
                effect: row.effect.name(),
                source: row.source.to_string(),
                reason: denial.to_string(),
                grant_allows: granted_for(&facet, &row.effect),
            });
        }
    }

    // Wall 3 — standing. Not a new authority: every dimension named
    // here is one the *manifest* declared no policy for, so admitting
    // under it is a waiver the manifest granted. A submitter with a
    // record keeps the waiver; one nobody has scored does not.
    //
    // This can only ever refuse something the other two walls let
    // through. It cannot admit anything they refused, which is the
    // property that keeps the manifest the ceiling.
    let unchecked = unchecked_dimensions(&facet, &pod);
    if standing.needs_the_verb_named() {
        for dimension in &unchecked {
            refusals.push(Refusal {
                wall: Wall::Trust,
                effect: "unchecked".to_string(),
                source: dimension
                    .split(':')
                    .next()
                    .unwrap_or("manifest")
                    .to_string(),
                reason: format!(
                    "{dimension}; the manifest waives that check, and \
                     {} has no earned standing to be waived for — \
                     declare the policy, or let the submitter earn a score",
                    request
                        .signer
                        .as_deref()
                        .unwrap_or("an unauthenticated submitter")
                ),
                grant_allows: Vec::new(),
            });
        }
    }

    let verdict = match refusals.split_first() {
        None => {
            audit.append(AdmissionEvent::PodAdmitted {
                uid: request.uid.clone(),
                artifact_sha256: pod.spec_sha256.clone(),
                manifest: manifest_id,
                signer: request.signer.clone(),
                subject: subject.clone(),
            });
            Verdict::Admit
        }
        Some((first, _)) => {
            audit.append(AdmissionEvent::PodRefused {
                uid: request.uid.clone(),
                artifact_sha256: pod.spec_sha256.clone(),
                manifest: manifest_id,
                signer: request.signer.clone(),
                subject: subject.clone(),
                wall: first.wall.as_str().to_string(),
                effect: first.effect.clone(),
                source: first.source.clone(),
                reason: first.reason.clone(),
            });
            Verdict::Deny {
                first: first.clone(),
                all: refusals.clone(),
            }
        }
    };

    Ok(Decision {
        verdict,
        unchecked,
        pod,
        audit,
        signer: request.signer.clone(),
        standing,
    })
}

/// Who asked, from the `AdmissionReview` request.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestMeta {
    pub uid: String,
    pub namespace: String,
    pub name: String,
    /// The authenticated requester — a ServiceAccount or an agent key.
    /// `None` when the review carried no `userInfo`, which the wall
    /// records rather than papering over: an unattributed decision is
    /// not evidence about anyone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
}

/// The row whose demand exceeds the grant by the most — the one worth
/// naming in a refusal.
fn worst_row<'a>(pod: &'a PodEffects, granted: &Grant) -> Option<&'a EffectRow> {
    pod.rows
        .iter()
        .filter(|r| Grant::narrow(granted, &r.demands).is_err())
        .max_by_key(|r| {
            r.demands.filesystem.rank() as u16
                + r.demands.network.rank() as u16
                + r.demands.exec.rank() as u16
        })
}

/// The grant's lattice, in words an operator can act on.
fn describe(g: &Grant) -> Vec<String> {
    vec![
        format!("filesystem: {:?}", g.filesystem),
        format!("network: {:?}", g.network),
        format!("exec: {:?}", g.exec),
    ]
}

/// What the facet grants in the dimension this effect belongs to.
fn granted_for(facet: &PodFacet, effect: &Effect) -> Vec<String> {
    match effect {
        Effect::Secret { .. } => facet.secrets.clone(),
        Effect::Capability { .. } => facet.capabilities.clone(),
        Effect::Egress { .. } => facet.egress.clone(),
        Effect::UntrustedImage { .. } => facet.image_prefixes.clone(),
        _ => Vec::new(),
    }
}

/// Dimensions the manifest declared no policy for.
fn unchecked_dimensions(facet: &PodFacet, pod: &PodEffects) -> Vec<String> {
    let mut out = Vec::new();
    if facet.image_prefixes.is_empty()
        && pod
            .rows
            .iter()
            .any(|r| matches!(r.effect, Effect::UntrustedImage { .. }))
    {
        out.push(
            "image provenance: the manifest names no `imagePrefixes`, so images were \
             not checked"
                .to_string(),
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::LexManifest;
    use crate::{EgressPolicy, Level};

    const PAYMENTS: &str = r#"{
      "metadata": { "name": "payments", "namespace": "payments" },
      "spec": {
        "goal": "serve the payments API",
        "grant": {
          "egress": ["postgres.payments.svc", "api.stripe.com:443"],
          "secrets": ["stripe-live-key"],
          "capabilities": ["NET_BIND_SERVICE"]
        }
      }
    }"#;

    fn manifest() -> Manifest {
        LexManifest::read(PAYMENTS).unwrap().1
    }

    fn snapshot() -> ClusterSnapshot {
        ClusterSnapshot {
            egress: Some(EgressPolicy {
                policy_names: vec!["payments-egress".into()],
                cidrs: vec!["10.42.0.0/16".into()],
                ..Default::default()
            }),
            trusted_image_prefixes: vec!["registry.internal/".into()],
            ..Default::default()
        }
    }

    fn meta() -> RequestMeta {
        RequestMeta {
            uid: "abc-123".into(),
            namespace: "payments".into(),
            name: "api".into(),
            signer: Some("system:serviceaccount:payments:deployer".into()),
        }
    }

    const GOOD: &str = r#"{"containers":[{"name":"api",
        "image":"registry.internal/payments/api@sha256:aa",
        "env":[{"name":"K","valueFrom":{"secretKeyRef":{"name":"stripe-live-key","key":"k"}}}],
        "securityContext":{"capabilities":{"add":["NET_BIND_SERVICE"]}}}]}"#;

    #[test]
    fn a_pod_inside_its_grant_is_admitted_and_recorded() {
        let d = admit(GOOD, &manifest(), &snapshot(), &meta(), None).unwrap();
        assert!(d.verdict.allowed(), "{:?}", d.verdict);
        assert_eq!(d.exit_code(), 0);
        assert_eq!(d.audit.len(), 2, "request then decision");
        d.audit.verify().expect("the chain verifies");
        assert_eq!(d.audit.entries()[1].prev_hash, d.audit.entries()[0].hash);
    }

    /// The demo. The pod is exemplary; the cluster's NetworkPolicy is
    /// not. An allow-list of two hosts cannot admit `0.0.0.0/0`.
    #[test]
    fn a_pod_that_lies_about_its_egress_is_refused_by_both_walls() {
        let open = ClusterSnapshot {
            egress: Some(EgressPolicy {
                policy_names: vec!["payments-egress".into(), "legacy-allow-all".into()],
                cidrs: vec!["10.42.0.0/16".into(), "0.0.0.0/0".into()],
                ..Default::default()
            }),
            ..snapshot()
        };
        let d = admit(GOOD, &manifest(), &open, &meta(), None).unwrap();
        assert_eq!(d.exit_code(), 8);

        let Verdict::Deny { all, .. } = &d.verdict else {
            panic!("expected a refusal, got {:?}", d.verdict);
        };
        // Both walls catch it, and they catch different things: the
        // lattice says `full` exceeds `allowlist`; the facet says
        // 0.0.0.0/0 is not one of the two named hosts.
        assert!(all.iter().any(|r| r.wall == Wall::TypeCheck));
        let facet_refusal = all
            .iter()
            .find(|r| r.wall == Wall::Narrowing)
            .expect("the facet refuses it too");
        assert!(facet_refusal
            .grant_allows
            .contains(&"api.stripe.com:443".to_string()));
    }

    /// A Secret the manifest never named, in a pod that is otherwise
    /// inside its lattice ceiling. The facet is the only wall that
    /// catches this — `filesystem: read-only` cannot say *which*.
    #[test]
    fn a_secret_the_manifest_never_named_is_refused_by_the_facet_alone() {
        let spec = r#"{"containers":[{"name":"api",
            "image":"registry.internal/payments/api@sha256:aa",
            "env":[{"name":"K","valueFrom":{"secretKeyRef":{"name":"root-ca-key","key":"k"}}}]}]}"#;
        let d = admit(spec, &manifest(), &snapshot(), &meta(), None).unwrap();

        let Verdict::Deny { all, .. } = &d.verdict else {
            panic!("expected a refusal, got {:?}", d.verdict);
        };
        assert_eq!(
            all.len(),
            1,
            "the lattice is satisfied; only the facet trips"
        );
        assert_eq!(all[0].wall, Wall::Narrowing);
        assert!(all[0].reason.contains("root-ca-key"));
        assert!(all[0].source.contains("containers[api]"));
    }

    /// ...and the mirror: `hostNetwork` passes any list of hosts and
    /// fails the lattice. Neither wall alone is enough.
    #[test]
    fn host_network_is_caught_by_the_lattice_not_the_egress_list() {
        let spec = r#"{"hostNetwork":true,"containers":[{"name":"api",
            "image":"registry.internal/payments/api@sha256:aa"}]}"#;
        let d = admit(spec, &manifest(), &snapshot(), &meta(), None).unwrap();

        let Verdict::Deny { all, .. } = &d.verdict else {
            panic!("expected a refusal");
        };
        assert!(all.iter().any(|r| r.wall == Wall::TypeCheck));
        let tc = all.iter().find(|r| r.wall == Wall::TypeCheck).unwrap();
        assert!(
            tc.source.contains("hostNetwork"),
            "names the field: {}",
            tc.source
        );
        assert!(tc.grant_allows.iter().any(|g| g.contains("network")));
    }

    /// The privileged init container from milestone 1: reading only
    /// `containers[0]` would admit this.
    #[test]
    fn a_privileged_init_container_is_refused() {
        let spec = r#"{"containers":[{"name":"api",
            "image":"registry.internal/payments/api@sha256:aa"}],
            "initContainers":[{"name":"tuner","image":"registry.internal/ops@sha256:bb",
              "securityContext":{"privileged":true}}]}"#;
        let d = admit(spec, &manifest(), &snapshot(), &meta(), None).unwrap();
        assert!(!d.verdict.allowed());
        let Verdict::Deny { all, .. } = &d.verdict else {
            panic!()
        };
        assert!(all
            .iter()
            .any(|r| r.source.contains("initContainers[tuner]")));
    }

    /// "We did not look" and "we looked and it was fine" are different
    /// facts, and an admission says which it is.
    #[test]
    fn a_dimension_the_manifest_declares_no_policy_for_is_reported_not_hidden() {
        // The manifest names no imagePrefixes, and the pod's image is
        // from an untrusted source by the snapshot's reckoning.
        let spec = r#"{"containers":[{"name":"api","image":"docker.io/nginx:latest"}]}"#;
        let d = admit(spec, &manifest(), &snapshot(), &meta(), None).unwrap();
        assert!(
            d.unchecked.iter().any(|u| u.contains("image provenance")),
            "unchecked: {:?}",
            d.unchecked
        );
    }

    /// ...and when the manifest *does* declare one, it is enforced.
    #[test]
    fn a_declared_image_policy_is_enforced() {
        let strict = LexManifest::read(
            r#"{"spec":{"grant":{"egress":["postgres.payments.svc"],
                "imagePrefixes":["registry.internal/"]}}}"#,
        )
        .unwrap()
        .1;
        let spec = r#"{"containers":[{"name":"api","image":"docker.io/nginx:latest"}]}"#;
        let d = admit(spec, &strict, &snapshot(), &meta(), None).unwrap();

        let Verdict::Deny { all, .. } = &d.verdict else {
            panic!("expected a refusal, got {:?}", d.verdict);
        };
        assert!(all.iter().any(|r| r.reason.contains("docker.io/nginx")));
        assert!(d.unchecked.is_empty(), "it was checked");
    }

    /// The wall could not run is not the wall said no.
    #[test]
    fn a_document_that_is_not_a_pod_stops_the_wall_rather_than_refusing() {
        for not_a_pod in [r#"{}"#, r#"[]"#, r#"{"kind":"ConfigMap"}"#] {
            let err = admit(not_a_pod, &manifest(), &snapshot(), &meta(), None).unwrap_err();
            assert!(matches!(err, AdmissionError::Spec(_)), "{not_a_pod}: {err}");
        }
    }

    /// The record precedes the decision, on refusals as much as
    /// admissions — a wall you can only audit when it said yes is not
    /// one anybody can review.
    #[test]
    fn the_request_is_recorded_before_the_verdict() {
        let d = admit(
            r#"{"hostNetwork":true,"containers":[{"name":"a","image":"x@sha256:1"}]}"#,
            &manifest(),
            &snapshot(),
            &meta(),
            None,
        )
        .unwrap();
        assert!(!d.verdict.allowed());
        assert_eq!(d.audit.len(), 2);
        assert!(matches!(
            d.audit.entries()[0].event,
            AdmissionEvent::PodRequested { .. }
        ));
        assert!(matches!(
            d.audit.entries()[1].event,
            AdmissionEvent::PodRefused { .. }
        ));
        d.audit.verify().expect("the chain verifies");

        // The demand is in the record, so a reviewer sees what was
        // asked for and not only that it was refused.
        let AdmissionEvent::PodRequested { demands, .. } = &d.audit.entries()[0].event else {
            panic!()
        };
        assert_eq!(demands.network, Level::Full);
    }
}
