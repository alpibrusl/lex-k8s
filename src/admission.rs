//! The wall (alpibrusl/lex-k8s#3): an `AdmissionReview` in, a decision
//! out.
//!
//! ```text
//! pod_requested                    ← logged BEFORE any wall decides
//!   → effects       spec + snapshot → rows                     (#2)
//!   → lattice       pod.demands ≤ manifest.grant
//!   → facet         every named thing is named in the grant
//!   → trust         an unscored submitter gets no waivers
//!   → spend_charged the pod's reservation, priced and recorded
//!   → budget        the namespace must still fit `max_money_cents`
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

use lex_os_audit::{Chain, ChainPayload, SigningKey};
use lex_os_manifest::{Grant, Manifest};
use serde::{Deserialize, Serialize};

use crate::cost::{CostError, PriceList, SpendReport};
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
    /// The pod's priced reservation, recorded before the budget wall
    /// decides — so an admission carries the number it was admitted
    /// against, not only a refusal.
    SpendCharged {
        uid: String,
        artifact_sha256: String,
        currency: String,
        cpu_millicores: u64,
        memory_bytes: u64,
        pod_monthly_minor: u64,
        namespace_monthly_minor: u64,
        budget_minor: u64,
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
    /// Admitting the pod would put the namespace over
    /// `budget.max_money_cents`.
    Budget,
}

impl Wall {
    pub fn as_str(self) -> &'static str {
        match self {
            Wall::TypeCheck => "type-check",
            Wall::Narrowing => "narrowing",
            Wall::Trust => "trust",
            Wall::Budget => "budget",
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
    /// Grants this cluster can check but cannot enforce (#17).
    ///
    /// Disclosed on every decision, admitted or refused, because the
    /// alternative is a grant that reads as enforcement and is not.
    /// Distinct from `unchecked`: nothing the submitter does can clear
    /// this, so it never turns on their standing.
    pub unenforceable: Vec<String>,
    /// Who asked, as the API server authenticated them.
    pub signer: Option<String>,
    /// What the keyring said about them.
    pub standing: Standing,
    /// What this pod's reservation was priced at, in minor units, when
    /// a price list was supplied. `None` means *unpriced*, never zero.
    pub charged: Option<u64>,
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
    /// The spend inputs could not be reconciled with the grant — a
    /// report in another currency, say. Not a refusal: the wall could
    /// not run.
    #[error(transparent)]
    Cost(#[from] CostError),
}

/// What the namespace already spends, and what resources cost.
///
/// Two numbers rather than one because they answer different
/// questions and come from different places: the price list is a
/// standing fact about the cluster, and the report is a measurement
/// somebody took. Bundled so `admit` takes one optional argument
/// rather than two that are only ever meaningful together.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Spend {
    pub prices: PriceList,
    pub report: SpendReport,
}

/// Check one pod against the manifest governing its namespace.
/// `spend` is the price list plus what the namespace already spends,
/// when the operator supplied them. `None` runs no budget wall at all —
/// the same shape as `keyring`, and for the same reason: a wall nobody
/// configured must not invent a ceiling.
///
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
    spend: Option<&Spend>,
) -> Result<Decision, AdmissionError> {
    admit_inner(spec_json, manifest, snapshot, request, keyring, spend, None)
}

/// [`admit`], with every audit entry sealed by `key` (lex-os#54).
///
/// A separate entry point rather than a seventh argument on `admit`,
/// because there are exactly two callers that seal — the CLI and the
/// webhook — and forty that do not care. lex-os put the key on the
/// chain because it had twenty `append` sites that could each forget;
/// this crate has one place a chain is built, so naming the sealed path
/// is enough.
///
/// # Why this matters more here than upstream
///
/// This wall writes its chains to the **pod's own filesystem**, which is
/// the weakest place any consumer of `Chain<E>` has put one. Without a
/// seal, whoever can reach that volume can rewrite a refusal into an
/// admission and recompute the hashes, and the result verifies.
///
/// # What a seal still does not fix here
///
/// Each admission gets its **own** chain, so there is no tail to
/// truncate — and equally, **deleting a whole decision file is
/// invisible**. That is the same gap one level up, and a checkpoint
/// cannot close it: you cannot commit to the length of a set of files
/// nobody is counting. Closing it needs a running ledger of decision
/// heads; see the README's cautions.
#[allow(clippy::too_many_arguments)]
pub fn admit_sealed(
    spec_json: &str,
    manifest: &Manifest,
    snapshot: &ClusterSnapshot,
    request: &RequestMeta,
    keyring: Option<&Keyring>,
    spend: Option<&Spend>,
    key: &SigningKey,
) -> Result<Decision, AdmissionError> {
    admit_inner(
        spec_json,
        manifest,
        snapshot,
        request,
        keyring,
        spend,
        Some(key),
    )
}

#[allow(clippy::too_many_arguments)]
fn admit_inner(
    spec_json: &str,
    manifest: &Manifest,
    snapshot: &ClusterSnapshot,
    request: &RequestMeta,
    keyring: Option<&Keyring>,
    spend: Option<&Spend>,
    audit_key: Option<&SigningKey>,
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

    // Sealed before the first append, so there is no window in which an
    // entry is written unsealed — including the request entry, which is
    // logged before any wall runs and is therefore the one an
    // after-the-fact editor would most like to be missing.
    let mut audit: Chain<AdmissionEvent> = match audit_key {
        Some(k) => Chain::new().sealed_with(k.clone()),
        None => Chain::new(),
    };
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

    // Wall 2b — image provenance, from the *manifest*.
    //
    // The rows above can only refuse an image the cluster snapshot
    // already doubted, because a trusted image emits no row to refuse
    // (#19). That left `spec.grant.imagePrefixes` as decoration: a team
    // handed a mandate and told to narrow it — "from now on, only images
    // under your own path" — changed nothing, and nothing said so.
    //
    // So every image is held to the manifest as well. The two lists
    // intersect rather than override: the cluster says which registries
    // it will accept at all, the manifest says which of those this
    // workload may use, and a manifest can only narrow. An empty list
    // still means "the manifest names no policy" and is reported as an
    // unchecked dimension below, not read as "nothing is allowed".
    if !facet.image_prefixes.is_empty() {
        for image in &pod.images {
            if !facet
                .image_prefixes
                .iter()
                .any(|p| !p.is_empty() && image.starts_with(p.as_str()))
            {
                refusals.push(Refusal {
                    wall: Wall::Narrowing,
                    effect: format!("image:{image}"),
                    source: "spec.containers[].image".into(),
                    reason: format!(
                        "`{image}` is outside the `imagePrefixes` this manifest grants"
                    ),
                    grant_allows: facet.image_prefixes.clone(),
                });
            }
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
    let unenforceable = unenforceable_egress(&facet);

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

    // Wall 4 — the budget. After the others and before admitting,
    // matching lex-os's gate order, and the charge is recorded whether
    // or not it fits: a budget you can only see once it was exceeded is
    // not a budget anyone can plan against.
    //
    // **This refuses admissions; it never evicts.** A namespace already
    // over its ceiling keeps every pod it is running — the wall's whole
    // job is to stop the *next* one. An admission webhook that could
    // take down running workloads because a price list changed would be
    // a far worse failure than the overspend it prevented.
    let mut charged = None;
    if let Some(s) = spend {
        s.report.check_currency(&facet.currency)?;
        let r = pod.reservation.reservation;
        let pod_minor = s.prices.price(&r);
        let after = s.report.namespace_monthly_minor.saturating_add(pod_minor);
        let budget = manifest.budget.max_money_cents;
        audit.append(AdmissionEvent::SpendCharged {
            uid: request.uid.clone(),
            artifact_sha256: pod.spec_sha256.clone(),
            currency: facet.currency.clone(),
            cpu_millicores: r.cpu_millicores,
            memory_bytes: r.memory_bytes,
            pod_monthly_minor: pod_minor,
            namespace_monthly_minor: s.report.namespace_monthly_minor,
            budget_minor: budget,
        });
        charged = Some(pod_minor);

        // A container that declared nothing cannot be charged, and
        // pricing it at zero would make omitting `requests` the
        // cheapest way past the ceiling — the exact evasion this wall
        // exists to prevent. Refused before the arithmetic, because the
        // arithmetic would otherwise look like it succeeded.
        for u in &pod.reservation.undeclared {
            refusals.push(Refusal {
                wall: Wall::Budget,
                effect: "unpriced".to_string(),
                source: format!("{}[{}].resources.requests", u.kind, u.container),
                reason: format!(
                    "container `{}` declares no CPU or memory request, so it cannot be \
                     charged against the namespace budget — an empty request is not a \
                     request for nothing, it is a BestEffort pod that uses whatever the \
                     node has spare",
                    u.container
                ),
                grant_allows: vec![format!(
                    "budget: {} {} / month",
                    facet.currency,
                    money(budget)
                )],
            });
        }

        if after > budget {
            refusals.push(Refusal {
                wall: Wall::Budget,
                effect: "spend".to_string(),
                source: "resources.requests".to_string(),
                reason: format!(
                    "this pod reserves {} {}/month ({}m CPU, {} MiB), which would put \
                     `{}` at {} against a ceiling of {} ({} over) — this bounds \
                     committed reservation, not the invoice",
                    facet.currency,
                    money(pod_minor),
                    r.cpu_millicores,
                    r.memory_bytes / (1024 * 1024),
                    request.namespace,
                    money(after),
                    money(budget),
                    money(after - budget),
                ),
                grant_allows: vec![format!(
                    "budget: {} {} / month, of which {} is already committed",
                    facet.currency,
                    money(budget),
                    money(s.report.namespace_monthly_minor)
                )],
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
        unenforceable,
        pod,
        audit,
        signer: request.signer.clone(),
        standing,
        charged,
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

/// Minor units as a decimal. Integer arithmetic only, matching the
/// house rule that money never touches a float.
fn money(minor: u64) -> String {
    format!("{}.{:02}", minor / 100, minor % 100)
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

/// Can a Kubernetes `NetworkPolicy` hold a pod to this egress entry?
///
/// Only if it names something in the cluster. `NetworkPolicy` matches
/// CIDRs and selectors; it has no hostname, and there is no plan for
/// one. `postgres.payments.svc` maps onto a namespaceSelector and the
/// cluster really does stop the rest. `api.stripe.com:443` maps onto
/// nothing narrower than "anywhere, on 443" (#17).
///
/// Conservative on purpose: anything this cannot recognise as
/// in-cluster is treated as external, because the failure of guessing
/// wrong in that direction is a warning nobody needed, and in the other
/// direction it is a grant that claims enforcement it does not have.
fn is_in_cluster(host: &str) -> bool {
    let name = host.split(':').next().unwrap_or(host).trim_end_matches('.');
    if name.is_empty() {
        return false;
    }
    // A bare service name, or one of Kubernetes' own suffixes.
    !name.contains('.')
        || name.ends_with(".svc")
        || name.ends_with(".svc.cluster.local")
        || name.ends_with(".cluster.local")
}

/// Grants this cluster can check but cannot hold a pod to (#17).
///
/// Kept apart from [`unchecked_dimensions`] deliberately, and the
/// distinction is the whole point. An unchecked dimension is a *waiver
/// the manifest granted*: the author could have declared the policy and
/// chose not to, so making it turn on the submitter's standing is fair.
/// This is not that. No manifest can make `NetworkPolicy` understand a
/// hostname, so a team that declared everything correctly and simply
/// needs Stripe can do nothing to clear it. Refusing them for it would
/// punish a submitter for a limit of the substrate.
///
/// So it is disclosed on every decision and refuses nobody by default.
/// A deployment that would rather fail closed can say so
/// (`--refuse-unenforceable-egress`), which is the shape
/// `isolationFloor` already uses: this repo refuses what it cannot back,
/// once the operator has said that is what they want.
fn unenforceable_egress(facet: &PodFacet) -> Vec<String> {
    facet
        .egress
        .iter()
        .filter(|h| !is_in_cluster(h))
        .map(|h| {
            format!(
                "`{h}` is outside the cluster: NetworkPolicy has no hostname, so this pod \
                 can be held to a port but not to that host"
            )
        })
        .collect()
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
        let d = admit(GOOD, &manifest(), &snapshot(), &meta(), None, None).unwrap();
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
        let d = admit(GOOD, &manifest(), &open, &meta(), None, None).unwrap();
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
        let d = admit(spec, &manifest(), &snapshot(), &meta(), None, None).unwrap();

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
        let d = admit(spec, &manifest(), &snapshot(), &meta(), None, None).unwrap();

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

    // ── Egress the cluster cannot enforce (#17) ───────────────────

    #[test]
    fn in_cluster_names_are_enforceable() {
        for h in [
            "postgres",
            "postgres.payments.svc",
            "postgres.payments.svc.cluster.local",
            "postgres.payments.svc:5432",
        ] {
            assert!(is_in_cluster(h), "{h} maps onto a selector");
        }
    }

    #[test]
    fn external_hosts_are_not() {
        for h in [
            "api.stripe.com:443",
            "github.com",
            "1.2.3.4",
            "example.co.uk",
        ] {
            assert!(!is_in_cluster(h), "{h} has no NetworkPolicy expression");
        }
    }

    /// The disclosure, and the reason it is not a refusal: a grant
    /// naming an external host is still a perfectly good grant. The
    /// pod is admitted and the operator is told what the cluster can
    /// and cannot hold it to.
    #[test]
    fn an_external_grant_is_disclosed_but_admitted() {
        let spec = r#"{"containers":[{"name":"api",
            "image":"registry.internal/payments/api@sha256:aa"}]}"#;
        let d = admit(spec, &manifest(), &snapshot(), &meta(), None, None).unwrap();
        assert!(d.verdict.allowed(), "{:?}", d.verdict);
        assert!(
            d.unenforceable.iter().any(|u| u.contains("api.stripe.com")),
            "{:?}",
            d.unenforceable
        );
    }

    /// And it must not become the submitter's problem. `unchecked`
    /// drives the standing wall, so putting this there would refuse an
    /// unscored submitter for a limit of Kubernetes that no manifest
    /// they could write would clear.
    #[test]
    fn it_is_not_a_waiver_the_submitter_could_have_avoided() {
        let spec = r#"{"containers":[{"name":"api",
            "image":"registry.internal/payments/api@sha256:aa"}]}"#;
        let d = admit(spec, &manifest(), &snapshot(), &meta(), None, None).unwrap();
        assert!(
            !d.unchecked.iter().any(|u| u.contains("stripe")),
            "an unenforceable grant is not an undeclared one: {:?}",
            d.unchecked
        );
    }

    /// A manifest that only names in-cluster destinations promises
    /// nothing the cluster cannot deliver.
    #[test]
    fn an_in_cluster_only_grant_discloses_nothing() {
        let m = LexManifest::read(
            r#"{
              "metadata": { "name": "payments", "namespace": "payments" },
              "spec": {
                "goal": "serve the payments API",
                "grant": { "egress": ["postgres.payments.svc"], "secrets": [],
                           "capabilities": [] }
              }
            }"#,
        )
        .unwrap()
        .1;
        let spec = r#"{"containers":[{"name":"api",
            "image":"registry.internal/payments/api@sha256:aa"}]}"#;
        let d = admit(spec, &m, &snapshot(), &meta(), None, None).unwrap();
        assert!(d.unenforceable.is_empty(), "{:?}", d.unenforceable);
    }

    // ── Image provenance from the manifest (#19) ──────────────────
    //
    // The cluster snapshot says which registries it will accept at all.
    // The manifest says which of those *this workload* may use. Until
    // #19 only the first was consulted, because an image the snapshot
    // trusted emitted no row for the second to refuse — so narrowing
    // `imagePrefixes` changed nothing and nothing said so.

    /// The manifest narrows inside what the cluster already trusts.
    fn narrowed_to_payments() -> Manifest {
        LexManifest::read(
            r#"{
              "metadata": { "name": "payments", "namespace": "payments" },
              "spec": {
                "goal": "serve the payments API",
                "grant": {
                  "egress": ["postgres.payments.svc"],
                  "secrets": [],
                  "capabilities": [],
                  "imagePrefixes": ["registry.internal/payments/"]
                }
              }
            }"#,
        )
        .unwrap()
        .1
    }

    #[test]
    fn an_image_outside_the_manifests_prefixes_is_refused() {
        // The cluster trusts all of `registry.internal/`, so the snapshot
        // has no objection. The manifest is the only thing that can
        // refuse this, which is the whole point of the field.
        let spec = r#"{"containers":[{"name":"api",
            "image":"registry.internal/shared/base@sha256:aa"}]}"#;
        let d = admit(
            spec,
            &narrowed_to_payments(),
            &snapshot(),
            &meta(),
            None,
            None,
        )
        .unwrap();
        let Verdict::Deny { all, .. } = &d.verdict else {
            panic!("a manifest that names imagePrefixes must hold images to them");
        };
        let r = all
            .iter()
            .find(|r| r.effect.starts_with("image:"))
            .expect("the refusal names the image");
        assert!(r.reason.contains("imagePrefixes"), "{}", r.reason);
        assert!(
            r.grant_allows
                .iter()
                .any(|g| g == "registry.internal/payments/"),
            "the operator is told what is allowed: {:?}",
            r.grant_allows
        );
    }

    #[test]
    fn an_image_inside_the_manifests_prefixes_is_admitted() {
        let spec = r#"{"containers":[{"name":"api",
            "image":"registry.internal/payments/api@sha256:aa"}]}"#;
        let d = admit(
            spec,
            &narrowed_to_payments(),
            &snapshot(),
            &meta(),
            None,
            None,
        )
        .unwrap();
        assert!(d.verdict.allowed(), "{:?}", d.verdict);
    }

    /// Init containers run first and with the same reach; an image
    /// policy that only reads `containers[]` is not an image policy.
    #[test]
    fn an_init_containers_image_is_held_to_the_same_prefixes() {
        let spec = r#"{"containers":[{"name":"api",
            "image":"registry.internal/payments/api@sha256:aa"}],
            "initContainers":[{"name":"tuner","image":"registry.internal/ops@sha256:bb"}]}"#;
        let d = admit(
            spec,
            &narrowed_to_payments(),
            &snapshot(),
            &meta(),
            None,
            None,
        )
        .unwrap();
        assert!(!d.verdict.allowed(), "an init container is a container");
    }

    /// An empty list is "no policy declared", not "nothing permitted".
    /// Reading it as the latter would refuse every pod under a manifest
    /// that simply never mentioned images, and the waiver it actually
    /// implies is already reported as an unchecked dimension.
    #[test]
    fn a_manifest_naming_no_prefixes_does_not_refuse_on_images() {
        let spec = r#"{"containers":[{"name":"api",
            "image":"registry.internal/payments/api@sha256:aa"}]}"#;
        let d = admit(spec, &manifest(), &snapshot(), &meta(), None, None).unwrap();
        let refused_on_image = match &d.verdict {
            Verdict::Deny { all, .. } => all.iter().any(|r| r.effect.starts_with("image:")),
            _ => false,
        };
        assert!(!refused_on_image, "{:?}", d.verdict);
    }

    /// The manifest may only narrow. A prefix the cluster does not trust
    /// is not made trustworthy by a manifest naming it.
    #[test]
    fn a_manifest_cannot_widen_past_what_the_cluster_trusts() {
        let m = LexManifest::read(
            r#"{
              "metadata": { "name": "payments", "namespace": "payments" },
              "spec": {
                "goal": "serve the payments API",
                "grant": { "egress": [], "secrets": [], "capabilities": [],
                           "imagePrefixes": ["docker.io/"] }
              }
            }"#,
        )
        .unwrap()
        .1;
        let spec = r#"{"containers":[{"name":"api","image":"docker.io/library/nginx@sha256:aa"}]}"#;
        let d = admit(spec, &m, &snapshot(), &meta(), None, None).unwrap();
        assert!(
            !d.verdict.allowed(),
            "the cluster trusts only registry.internal/; a manifest cannot grant past it"
        );
    }

    /// The privileged init container from milestone 1: reading only
    /// `containers[0]` would admit this.
    #[test]
    fn a_privileged_init_container_is_refused() {
        let spec = r#"{"containers":[{"name":"api",
            "image":"registry.internal/payments/api@sha256:aa"}],
            "initContainers":[{"name":"tuner","image":"registry.internal/ops@sha256:bb",
              "securityContext":{"privileged":true}}]}"#;
        let d = admit(spec, &manifest(), &snapshot(), &meta(), None, None).unwrap();
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
        let d = admit(spec, &manifest(), &snapshot(), &meta(), None, None).unwrap();
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
        let d = admit(spec, &strict, &snapshot(), &meta(), None, None).unwrap();

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
            let err = admit(not_a_pod, &manifest(), &snapshot(), &meta(), None, None).unwrap_err();
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
