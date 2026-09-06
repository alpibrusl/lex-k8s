//! The `LexManifest` CRD, and the manifest it resolves to
//! (alpibrusl/lex-k8s#3).
//!
//! ```yaml
//! apiVersion: lex.dev/v1alpha1
//! kind: LexManifest
//! metadata: { name: payments, namespace: payments }
//! spec:
//!   goal: "serve the payments API"
//!   grant:
//!     egress: ["postgres.payments.svc", "api.stripe.com:443"]
//!     secrets: ["stripe-live-key"]
//!     capabilities: ["NET_BIND_SERVICE"]
//!     hostPath: false
//!     privileged: false
//!     exec: Sandboxed
//!   isolationFloor: microvm
//!   parent: cluster/platform-default
//! ```
//!
//! # It resolves to `lex_os_manifest::Manifest`
//!
//! Not to a type of this crate's own. lex-iac learned that the
//! expensive way: a parallel manifest is a second content-addressing
//! scheme and a second narrowing implementation, and the two drift.
//! The CRD is a *serialisation* — a shape Kubernetes can validate and
//! an operator can read — and [`LexManifest::resolve`] turns it into
//! the one `Manifest` everything else in the Lex project already
//! understands, with [`PodFacet`] in the facet slot lex-os#71 opened.
//!
//! # `parent` is the wall Gatekeeper structurally lacks
//!
//! A `LexManifest` naming a parent is checked against it at admission:
//! a team lead hands out authority they hold, never authority they do
//! not. A constraint language can only enumerate what is forbidden; it
//! has nowhere to put "and this policy is itself bounded by that one".

use lex_os_manifest::{
    facet::FacetRegistry, Budget, Goal, IsolationFloor, Level, Manifest, ManifestError,
};
use serde::{Deserialize, Serialize};

use crate::facet::PodFacet;

/// The custom resource, as it appears on the API server.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LexManifest {
    #[serde(default)]
    pub api_version: String,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub metadata: Metadata,
    pub spec: Spec,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Metadata {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub namespace: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Spec {
    #[serde(default)]
    pub goal: String,
    #[serde(default)]
    pub grant: PodFacet,
    /// The lattice level pods may reach on the `exec` axis before any
    /// capability or privilege raises it. `Sandboxed` is the sane
    /// floor: a container runs processes.
    #[serde(default)]
    pub exec: Option<String>,
    #[serde(default)]
    pub budget: Option<Budget>,
    /// Declared, and **not enforced by this repo** — see
    /// [`Spec::isolation_floor_is_unenforced`].
    #[serde(default)]
    pub isolation_floor: Option<String>,
    /// `<namespace>/<name>`, or `cluster/<name>` for a cluster-scoped
    /// parent. The manifest this one must narrow.
    #[serde(default)]
    pub parent: Option<String>,
}

/// Why a `LexManifest` could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ManifestReadError {
    #[error("LexManifest is not valid JSON: {0}")]
    Json(String),
    /// Valid JSON, but not a `LexManifest`: no `spec`. Same rule as the
    /// pod reader — absence is not an empty grant.
    #[error(
        "not a LexManifest: no `spec` field. A manifest granting nothing says \
         `spec: {{grant: {{}}}}`; a document that omits it is truncated or a \
         different kind, and this wall will not admit what it cannot read"
    )]
    NotAManifest,
    /// An `isolationFloor` this deployment cannot satisfy. Refusing is
    /// the point: see [`Spec::isolation_floor_is_unenforced`].
    #[error(
        "isolationFloor `{declared}` is not enforceable: this repo is the admission \
         wall only, and the RuntimeClass that would back a floor is deliberately \
         not here (alpibrusl/lex-k8s#1). Remove the field, or accept it explicitly \
         with `unenforced-{declared}`"
    )]
    UnenforceableFloor { declared: String },
}

impl LexManifest {
    pub fn from_json(src: &str) -> Result<Self, ManifestReadError> {
        let raw: serde_json::Value =
            serde_json::from_str(src).map_err(|e| ManifestReadError::Json(e.to_string()))?;
        if raw.get("spec").is_none() {
            return Err(ManifestReadError::NotAManifest);
        }
        serde_json::from_value(raw).map_err(|e| ManifestReadError::Json(e.to_string()))
    }

    /// `<namespace>/<name>` — how a `parent` reference names this one.
    pub fn reference(&self) -> String {
        let ns = if self.metadata.namespace.is_empty() {
            "cluster"
        } else {
            &self.metadata.namespace
        };
        format!("{}/{}", ns, self.metadata.name)
    }

    /// Turn the CRD into the manifest everything else understands.
    ///
    /// The lattice ceiling is *derived* from the grant rather than
    /// restated beside it — see [`PodFacet::implied_grant`]. An
    /// operator writes what pods may do; the `Grant` follows.
    pub fn resolve(&self) -> Result<Manifest, ManifestError> {
        if let Some(floor) = &self.spec.isolation_floor {
            if self.spec.isolation_floor_is_unenforced() {
                // Surfaced as an error by `read`, not here: `resolve`
                // is infallible on floors so a caller that has already
                // accepted the consequence can proceed.
                let _ = floor;
            }
        }
        let exec = parse_level(self.spec.exec.as_deref()).unwrap_or(Level::Sandboxed);
        let grant = self.spec.grant.implied_grant(exec);

        let mut manifest = Manifest::new(
            Goal::new(&self.spec.goal),
            grant,
            self.spec.budget.unwrap_or_else(Budget::research_default),
        )
        .with_facet(&self.spec.grant)?;

        // The egress allow-list is also lex-os's own, so a downstream
        // consumer of this manifest sees the hosts without knowing what
        // a `pod` facet is.
        manifest = manifest.with_egress(self.spec.grant.egress.clone());
        manifest.isolation_floor = parse_floor(self.spec.isolation_floor.as_deref())
            .unwrap_or(IsolationFloor::implied_by(&manifest.grant));
        Ok(manifest)
    }

    /// Read and resolve, refusing a floor this deployment cannot back.
    pub fn read(src: &str) -> Result<(Self, Manifest), ManifestReadError> {
        let crd = LexManifest::from_json(src)?;
        if crd.spec.isolation_floor_is_unenforced() {
            return Err(ManifestReadError::UnenforceableFloor {
                declared: crd.spec.isolation_floor.clone().unwrap_or_default(),
            });
        }
        let manifest = crd
            .resolve()
            .map_err(|e| ManifestReadError::Json(e.to_string()))?;
        Ok((crd, manifest))
    }
}

impl Spec {
    /// Does this spec declare an isolation floor nothing here can
    /// enforce?
    ///
    /// The RuntimeClass that would back a floor is deliberately not in
    /// this repo (#1), so a manifest asking for `microvm` is asking for
    /// something no code here provides. Accepting it silently would be
    /// the worst option: an operator would believe a boundary exists.
    ///
    /// So it is refused — unless spelled `unenforced-microvm`, which is
    /// the operator saying they know. Refuse, don't downgrade, with a
    /// way to say yes on purpose.
    pub fn isolation_floor_is_unenforced(&self) -> bool {
        match self.isolation_floor.as_deref() {
            None => false,
            Some(f) => !f.starts_with("unenforced-"),
        }
    }
}

fn parse_level(s: Option<&str>) -> Option<Level> {
    match s?.to_ascii_lowercase().as_str() {
        "none" => Some(Level::None),
        "readonly" | "read-only" => Some(Level::ReadOnly),
        "sandboxed" => Some(Level::Sandboxed),
        "loopback" => Some(Level::Loopback),
        "readwrite" | "read-write" => Some(Level::ReadWrite),
        "allowlist" => Some(Level::Allowlist),
        "full" => Some(Level::Full),
        _ => None,
    }
}

fn parse_floor(s: Option<&str>) -> Option<IsolationFloor> {
    let s = s?.trim_start_matches("unenforced-").to_ascii_lowercase();
    match s.as_str() {
        "namespace" => Some(IsolationFloor::Namespace),
        "gvisor" => Some(IsolationFloor::Gvisor),
        "microvm" => Some(IsolationFloor::MicroVm),
        _ => None,
    }
}

/// The facets this wall knows how to narrow.
pub fn registry() -> FacetRegistry {
    FacetRegistry::new().with::<PodFacet>()
}

/// Is `child` a well-formed narrowing of `parent`?
///
/// Every wall is lex-os's — trust lattice, budget, egress, actuation —
/// plus the `pod` facet through [`registry`]. This crate contributes a
/// domain, not a second opinion about what narrowing means.
pub fn narrow(parent: &Manifest, child: &Manifest) -> Result<(), ManifestError> {
    Manifest::validate_narrowing_with(parent, child, &registry())
}

/// The `pod` facet a manifest carries, or an empty one.
///
/// Absent grants nothing — which is why the empty facet is the right
/// answer rather than an error. A facet that is *present and
/// unreadable* is a different thing, and `Manifest::facet` returns it
/// as `FacetUnreadable` (lex-os#73).
pub fn pod_facet(m: &Manifest) -> Result<PodFacet, ManifestError> {
    m.facet::<PodFacet>()
        .unwrap_or_else(|| Ok(PodFacet::default()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAYMENTS: &str = r#"{
      "apiVersion": "lex.dev/v1alpha1",
      "kind": "LexManifest",
      "metadata": { "name": "payments", "namespace": "payments" },
      "spec": {
        "goal": "serve the payments API",
        "grant": {
          "egress": ["postgres.payments.svc", "api.stripe.com:443"],
          "secrets": ["stripe-live-key"],
          "capabilities": ["NET_BIND_SERVICE"],
          "hostPath": false,
          "privileged": false
        },
        "parent": "cluster/platform-default"
      }
    }"#;

    #[test]
    fn the_crd_resolves_to_a_lex_os_manifest() {
        let (crd, m) = LexManifest::read(PAYMENTS).unwrap();
        assert_eq!(crd.reference(), "payments/payments");
        assert_eq!(crd.spec.parent.as_deref(), Some("cluster/platform-default"));

        // The lattice ceiling is derived, not restated.
        assert_eq!(m.grant.filesystem, Level::ReadOnly, "one Secret");
        assert_eq!(m.grant.network, Level::Allowlist, "two named hosts");
        assert_eq!(m.grant.exec, Level::Sandboxed);

        // The facet is on the manifest, and folds into its identity.
        assert!(m.has_facet("pod"));
        assert_eq!(pod_facet(&m).unwrap().secrets, ["stripe-live-key"]);
        assert_eq!(m.egress, ["postgres.payments.svc", "api.stripe.com:443"]);
    }

    /// The lex-iac#8 rule, third time: absence is not an empty grant.
    #[test]
    fn a_document_without_a_spec_is_not_a_manifest() {
        for not_a_manifest in [
            r#"{}"#,
            r#"[]"#,
            r#"{"apiVersion":"lex.dev/v1alpha1","kind":"LexManifest","metadata":{}}"#,
            r#"{"kind":"ConfigMap","data":{}}"#,
        ] {
            assert_eq!(
                LexManifest::from_json(not_a_manifest),
                Err(ManifestReadError::NotAManifest),
                "{not_a_manifest}"
            );
        }
        // An explicitly empty grant is a real answer: it grants nothing.
        let (_, m) = LexManifest::read(r#"{"spec":{"grant":{}}}"#).unwrap();
        assert_eq!(m.grant.network, Level::None);
        assert!(pod_facet(&m).unwrap().secrets.is_empty());
    }

    /// A floor nothing here can enforce is refused rather than accepted
    /// silently — an operator must not come away believing a boundary
    /// exists.
    #[test]
    fn an_unenforceable_isolation_floor_is_refused() {
        let asking = r#"{"spec":{"grant":{},"isolationFloor":"microvm"}}"#;
        assert!(matches!(
            LexManifest::read(asking),
            Err(ManifestReadError::UnenforceableFloor { .. })
        ));

        // ...and there is a way to say yes on purpose.
        let knowing = r#"{"spec":{"grant":{},"isolationFloor":"unenforced-microvm"}}"#;
        let (_, m) = LexManifest::read(knowing).unwrap();
        assert_eq!(m.isolation_floor, IsolationFloor::MicroVm);
    }

    /// The wall on manifests themselves. A namespace lead cannot mint
    /// authority the platform never gave them.
    #[test]
    fn a_child_manifest_that_widens_its_parent_is_refused() {
        let (_, parent) = LexManifest::read(PAYMENTS).unwrap();

        let tighter = r#"{"spec":{"grant":{
            "egress":["postgres.payments.svc"], "secrets":["stripe-live-key"]}}}"#;
        let (_, child) = LexManifest::read(tighter).unwrap();
        assert!(narrow(&parent, &child).is_ok());

        let mints = r#"{"spec":{"grant":{
            "egress":["postgres.payments.svc","exfil.example.com:443"],
            "secrets":["stripe-live-key"]}}}"#;
        let (_, widening) = LexManifest::read(mints).unwrap();
        let err = narrow(&parent, &widening).unwrap_err();
        assert!(
            err.to_string().contains("exfil.example.com:443"),
            "the refusal names the entry that widened: {err}"
        );
    }

    /// Widening the lattice is caught even when the facet would pass,
    /// because the ceiling is derived from the facet and `privileged`
    /// lifts it.
    #[test]
    fn claiming_privileged_widens_both_walls() {
        let (_, parent) = LexManifest::read(PAYMENTS).unwrap();
        let priv_child = r#"{"spec":{"grant":{
            "egress":["postgres.payments.svc"],"privileged":true}}}"#;
        let (_, child) = LexManifest::read(priv_child).unwrap();

        assert_eq!(child.grant.exec, Level::Full);
        assert!(narrow(&parent, &child).is_err());
    }
}
