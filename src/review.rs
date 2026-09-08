//! The `AdmissionReview` wire format (alpibrusl/lex-k8s#3).
//!
//! What the API server POSTs to a validating webhook, and what it
//! expects back. Modelled here so the decision in [`crate::admission`]
//! can be driven from a real request without a server in the loop — the
//! CLI reads one on stdin, and a webhook binary would be a thin wrapper
//! around the same two functions.
//!
//! # The refusal is structured, not a sentence
//!
//! Kubernetes has a place for this and most webhooks do not use it:
//! `status.details.causes[]`, each with a `type`, a `message` and a
//! `field`. That maps exactly onto a [`Refusal`](crate::admission::Refusal)
//! — the wall, the reason, the field it came from — so `kubectl` shows
//! an operator the line of YAML to change, and an agent gets something
//! it can act on instead of a string to parse.
//!
//! `status.message` still carries a one-line summary, because that is
//! what most tooling prints.

use serde::{Deserialize, Serialize};

use crate::admission::{Decision, RequestMeta, Verdict};

/// What the API server sends.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdmissionReview {
    #[serde(default)]
    pub api_version: String,
    #[serde(default)]
    pub kind: String,
    /// Required on a request. Absent means this is not one — the same
    /// rule the pod and manifest readers apply.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request: Option<AdmissionRequest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response: Option<AdmissionResponse>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdmissionRequest {
    #[serde(default)]
    pub uid: String,
    #[serde(default)]
    pub namespace: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub operation: String,
    /// The object under review. For a pod admission this is the whole
    /// `Pod`, which [`crate::PodSpec::from_json`] already unwraps.
    #[serde(default)]
    pub object: serde_json::Value,
    /// Who submitted it.
    ///
    /// Unlike every other input to this wall, this one is not asserted
    /// by the caller: the API server authenticates the requester and
    /// fills it in. That is why lex-k8s takes no `--signer` flag where
    /// lex-iac needs one — a webhook that let its caller name the
    /// submitter would let any submitter borrow another's record.
    #[serde(default)]
    pub user_info: UserInfo,
}

/// The authenticated requester, as the API server reports it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserInfo {
    /// `system:serviceaccount:<namespace>:<name>` for a controller, or
    /// a user identity for a person.
    #[serde(default)]
    pub username: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdmissionResponse {
    pub uid: String,
    pub allowed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<Status>,
    /// Shown to the submitter on an *allowed* admission. Where the
    /// dimensions nobody declared a policy for are reported: an
    /// operator should not have to guess whether the wall looked.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status {
    pub code: u16,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<Details>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Details {
    #[serde(default)]
    pub causes: Vec<Cause>,
}

/// One machine-readable reason, in Kubernetes' own shape plus one
/// field of ours.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cause {
    /// The wall: `type-check` or `narrowing`.
    #[serde(rename = "reason")]
    pub reason: String,
    pub message: String,
    /// The field, as an operator would grep for it.
    pub field: String,
    /// What the manifest *does* grant in this dimension.
    ///
    /// A list rather than prose folded into `message`, because the
    /// point of a typed record is that an agent can read it. Kubernetes
    /// ignores fields it does not know, so this costs nothing on the
    /// wire and saves every consumer a regex.
    #[serde(default, rename = "grantAllows", skip_serializing_if = "Vec::is_empty")]
    pub grant_allows: Vec<String>,
}

/// Why a review could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReviewError {
    #[error("AdmissionReview is not valid JSON: {0}")]
    Json(String),
    #[error(
        "not an AdmissionReview request: no `request` field. This wall will not \
         answer a document it cannot read"
    )]
    NotARequest,
}

impl AdmissionReview {
    pub fn from_json(src: &str) -> Result<Self, ReviewError> {
        let raw: serde_json::Value =
            serde_json::from_str(src).map_err(|e| ReviewError::Json(e.to_string()))?;
        if raw.get("request").is_none() {
            return Err(ReviewError::NotARequest);
        }
        serde_json::from_value(raw).map_err(|e| ReviewError::Json(e.to_string()))
    }

    /// The request, or the error saying there wasn't one.
    pub fn request(&self) -> Result<&AdmissionRequest, ReviewError> {
        self.request.as_ref().ok_or(ReviewError::NotARequest)
    }
}

impl AdmissionRequest {
    pub fn meta(&self) -> RequestMeta {
        // On CREATE the name is often empty because `generateName` is
        // in use; the object still carries whichever was set, and a
        // record with no name in it is one nobody can trace back.
        let name = if self.name.is_empty() {
            self.object
                .pointer("/metadata/name")
                .or_else(|| self.object.pointer("/metadata/generateName"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string()
        } else {
            self.name.clone()
        };
        RequestMeta {
            uid: self.uid.clone(),
            namespace: self.namespace.clone(),
            name,
            // Absent rather than empty: a review with no `userInfo` is
            // one nobody authenticated, and an empty-string identity
            // would pool every such request under one "signer".
            signer: Some(self.user_info.username.clone()).filter(|u| !u.is_empty()),
        }
    }

    /// The object as JSON text, for the compiler.
    pub fn object_json(&self) -> String {
        self.object.to_string()
    }
}

/// Turn a decision into the response the API server expects.
pub fn respond(uid: &str, decision: &Decision) -> AdmissionReview {
    let response = match &decision.verdict {
        Verdict::Admit => AdmissionResponse {
            uid: uid.to_string(),
            allowed: true,
            status: None,
            // Reported on the way *in*, while there is still someone
            // reading. A dimension nobody declared a policy for is not
            // the same as one that passed.
            // Both go to `kubectl apply`'s own output. A grant the
            // cluster cannot enforce is exactly the kind of thing the
            // person deploying should be told at the moment they deploy,
            // rather than discovering in a README (#17).
            warnings: decision
                .unchecked
                .iter()
                .cloned()
                .chain(decision.unenforceable.iter().cloned())
                .collect(),
        },
        Verdict::Deny { first, all } => AdmissionResponse {
            uid: uid.to_string(),
            allowed: false,
            status: Some(Status {
                code: 403,
                message: format!(
                    "{} refused by the {} wall: {}",
                    first.effect,
                    first.wall.as_str(),
                    first.reason
                ),
                details: Some(Details {
                    causes: all
                        .iter()
                        .map(|r| Cause {
                            reason: r.wall.as_str().to_string(),
                            message: format!("{}: {}", r.effect, r.reason),
                            field: r.source.clone(),
                            grant_allows: r.grant_allows.clone(),
                        })
                        .collect(),
                }),
            }),
            warnings: Vec::new(),
        },
    };

    AdmissionReview {
        api_version: "admission.k8s.io/v1".to_string(),
        kind: "AdmissionReview".to_string(),
        request: None,
        response: Some(response),
    }
}

/// The response for a request this wall could not even read.
///
/// `allowed: false`, because with `failurePolicy: Fail` the API server
/// would reject it anyway and saying so plainly is better than letting
/// the connection error stand in for a decision. The message says the
/// wall could not run, not that the pod was refused — the distinction
/// lex-os draws between exit 2 and exit 8.
pub fn cannot_run(uid: &str, why: &str) -> AdmissionReview {
    AdmissionReview {
        api_version: "admission.k8s.io/v1".to_string(),
        kind: "AdmissionReview".to_string(),
        request: None,
        response: Some(AdmissionResponse {
            uid: uid.to_string(),
            allowed: false,
            status: Some(Status {
                code: 500,
                message: format!(
                    "the lex-k8s admission wall could not run, so it did not decide: {why}"
                ),
                details: None,
            }),
            warnings: Vec::new(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::admit;
    use crate::manifest::LexManifest;
    use crate::{ClusterSnapshot, EgressPolicy};

    const REVIEW: &str = r#"{
      "apiVersion": "admission.k8s.io/v1",
      "kind": "AdmissionReview",
      "request": {
        "uid": "705ab4f5-6393-11e8-b7cc-42010a800002",
        "kind": { "group": "", "version": "v1", "kind": "Pod" },
        "resource": { "group": "", "version": "v1", "resource": "pods" },
        "namespace": "payments",
        "name": "",
        "operation": "CREATE",
        "userInfo": { "username": "system:serviceaccount:payments:deployer" },
        "object": {
          "apiVersion": "v1", "kind": "Pod",
          "metadata": { "generateName": "api-7d9f-", "namespace": "payments" },
          "spec": { "containers": [{ "name": "api",
            "image": "registry.internal/payments/api@sha256:aa",
            "env": [{ "name": "K", "valueFrom": {
              "secretKeyRef": { "name": "root-ca-key", "key": "k" } } }] }] }
        }
      }
    }"#;

    fn manifest() -> lex_os_manifest::Manifest {
        LexManifest::read(
            r#"{"spec":{"grant":{"egress":["postgres.payments.svc"],
                "secrets":["stripe-live-key"]}}}"#,
        )
        .unwrap()
        .1
    }

    fn snapshot() -> ClusterSnapshot {
        ClusterSnapshot {
            egress: Some(EgressPolicy {
                policy_names: vec!["payments-egress".into()],
                cidrs: vec!["10.42.0.0/16".into()],
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn a_real_review_reads_and_the_name_survives_generate_name() {
        let review = AdmissionReview::from_json(REVIEW).unwrap();
        let req = review.request().unwrap();
        assert_eq!(req.operation, "CREATE");
        let meta = req.meta();
        assert_eq!(meta.namespace, "payments");
        assert_eq!(
            meta.name, "api-7d9f-",
            "an unnamed pod is still traceable through generateName"
        );
    }

    /// The refusal reaches `kubectl` as structured causes, each naming
    /// the field to change.
    #[test]
    fn a_refusal_is_returned_as_kubernetes_shaped_causes() {
        let review = AdmissionReview::from_json(REVIEW).unwrap();
        let req = review.request().unwrap();
        let d = admit(
            &req.object_json(),
            &manifest(),
            &snapshot(),
            &req.meta(),
            None,
            None,
        )
        .unwrap();
        assert!(!d.verdict.allowed());

        let out = respond(&req.uid, &d);
        let resp = out.response.unwrap();
        assert_eq!(
            resp.uid, req.uid,
            "the uid must echo, or the API server drops it"
        );
        assert!(!resp.allowed);

        let status = resp.status.unwrap();
        assert_eq!(status.code, 403);
        assert!(status.message.contains("root-ca-key"));

        let causes = status.details.unwrap().causes;
        assert_eq!(causes.len(), 1);
        assert_eq!(causes[0].reason, "narrowing");
        assert!(causes[0].field.contains("containers[api]"));
        assert_eq!(
            causes[0].grant_allows,
            ["stripe-live-key"],
            "what the manifest does grant, as data rather than prose"
        );
    }

    #[test]
    fn an_admission_carries_the_dimensions_nobody_declared_a_policy_for() {
        let review =
            AdmissionReview::from_json(&REVIEW.replace("root-ca-key", "stripe-live-key")).unwrap();
        let req = review.request().unwrap();
        let d = admit(
            &req.object_json(),
            &manifest(),
            &snapshot(),
            &req.meta(),
            None,
            None,
        )
        .unwrap();
        assert!(d.verdict.allowed(), "{:?}", d.verdict);

        let resp = respond(&req.uid, &d).response.unwrap();
        assert!(resp.allowed);
        assert!(
            resp.warnings.iter().any(|w| w.contains("image provenance")),
            "an admitted pod still says what was not checked: {:?}",
            resp.warnings
        );
    }

    /// Could-not-run is not refused, and says so.
    #[test]
    fn a_wall_that_cannot_run_says_that_rather_than_deciding() {
        let out = cannot_run("uid-1", "the manifest's `pod` facet does not parse");
        let resp = out.response.unwrap();
        assert!(!resp.allowed, "failurePolicy: Fail would reject it anyway");
        let status = resp.status.unwrap();
        assert_eq!(status.code, 500, "not 403 — this is not a decision");
        assert!(status.message.contains("could not run"));
        assert!(status.details.is_none());
    }

    #[test]
    fn a_document_that_is_not_a_request_is_refused_to_be_read() {
        for bad in [r#"{}"#, r#"[]"#, r#"{"response":{}}"#, "not json"] {
            assert!(AdmissionReview::from_json(bad).is_err(), "{bad}");
        }
    }
}
