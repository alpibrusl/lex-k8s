//! The slice of a Kubernetes `PodSpec` this wall reads.
//!
//! An admission review carries the whole object — labels, annotations,
//! probes, resource requests, scheduling hints. Almost none of that is
//! authority. What decides what a pod can *reach* is a short list of
//! fields, so that is all this models.
//!
//! # Tolerant of shape, never of absence
//!
//! Unknown fields are ignored: this is a wall over an evolving API, and
//! refusing to parse a spec is not the same as refusing to admit it.
//! But tolerance stops at the fields that carry authority. A pod with
//! no `containers` is not a pod that runs nothing — it is a document
//! this wall cannot vouch for, and [`PodSpec::from_json`] says so.
//!
//! That distinction is not theoretical. In lex-iac the same defaulting
//! meant a truncated `terraform show -json` was approved with exit 0
//! (alpibrusl/lex-iac#8). The rule is the same here: **absent evidence
//! is not evidence of absence.**

use serde::{Deserialize, Serialize};

/// Why a spec could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SpecError {
    #[error("spec is not valid JSON: {0}")]
    Json(String),
    /// Valid JSON, but not a PodSpec: no `containers` at all. A pod
    /// must declare at least one, so a document without the field is
    /// truncated, from another resource kind, or not a pod — and this
    /// wall will not admit what it cannot read.
    #[error(
        "not a PodSpec: no `containers` field. Kubernetes requires at least one \
         container, so a document that omits it is truncated, a different resource \
         kind, or not a pod — this wall will not admit what it cannot read"
    )]
    NotAPodSpec,
}

/// Where a container sits in the pod's lifecycle.
///
/// Modelled explicitly rather than reading only `containers[0]`, which
/// is the cheapest large win in coverage: an init container running
/// privileged has already escaped by the time the app container starts,
/// and an ephemeral debug container is a live escalation path into a
/// pod that was admitted long ago.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ContainerKind {
    /// Runs to completion before the app containers start.
    Init,
    /// An init container with `restartPolicy: Always` — Kubernetes'
    /// native sidecar (1.29+). It runs alongside the app containers for
    /// the pod's whole life, so its authority is live authority.
    Sidecar,
    /// An ordinary `containers[]` entry.
    App,
    /// Injected into a running pod by `kubectl debug`. Never present in
    /// a create request; a wall that ignored them would miss the update
    /// that adds one.
    Ephemeral,
}

impl ContainerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ContainerKind::Init => "initContainers",
            ContainerKind::Sidecar => "initContainers(sidecar)",
            ContainerKind::App => "containers",
            ContainerKind::Ephemeral => "ephemeralContainers",
        }
    }
}

/// The pod, reduced to what carries authority.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PodSpec {
    #[serde(default)]
    pub host_network: bool,
    /// Kubernetes spells these `hostPID` and `hostIPC`, which
    /// `rename_all = "camelCase"` would render `hostPid` and `hostIpc`
    /// — so they are named explicitly. Getting this wrong is silent:
    /// the field simply never matches, and every pod sharing the node's
    /// PID namespace reads as if it did not.
    #[serde(default, rename = "hostPID")]
    pub host_pid: bool,
    #[serde(default, rename = "hostIPC")]
    pub host_ipc: bool,
    /// The identity the pod's API requests carry. Empty means
    /// `default`, which is a real ServiceAccount with real bindings —
    /// not an absence of identity.
    #[serde(default)]
    pub service_account_name: String,
    #[serde(default)]
    pub volumes: Vec<Volume>,
    #[serde(default)]
    pub security_context: PodSecurityContext,
    /// Required. See [`SpecError::NotAPodSpec`].
    pub containers: Vec<Container>,
    #[serde(default)]
    pub init_containers: Vec<Container>,
    #[serde(default)]
    pub ephemeral_containers: Vec<Container>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PodSecurityContext {
    #[serde(default)]
    pub run_as_user: Option<i64>,
    #[serde(default)]
    pub run_as_non_root: Option<bool>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Container {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub image: String,
    /// `Always` on an init container makes it a sidecar (k8s 1.29+).
    #[serde(default)]
    pub restart_policy: Option<String>,
    #[serde(default)]
    pub security_context: SecurityContext,
    #[serde(default)]
    pub volume_mounts: Vec<VolumeMount>,
    #[serde(default)]
    pub env: Vec<EnvVar>,
    #[serde(default)]
    pub env_from: Vec<EnvFromSource>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityContext {
    #[serde(default)]
    pub privileged: Option<bool>,
    #[serde(default)]
    pub allow_privilege_escalation: Option<bool>,
    #[serde(default)]
    pub read_only_root_filesystem: Option<bool>,
    #[serde(default)]
    pub run_as_user: Option<i64>,
    #[serde(default)]
    pub capabilities: Capabilities,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capabilities {
    #[serde(default)]
    pub add: Vec<String>,
    #[serde(default)]
    pub drop: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Volume {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub host_path: Option<HostPathVolume>,
    #[serde(default)]
    pub secret: Option<SecretVolume>,
    #[serde(default)]
    pub projected: Option<ProjectedVolume>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostPathVolume {
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub r#type: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretVolume {
    #[serde(default)]
    pub secret_name: String,
}

/// A projected volume can carry secrets too, and a wall that only read
/// `volume.secret` would miss every one of them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectedVolume {
    #[serde(default)]
    pub sources: Vec<ProjectedSource>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectedSource {
    #[serde(default)]
    pub secret: Option<SecretVolume>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VolumeMount {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub mount_path: String,
    /// Kubernetes defaults this to `false`, i.e. **writable**. Modelled
    /// as `Option` so "the spec did not say" is distinguishable from
    /// "the spec said false" in the compiler, even though both end up
    /// writable — the difference matters when reporting *why*.
    #[serde(default)]
    pub read_only: Option<bool>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvVar {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub value_from: Option<EnvVarSource>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvVarSource {
    #[serde(default)]
    pub secret_key_ref: Option<SecretKeySelector>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretKeySelector {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub key: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvFromSource {
    #[serde(default)]
    pub secret_ref: Option<SecretEnvSource>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretEnvSource {
    #[serde(default)]
    pub name: String,
}

impl PodSpec {
    /// Parse a `PodSpec`.
    ///
    /// Accepts either a bare spec or a whole `Pod` object, since an
    /// admission review carries the latter and an operator reaching for
    /// this on the command line will have whichever `kubectl get` gave
    /// them. Unwrapping here beats making every caller remember.
    ///
    /// The `containers` membership test runs before deserialising, so
    /// the refusal speaks the caller's vocabulary rather than serde's,
    /// and so a top-level JSON array — which serde would otherwise read
    /// as a struct with every field defaulted — lands there too.
    pub fn from_json(src: &str) -> Result<Self, SpecError> {
        let raw: serde_json::Value =
            serde_json::from_str(src).map_err(|e| SpecError::Json(e.to_string()))?;
        // A whole Pod nests the spec; a bare spec does not.
        let spec = raw.get("spec").unwrap_or(&raw);
        if spec.get("containers").is_none() {
            return Err(SpecError::NotAPodSpec);
        }
        serde_json::from_value(spec.clone()).map_err(|e| SpecError::Json(e.to_string()))
    }

    /// Every container, tagged with the role it plays.
    ///
    /// Order is init → sidecar → app → ephemeral, which is the order
    /// they gain authority in, so a refusal naming the first row names
    /// the earliest escape.
    pub fn all_containers(&self) -> Vec<(ContainerKind, &Container)> {
        let mut out = Vec::new();
        for c in &self.init_containers {
            // `restartPolicy: Always` on an init container is the
            // native sidecar. It outlives initialisation, so its
            // authority is live rather than momentary.
            let kind = match c.restart_policy.as_deref() {
                Some("Always") => ContainerKind::Sidecar,
                _ => ContainerKind::Init,
            };
            out.push((kind, c));
        }
        out.extend(self.containers.iter().map(|c| (ContainerKind::App, c)));
        out.extend(
            self.ephemeral_containers
                .iter()
                .map(|c| (ContainerKind::Ephemeral, c)),
        );
        out
    }

    /// Look up a volume by the name a mount refers to.
    pub fn volume(&self, name: &str) -> Option<&Volume> {
        self.volumes.iter().find(|v| v.name == name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_whole_pod_object_and_a_bare_spec_both_parse() {
        let bare = r#"{"containers":[{"name":"app","image":"nginx:1.27"}]}"#;
        let whole = r#"{"apiVersion":"v1","kind":"Pod","metadata":{"name":"x"},
                        "spec":{"containers":[{"name":"app","image":"nginx:1.27"}]}}"#;
        assert_eq!(
            PodSpec::from_json(bare).unwrap(),
            PodSpec::from_json(whole).unwrap()
        );
    }

    /// The lex-iac#8 lesson, applied before it can bite here: a
    /// document that omits the field carrying authority is not a
    /// document with no authority in it.
    #[test]
    fn a_document_without_containers_is_not_a_pod_spec() {
        for not_a_pod in [
            r#"{}"#,
            r#"[]"#,
            r#"{"apiVersion":"v1","kind":"Pod","metadata":{"name":"x"}}"#,
            r#"{"apiVersion":"v1","kind":"ConfigMap","data":{"a":"b"}}"#,
        ] {
            assert_eq!(
                PodSpec::from_json(not_a_pod),
                Err(SpecError::NotAPodSpec),
                "{not_a_pod} must not read as a pod with nothing in it"
            );
        }

        // An *explicitly* empty list is a real answer, even though
        // Kubernetes would reject it: the field is present, so the wall
        // can say "this declares no containers" rather than "I could
        // not tell".
        assert!(PodSpec::from_json(r#"{"containers":[]}"#).is_ok());
    }

    /// Every authority-bearing field has to actually deserialise, and
    /// a field that silently never matches is worse than one that
    /// errors. `initContainers` did exactly that until `PodSpec` grew
    /// its `rename_all`, and `hostPID`/`hostIPC` still would under it.
    #[test]
    fn every_authority_field_is_actually_read() {
        let p = PodSpec::from_json(
            r#"{"hostNetwork":true,"hostPID":true,"hostIPC":true,
                "serviceAccountName":"ci",
                "containers":[{"name":"app","image":"nginx",
                  "securityContext":{"allowPrivilegeEscalation":true,
                    "readOnlyRootFilesystem":false,
                    "capabilities":{"add":["NET_ADMIN"]}},
                  "volumeMounts":[{"name":"h","mountPath":"/h","readOnly":true}],
                  "envFrom":[{"secretRef":{"name":"bulk"}}]}],
                "initContainers":[{"name":"setup","image":"busybox"}],
                "ephemeralContainers":[{"name":"dbg","image":"busybox"}],
                "volumes":[{"name":"h","hostPath":{"path":"/var","type":"Directory"}}],
                "securityContext":{"runAsNonRoot":true}}"#,
        )
        .unwrap();

        assert!(p.host_network, "hostNetwork");
        assert!(p.host_pid, "hostPID — camelCase would spell this hostPid");
        assert!(p.host_ipc, "hostIPC — likewise");
        assert_eq!(p.service_account_name, "ci");
        assert_eq!(p.init_containers.len(), 1, "initContainers");
        assert_eq!(p.ephemeral_containers.len(), 1, "ephemeralContainers");
        assert_eq!(p.volumes[0].host_path.as_ref().unwrap().path, "/var");
        assert_eq!(p.security_context.run_as_non_root, Some(true));

        let c = &p.containers[0];
        assert_eq!(c.security_context.allow_privilege_escalation, Some(true));
        assert_eq!(c.security_context.capabilities.add, ["NET_ADMIN"]);
        assert_eq!(c.volume_mounts[0].read_only, Some(true));
        assert_eq!(c.env_from[0].secret_ref.as_ref().unwrap().name, "bulk");
    }

    #[test]
    fn unknown_fields_are_ignored_not_rejected() {
        let p = PodSpec::from_json(
            r#"{"containers":[{"name":"app","image":"nginx","someFutureField":{"a":1}}],
                "schedulerName":"custom","someOtherFutureField":[1,2,3]}"#,
        )
        .unwrap();
        assert_eq!(p.containers.len(), 1);
    }

    #[test]
    fn a_sidecar_is_an_init_container_that_never_stops() {
        let p = PodSpec::from_json(
            r#"{"containers":[{"name":"app","image":"nginx"}],
                "initContainers":[
                  {"name":"setup","image":"busybox"},
                  {"name":"proxy","image":"envoy","restartPolicy":"Always"}
                ],
                "ephemeralContainers":[{"name":"debug","image":"busybox"}]}"#,
        )
        .unwrap();

        let kinds: Vec<_> = p
            .all_containers()
            .iter()
            .map(|(k, c)| (*k, c.name.clone()))
            .collect();
        assert_eq!(
            kinds,
            vec![
                (ContainerKind::Init, "setup".to_string()),
                (ContainerKind::Sidecar, "proxy".to_string()),
                (ContainerKind::App, "app".to_string()),
                (ContainerKind::Ephemeral, "debug".to_string()),
            ],
            "every container contributes authority, in the order it gains it"
        );
    }

    #[test]
    fn malformed_input_never_panics() {
        for case in [
            "",
            "{",
            "null",
            "3",
            r#""a string""#,
            r#"{"containers":null}"#,
            r#"{"containers":"not a list"}"#,
            r#"{"containers":[{}]}"#,
            r#"{"containers":[{"securityContext":{"capabilities":{"add":null}}}]}"#,
            r#"{"spec":{"spec":{"containers":[]}}}"#,
        ] {
            let _ = PodSpec::from_json(case);
        }
    }
}
