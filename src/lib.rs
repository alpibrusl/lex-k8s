//! **lex-k8s** — a validating admission wall for Kubernetes.
//!
//! `lex-os-check` refuses a `.lex` program whose effects exceed the
//! manifest's grant, before it runs. This does the same for a pod: the
//! spec compiles to typed effect rows, each row carries the [`Grant`]
//! it demands, and their join is what the namespace's grant has to
//! cover.
//!
//! Milestone 1 (alpibrusl/lex-k8s#2) is that compiler and nothing else:
//! a pure function of a spec and a cluster snapshot. No API server, no
//! CRD, no webhook, no certificates.
//!
//! ```
//! use lex_k8s::{compile_str, ClusterSnapshot};
//! use lex_os_manifest::Level;
//!
//! // A pod that looks unremarkable, on a cluster with no NetworkPolicy.
//! let spec = r#"{"containers":[{"name":"app","image":"nginx@sha256:abc"}]}"#;
//! let pod = compile_str(spec, &ClusterSnapshot::default()).unwrap();
//!
//! // Kubernetes' default egress is open, so it is asking for the network.
//! assert_eq!(pod.demands.network, Level::Full);
//! ```

pub mod admission;
pub mod cluster;
pub mod cost;
pub mod effect;
pub mod facet;
pub mod manifest;
pub mod review;
pub mod spec;
pub mod trust;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub use admission::{
    admit, AdmissionError, AdmissionEvent, Decision, Refusal, RequestMeta, Verdict, Wall,
};
pub use cluster::{ClusterSnapshot, EgressPolicy, RbacRule};
pub use cost::{CostError, PodReservation, PriceList, Reservation, SpendReport, Undeclared};
pub use effect::{Effect, ImageDoubt, Reach, SecretVia, Source};
pub use facet::{Denial, PodFacet};
pub use lex_os_manifest::{Grant, Level, Reversibility};
pub use manifest::{narrow, pod_facet, LexManifest, ManifestReadError};
pub use review::{respond, AdmissionRequest, AdmissionReview, ReviewError};
pub use spec::{Container, ContainerKind, PodSpec, ResourceList, Resources, SpecError};
pub use trust::{Keyring, Standing, Submitter, TrustError};

/// One authority-bearing thing the pod declares.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectRow {
    pub effect: Effect,
    pub source: Source,
    pub demands: Grant,
    pub reversibility: Reversibility,
}

/// A compiled pod: the rows, their join, and the identity of what was
/// read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PodEffects {
    /// Hex SHA-256 of the exact spec JSON compiled. An admission is
    /// only ever an admission of *these* bytes.
    pub spec_sha256: String,
    /// Hex SHA-256 of the snapshot the verdict depended on. A decision
    /// you cannot reproduce is a decision you cannot audit.
    pub snapshot_sha256: String,
    pub rows: Vec<EffectRow>,
    /// The join of every row: the grant this pod needs.
    pub demands: Grant,
    /// What the pod asks the scheduler to reserve, by Kubernetes' own
    /// effective-request rule, plus any container that declared
    /// nothing. Computed here because it is a fact about the spec, the
    /// same as an effect row; what it *costs* needs a price list, which
    /// is the wall's business rather than the compiler's.
    pub reservation: PodReservation,
}

impl PodEffects {
    /// Rows at the given class.
    pub fn rows_at(&self, class: Reversibility) -> Vec<&EffectRow> {
        self.rows
            .iter()
            .filter(|r| r.reversibility == class)
            .collect()
    }

    /// Does anything here outlive the pod in a way eviction will not
    /// undo?
    pub fn has_consequential(&self) -> bool {
        self.rows
            .iter()
            .any(|r| r.reversibility == Reversibility::IrreversibleConsequential)
    }

    /// Rows this build could not read, and so read at their widest.
    pub fn unreadable(&self) -> Vec<&EffectRow> {
        self.rows
            .iter()
            .filter(|r| matches!(r.effect, Effect::Unreadable { .. }))
            .collect()
    }

    /// Is this pod inside `granted`?
    ///
    /// The whole wall, in one comparison — the same one `lex-os-check`
    /// makes against a `.lex` program's effects.
    pub fn within(&self, granted: &Grant) -> Result<(), lex_os_manifest::TrustError> {
        // `narrow` hands back the narrowed grant; the wall only needs
        // to know whether it narrowed at all.
        Grant::narrow(granted, &self.demands).map(|_| ())
    }
}

/// Compile a spec, given the cluster state its authority depends on.
///
/// Pure: no API server, no network, no filesystem. The only failure
/// mode is a document that is not a pod spec.
pub fn compile_str(src: &str, snapshot: &ClusterSnapshot) -> Result<PodEffects, SpecError> {
    let spec = PodSpec::from_json(src)?;
    compile(&spec, snapshot, src)
}

/// Compile an already-parsed spec, pinning `raw` as the identity of the
/// bytes. Prefer [`compile_str`] unless you parsed it yourself.
pub fn compile(
    spec: &PodSpec,
    snapshot: &ClusterSnapshot,
    raw: &str,
) -> Result<PodEffects, SpecError> {
    let mut rows: Vec<EffectRow> = Vec::new();
    let mut push = |effect: Effect, source: Source| {
        rows.push(EffectRow {
            demands: effect.demands(),
            reversibility: effect.reversibility(),
            effect,
            source,
        });
    };

    // --- pod-level namespaces -------------------------------------
    if spec.host_network {
        push(Effect::HostNetwork, Source::pod("hostNetwork"));
    }
    if spec.host_pid {
        push(
            Effect::HostNamespace {
                which: "PID".into(),
            },
            Source::pod("hostPID"),
        );
    }
    if spec.host_ipc {
        push(
            Effect::HostNamespace {
                which: "IPC".into(),
            },
            Source::pod("hostIPC"),
        );
    }

    // --- volumes ---------------------------------------------------
    //
    // A hostPath is authority whether or not anything mounts it: the
    // kubelet stages it for the pod either way, and a volume declared
    // now can be mounted by an ephemeral container later. Writability
    // comes from the mounts that reference it, defaulting to writable
    // when nothing says otherwise — which is Kubernetes' own default.
    for volume in &spec.volumes {
        if let Some(hp) = &volume.host_path {
            let writable = spec
                .all_containers()
                .iter()
                .flat_map(|(_, c)| c.volume_mounts.iter())
                .filter(|m| m.name == volume.name)
                .any(|m| m.read_only != Some(true));
            let mounted = spec
                .all_containers()
                .iter()
                .any(|(_, c)| c.volume_mounts.iter().any(|m| m.name == volume.name));
            push(
                Effect::HostPath {
                    path: hp.path.clone(),
                    // An unmounted hostPath is still staged, and is
                    // still writable unless a mount says otherwise.
                    writable: writable || !mounted,
                },
                Source::pod(format!("volumes[{}].hostPath", volume.name)),
            );
        }
        if let Some(s) = &volume.secret {
            push(
                Effect::Secret {
                    name: s.secret_name.clone(),
                    via: SecretVia::Volume,
                },
                Source::pod(format!("volumes[{}].secret", volume.name)),
            );
        }
        if let Some(p) = &volume.projected {
            for src in &p.sources {
                if let Some(s) = &src.secret {
                    push(
                        Effect::Secret {
                            name: s.secret_name.clone(),
                            via: SecretVia::Projected,
                        },
                        Source::pod(format!("volumes[{}].projected.secret", volume.name)),
                    );
                }
            }
        }
    }

    // --- per-container ---------------------------------------------
    for (kind, c) in spec.all_containers() {
        let name = if c.name.is_empty() { "?" } else { &c.name };
        let sc = &c.security_context;

        if sc.privileged == Some(true) {
            push(
                Effect::Privileged,
                Source::container(kind, name, "securityContext.privileged"),
            );
        }
        if sc.allow_privilege_escalation == Some(true) {
            push(
                Effect::PrivilegeEscalation,
                Source::container(kind, name, "securityContext.allowPrivilegeEscalation"),
            );
        }
        for cap in &sc.capabilities.add {
            push(
                Effect::Capability {
                    name: cap.clone(),
                    dangerous: effect::is_dangerous_capability(cap),
                },
                Source::container(kind, name, "securityContext.capabilities.add"),
            );
        }

        for e in &c.env {
            if let Some(from) = &e.value_from {
                if let Some(k) = &from.secret_key_ref {
                    push(
                        Effect::Secret {
                            name: k.name.clone(),
                            via: SecretVia::Env,
                        },
                        Source::container(kind, name, format!("env[{}].valueFrom", e.name)),
                    );
                }
            }
        }
        for f in &c.env_from {
            if let Some(s) = &f.secret_ref {
                push(
                    Effect::Secret {
                        name: s.name.clone(),
                        via: SecretVia::EnvFrom,
                    },
                    Source::container(kind, name, "envFrom.secretRef"),
                );
            }
        }

        if let Some(doubt) = image_doubt(&c.image, snapshot) {
            push(
                Effect::UntrustedImage {
                    image: c.image.clone(),
                    why: doubt,
                },
                Source::container(kind, name, "image"),
            );
        }
    }

    // --- egress ----------------------------------------------------
    //
    // `hostNetwork` already demands `network: full`, but the egress row
    // is emitted regardless: it says what the *cluster* permits, which
    // is a different fact from what the pod asked for, and milestone 2
    // needs both to report a mismatch.
    let (reach, policies) = match &snapshot.egress {
        None => (Reach::NoPolicy, Vec::new()),
        Some(p) if p.is_unrestricted() => (Reach::Unrestricted, p.policy_names.clone()),
        Some(p) if p.permits_nothing() => (Reach::None, p.policy_names.clone()),
        Some(p) => (Reach::Allowlist, p.policy_names.clone()),
    };
    push(Effect::Egress { reach, policies }, Source::pod("egress"));

    // --- RBAC ------------------------------------------------------
    for rule in &snapshot.rbac {
        push(
            Effect::ApiAccess {
                resource: rule.resource.clone(),
                verbs: rule.verbs.clone(),
                cluster_wide: rule.cluster_wide(),
                escalation: rule.escalation_path().map(str::to_string),
            },
            Source::pod(format!(
                "serviceAccountName={} via {}",
                if spec.service_account_name.is_empty() {
                    "default"
                } else {
                    &spec.service_account_name
                },
                if rule.binding.is_empty() {
                    "(binding)"
                } else {
                    &rule.binding
                }
            )),
        );
    }

    let demands = rows.iter().map(|r| r.demands).fold(
        Grant::new(Level::None, Level::None, Level::None),
        effect::join,
    );

    Ok(PodEffects {
        spec_sha256: sha256_hex(raw),
        snapshot_sha256: snapshot.content_id(),
        rows,
        demands,
        reservation: cost::effective_requests(&spec.all_containers())?,
    })
}

/// Is there reason to doubt this image is what it claims?
///
/// Three separable doubts, and the order matters: an unidentified image
/// is a worse problem than an unvouched-for one, so it is reported
/// first.
fn image_doubt(image: &str, snapshot: &ClusterSnapshot) -> Option<ImageDoubt> {
    let img = image.trim();
    if img.is_empty() {
        return Some(ImageDoubt::Floating);
    }
    // A digest pins the bytes. Everything else is a moving target.
    if !img.contains("@sha256:") {
        // Split off any registry port before looking for a tag, or
        // `registry:5000/app` reads as tag `5000/app`.
        let last = img.rsplit('/').next().unwrap_or(img);
        return match last.split_once(':') {
            None => Some(ImageDoubt::Floating),
            Some((_, tag)) if tag == "latest" || tag.is_empty() => Some(ImageDoubt::Floating),
            Some(_) => Some(ImageDoubt::NotPinned),
        };
    }
    if !snapshot.trusts_image(img) {
        return Some(ImageDoubt::UntrustedSource);
    }
    None
}

fn sha256_hex(src: &str) -> String {
    let mut h = Sha256::new();
    h.update(src.as_bytes());
    hex::encode(h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap_open() -> ClusterSnapshot {
        ClusterSnapshot {
            trusted_image_prefixes: vec!["registry.internal/".into()],
            ..Default::default()
        }
    }

    #[test]
    fn the_spec_hash_pins_the_exact_bytes() {
        let a = compile_str(r#"{"containers":[]}"#, &ClusterSnapshot::default()).unwrap();
        let b = compile_str(r#"{"containers":[] }"#, &ClusterSnapshot::default()).unwrap();
        assert_ne!(a.spec_sha256, b.spec_sha256);
    }

    /// The snapshot is part of the verdict, so it is part of the
    /// record. Same spec, different cluster, different decision.
    #[test]
    fn the_same_spec_on_two_clusters_records_two_snapshots() {
        let spec = r#"{"containers":[{"name":"a","image":"registry.internal/a@sha256:x"}]}"#;
        let open = compile_str(spec, &snap_open()).unwrap();
        let closed = compile_str(
            spec,
            &ClusterSnapshot {
                egress: Some(EgressPolicy {
                    deny_all: true,
                    policy_names: vec!["default-deny".into()],
                    ..Default::default()
                }),
                ..snap_open()
            },
        )
        .unwrap();

        assert_eq!(open.spec_sha256, closed.spec_sha256);
        assert_ne!(open.snapshot_sha256, closed.snapshot_sha256);
        assert_eq!(open.demands.network, Level::Full);
        assert_eq!(closed.demands.network, Level::None);
    }

    #[test]
    fn every_container_kind_contributes_authority() {
        let spec = r#"{
          "containers":[{"name":"app","image":"registry.internal/app@sha256:a"}],
          "initContainers":[
            {"name":"setup","image":"registry.internal/s@sha256:b",
             "securityContext":{"privileged":true}},
            {"name":"proxy","image":"registry.internal/p@sha256:c","restartPolicy":"Always",
             "securityContext":{"capabilities":{"add":["NET_ADMIN"]}}}
          ],
          "ephemeralContainers":[
            {"name":"debug","image":"registry.internal/d@sha256:e",
             "securityContext":{"capabilities":{"add":["SYS_PTRACE"]}}}
          ]
        }"#;
        let pod = compile_str(spec, &snap_open()).unwrap();

        let sources: Vec<String> = pod
            .rows
            .iter()
            .filter(|r| !matches!(r.effect, Effect::Egress { .. }))
            .map(|r| r.source.to_string())
            .collect();
        assert!(sources
            .iter()
            .any(|s| s.starts_with("initContainers[setup]")));
        assert!(sources
            .iter()
            .any(|s| s.starts_with("initContainers(sidecar)[proxy]")));
        assert!(sources
            .iter()
            .any(|s| s.starts_with("ephemeralContainers[debug]")));

        // The privileged init container is what decides the pod's exec
        // demand, even though the app container is unremarkable.
        assert_eq!(pod.demands.exec, Level::Full);
        assert_eq!(pod.demands.filesystem, Level::Full);
    }

    #[test]
    fn secrets_are_found_wherever_they_hide() {
        let spec = r#"{
          "volumes":[
            {"name":"v1","secret":{"secretName":"tls"}},
            {"name":"v2","projected":{"sources":[{"secret":{"secretName":"ca"}}]}}
          ],
          "containers":[{"name":"app","image":"registry.internal/a@sha256:x",
            "env":[{"name":"PW","valueFrom":{"secretKeyRef":{"name":"db","key":"pw"}}}],
            "envFrom":[{"secretRef":{"name":"bulk"}}]}]
        }"#;
        let pod = compile_str(spec, &snap_open()).unwrap();

        let mut found: Vec<String> = pod
            .rows
            .iter()
            .filter_map(|r| match &r.effect {
                Effect::Secret { name, .. } => Some(name.clone()),
                _ => None,
            })
            .collect();
        found.sort();
        assert_eq!(found, ["bulk", "ca", "db", "tls"]);
    }

    /// Kubernetes defaults a mount to writable. A wall that read the
    /// absent flag as read-only would understate every hostPath that
    /// did not spell it out.
    #[test]
    fn a_host_path_mount_is_writable_unless_it_says_otherwise() {
        let writable = r#"{"volumes":[{"name":"h","hostPath":{"path":"/var/run"}}],
          "containers":[{"name":"a","image":"registry.internal/a@sha256:x",
            "volumeMounts":[{"name":"h","mountPath":"/host"}]}]}"#;
        let ro = r#"{"volumes":[{"name":"h","hostPath":{"path":"/var/run"}}],
          "containers":[{"name":"a","image":"registry.internal/a@sha256:x",
            "volumeMounts":[{"name":"h","mountPath":"/host","readOnly":true}]}]}"#;

        assert_eq!(
            compile_str(writable, &snap_open())
                .unwrap()
                .demands
                .filesystem,
            Level::Full
        );
        assert_eq!(
            compile_str(ro, &snap_open()).unwrap().demands.filesystem,
            Level::ReadWrite
        );
    }

    /// A hostPath nothing mounts is still staged by the kubelet, and an
    /// ephemeral container added later can mount it. Reading it as
    /// harmless because no mount references it today would be a hole
    /// with a one-command exploit.
    #[test]
    fn an_unmounted_host_path_is_still_authority() {
        let spec = r#"{"volumes":[{"name":"h","hostPath":{"path":"/"}}],
          "containers":[{"name":"a","image":"registry.internal/a@sha256:x"}]}"#;
        let pod = compile_str(spec, &snap_open()).unwrap();
        assert_eq!(pod.demands.filesystem, Level::Full);
    }

    #[test]
    fn image_doubts_are_distinguished() {
        for (image, want) in [
            ("nginx", Some(ImageDoubt::Floating)),
            ("nginx:latest", Some(ImageDoubt::Floating)),
            ("nginx:1.27", Some(ImageDoubt::NotPinned)),
            ("registry:5000/app", Some(ImageDoubt::Floating)),
            ("registry:5000/app:1.2", Some(ImageDoubt::NotPinned)),
            (
                "docker.io/nginx@sha256:abc",
                Some(ImageDoubt::UntrustedSource),
            ),
            ("registry.internal/app@sha256:abc", None),
            ("", Some(ImageDoubt::Floating)),
        ] {
            assert_eq!(image_doubt(image, &snap_open()), want, "{image:?}");
        }
    }

    #[test]
    fn rbac_escalation_lifts_the_exec_demand() {
        let spec = r#"{"serviceAccountName":"ci","containers":[
            {"name":"a","image":"registry.internal/a@sha256:x"}]}"#;
        let snapshot = ClusterSnapshot {
            rbac: vec![RbacRule {
                binding: "ci-can-deploy".into(),
                resource: "pods".into(),
                verbs: vec!["create".into()],
                namespace: Some("ci".into()),
                ..Default::default()
            }],
            ..snap_open()
        };
        let pod = compile_str(spec, &snapshot).unwrap();
        assert_eq!(pod.demands.exec, Level::Full, "creating pods is privilege");
        assert!(pod.has_consequential());

        let row = pod
            .rows
            .iter()
            .find(|r| matches!(r.effect, Effect::ApiAccess { .. }))
            .unwrap();
        assert!(row.source.to_string().contains("ci-can-deploy"));
        assert!(row.effect.explain().contains("privileged"));
    }

    #[test]
    fn a_pod_within_its_grant_and_one_that_is_not() {
        let spec = r#"{"containers":[{"name":"a","image":"registry.internal/a@sha256:x",
            "env":[{"name":"P","valueFrom":{"secretKeyRef":{"name":"db","key":"p"}}}]}]}"#;
        let snapshot = ClusterSnapshot {
            egress: Some(EgressPolicy {
                policy_names: vec!["egress-api".into()],
                cidrs: vec!["10.0.0.0/8".into()],
                ..Default::default()
            }),
            ..snap_open()
        };
        let pod = compile_str(spec, &snapshot).unwrap();
        assert_eq!(
            pod.demands,
            Grant::new(Level::ReadOnly, Level::Allowlist, Level::None)
        );

        assert!(pod
            .within(&Grant::new(
                Level::ReadWrite,
                Level::Allowlist,
                Level::Sandboxed
            ))
            .is_ok());
        // ...and a grant that does not cover the egress refuses.
        assert!(pod
            .within(&Grant::new(
                Level::ReadWrite,
                Level::Loopback,
                Level::Sandboxed
            ))
            .is_err());
    }

    #[test]
    fn malformed_input_never_panics_and_is_never_harmless() {
        for case in [
            "",
            "{",
            "[]",
            "null",
            r#"{"containers":[{}]}"#,
            r#"{"containers":[{"securityContext":{"capabilities":{"add":["","CAP_"]}}}]}"#,
            r#"{"volumes":[{"name":"h","hostPath":{}}],"containers":[]}"#,
        ] {
            let _ = compile_str(case, &ClusterSnapshot::default());
        }

        // A container with nothing in it still has an unidentified
        // image and still sits on an open cluster.
        let pod = compile_str(r#"{"containers":[{}]}"#, &ClusterSnapshot::default()).unwrap();
        assert_eq!(pod.demands.network, Level::Full);
        assert!(pod
            .rows
            .iter()
            .any(|r| matches!(r.effect, Effect::UntrustedImage { .. })));
    }
}
