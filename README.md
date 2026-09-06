# lex-k8s

**Part of the [Lex](https://lexlang.org) project** — Substrate · [Manifesto](https://lexlang.org/manifesto) · [lex-lang](https://github.com/alpibrusl/lex-lang) · [lex-os](https://github.com/alpibrusl/lex-os) · [lex-iac](https://github.com/alpibrusl/lex-iac)

> A pod spec is a capability request. Kubernetes admits it without ever
> asking what it adds up to.

`lex-os-check` refuses a `.lex` program whose effects exceed the
manifest's grant, before it runs. This does the same for a pod. The spec
compiles to typed effect rows, each row carries the trust `Grant` it
demands, and their join is what the namespace's grant has to cover.

The wall is then one comparison, not a rule list:

```rust
pod.within(&namespace_grant)?
```

## We are not building a Kubernetes

Placement, networking, storage and reconciliation are solved, and they
are the least lex-shaped problems there are. This repo is **one seam**:
the type-check wall as a validating admission webhook.

The other seam — the perimeter as a RuntimeClass — is deliberately
elsewhere. A containerd shim is a second consumer of lex-os's core, not
a downstream consumer of it, and it belongs in the lex-os workspace.

## Try it

```sh
cargo run --example compile_pod
```

```
The same pod. Two clusters. One of them admits it.

namespace grant:  Grant { filesystem: ReadOnly, network: Allowlist, exec: Sandboxed }

a cluster with one egress policy
  demands:   Grant { filesystem: None, network: Allowlist, exec: None }
  verdict:   ADMITTED

...and one with a forgotten legacy-allow-all
  demands:   Grant { filesystem: None, network: Full, exec: None }
  verdict:   REFUSED
             trust widening on network: child requests `full` but parent
             only grants `allowlist`
             egress is unrestricted: one of `payments-egress`,
             `legacy-allow-all` permits 0.0.0.0/0
```

Nothing about the spec changed between those two runs. The pod annotates
itself `lex.dev/egress: metrics.internal:9090`, drops `ALL`
capabilities, and pins its image by digest. **An annotation is a claim;
a NetworkPolicy is the wall** — so the compiler reports what the cluster
enforces, and on the second cluster that is `0.0.0.0/0`.

On your own pod:

```sh
kubectl get pod api -o json > pod.json
cargo run --example compile_pod -- pod.json snapshot.json
```

```
SOURCE                                                  EFFECT             CLASS
initContainers[sysctl-tuner].securityContext.privileged privileged         CONSEQUENTIAL
spec.egress                                             egress:allowlist   bounded
spec.serviceAccountName=default via ci-deployer         api:deployments    CONSEQUENTIAL

this pod demands:
  filesystem: Full
  network:    Allowlist
  exec:       Full
```

That pod's *app* container is unremarkable. Reading only `containers[0]`
— which is what most tooling does — would have called it clean.

## Where this is

**Milestone 1 of [#1](https://github.com/alpibrusl/lex-k8s/issues/1).**
A pure function from a `PodSpec` and a cluster snapshot to effect rows
([#2](https://github.com/alpibrusl/lex-k8s/issues/2)). No cluster, no
API server, no CRD, no certificates.

Not yet here: the `LexManifest` CRD and the admission webhook
([#3](https://github.com/alpibrusl/lex-k8s/issues/3)), and attestation
([#4](https://github.com/alpibrusl/lex-k8s/issues/4)).

## The effect model

Every authority-bearing field becomes a row, and every row demands a
`Grant`. The mapping is a judgement call, so it is written down rather
than buried:

| pod declares | filesystem | network | exec |
| --- | --- | --- | --- |
| secret mounted or in env | `read-only` | — | — |
| `hostPath`, read-only | `read-write` | — | — |
| `hostPath`, writable | `full` | — | — |
| `privileged: true` | `full` | — | `full` |
| `hostPID` / `hostIPC` | — | — | `full` |
| `allowPrivilegeEscalation: true` | — | — | `full` |
| dangerous capability | — | — | `full` |
| other added capability | — | — | `sandboxed` |
| `hostNetwork: true` | — | `full` | — |
| egress policy permitting `0.0.0.0/0` | — | `full` | — |
| **no egress policy at all** | — | `full` | — |
| egress policy with rules | — | `allowlist` | — |
| egress deny-all | — | `none` | — |
| any RBAC binding | — | `allowlist` | — |
| unreadable field | *the widest it could imply* | | |

There is deliberately no baseline row. A pod that declares nothing
demands nothing — charging every pod a floor would make the interesting
ones harder to see.

### Two rows worth defending

**A read-only `hostPath` is `read-write`, not `read-only`.** The level
describes reach, not the mount flag. Reading `/var/lib/kubelet` is not
the same kind of act as reading your own container filesystem, and
grading it alongside a mounted Secret would let a grant that meant the
second authorise the first.

**No egress policy is `full`.** In Kubernetes, a pod that no
`NetworkPolicy` selects has unrestricted egress. Reading absence as
"nothing declared, so nothing granted" would have the default backwards
on the most common cluster there is.

That second one is a specific mistake, made in a sibling repo and fixed
there ([lex-iac#8](https://github.com/alpibrusl/lex-iac/pull/8)): a
document that omitted its authority-bearing field was read as a document
with no authority in it, and approved. The rule both repos now hold to:

> **Absent evidence is not evidence of absence.**

So a document with no `containers` is refused rather than read as a pod
that runs nothing, and a field this build cannot parse is read as the
widest thing it could have meant.

## The cluster snapshot is an input, not a lookup

A `PodSpec` alone does not say what a pod can reach. Egress is decided
by the `NetworkPolicy` objects selecting it; API reach by the bindings
on its ServiceAccount. Both are passed in:

```rust
compile_str(&spec_json, &snapshot)   // pure. no API server.
```

Three reasons, in order of how much they matter:

1. A wall that queries mid-admission is a wall whose verdict depends on
   *when* it ran. The snapshot folds into the record, so a decision can
   be reproduced against the state it was actually made on.
2. Every interesting case is reachable from a fixture, so it gets tested
   rather than described.
3. The API server is calling *us*, inside its own request path. Calling
   back into it to decide is a deadlock waiting for a bad afternoon.

The webhook builds the snapshot from informer caches before it decides.
Staleness is handled there, and it is a separate problem from this one.

## Every container, not the first one

Init containers, native sidecars (`restartPolicy: Always`, k8s 1.29+),
and ephemeral containers all contribute authority:

- an **init container** running privileged has already been root on the
  node by the time the app container starts;
- a **sidecar** holds its authority for the pod's whole life;
- an **ephemeral container** is a live escalation path into a pod that
  was admitted long ago, and never appears in the create request.

## Honest cautions

1. **A webhook is only a wall if it cannot be bypassed.** That means
   `failurePolicy: Fail` and an API server that enforces it. Anyone with
   cluster-admin can delete the webhook; the audit chain records that
   they did, it does not stop them.
2. **The effect row is lossy, and that is structural.** Sidecars, CSI
   drivers and operators act on the pod's behalf; the row captures what
   the spec *declares*, not what the node does. Bounding the rest needs
   the RuntimeClass, which is not in this repo and by design never will
   be.
3. **Signing is asserted, not verified.** This crate has no keys, no
   registry access, and no business doing crypto in an admission path.
   It records what the snapshot claims. Milestone 3 turns accepted
   admissions into attestations, and that is where trust is *earned*
   rather than declared.
4. **The dangerous-capability list is a list, and lists are wrong.** A
   capability not on it still raises `exec`, to `sandboxed` rather than
   `full`. Getting the list wrong understates one pod; getting the
   default wrong would understate all of them.

## Develop

```sh
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

## License

[EUPL-1.2](LICENSE).
