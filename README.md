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

The demo #3 exists to refuse — a pod that lies about its egress, stopped
before it schedules:

```sh
cargo run -- admit \
  --manifest tests/fixtures/manifest_payments.json \
  --snapshot tests/fixtures/snapshot_policy_is_a_lie.json \
  < tests/fixtures/review_lying_about_egress.json
```

```
REFUSED   payments/exporter-7d9f- — 2 wall(s) tripped
  [type-check] egress:unrestricted
    at:     spec.egress
    reason: trust widening on network: child requests `full` but parent
            only grants `allowlist`
  [narrowing] egress:unrestricted
    at:     spec.egress
    reason: `0.0.0.0/0` is not among the 2 the manifest grants:
            postgres.payments.svc, api.stripe.com:443
audit: 2 entries, head sha256:452a9848…
exit 8
```

The pod drops `ALL` capabilities, pins its image by digest, and annotates
itself with a narrow egress. A forgotten `legacy-allow-all` NetworkPolicy
also selects it. **An annotation is a claim; a NetworkPolicy is the wall.**

And the wall a constraint language has nowhere to put — on the policies
themselves:

```sh
cargo run -- manifest narrow \
  --parent tests/fixtures/manifest_platform.json \
  --child  tests/fixtures/manifest_mints_itself_root.json
```

```
REFUSED — the child widens its parent.
  trust widening on filesystem: child requests `full` but parent only
  grants `read-only`

A team lead hands out authority they hold, never authority they
do not.
```

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

**Milestones 1 and 2 of [#1](https://github.com/alpibrusl/lex-k8s/issues/1).**
A pure function from a `PodSpec` and a cluster snapshot to effect rows
([#2](https://github.com/alpibrusl/lex-k8s/issues/2)), the `LexManifest`
CRD, the two admission walls, and the hash-chained audit
([#3](https://github.com/alpibrusl/lex-k8s/issues/3)).

**There is no serving binary yet, and that is deliberate.** `lex-k8s
admit` reads an `AdmissionReview` on stdin and writes the response on
stdout — exactly what a webhook does between its TLS handshake and its
HTTP reply. The deployment manifests are in [`deploy/`](deploy/). What
is missing is the HTTP+TLS wrapper and a cluster to test it against;
shipping an untested TLS server would be worse than shipping none, so
the `kind` demo in #3 is still open and is the one part of this
milestone nobody has run.

Not yet here: attestation
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

## Three walls, because one cannot say all three things

The lattice bounds **how far**: `network: allowlist` means named
destinations rather than the whole internet. The `pod` facet bounds
**where**: which hosts, which Secrets, which capabilities.

Neither alone is enough, and the gap is not theoretical:

| a pod that… | lattice | facet |
| --- | --- | --- |
| reaches `exfil.example.com` under an allowlist policy | passes | **refuses** |
| sets `hostNetwork: true` | **refuses** | passes any host list |
| mounts a Secret the manifest never named | passes | **refuses** |

The facet lives on the same `lex_os_manifest::Manifest`, in the slot
[lex-os#71](https://github.com/alpibrusl/lex-os/issues/71) opened —
lex-iac's `infra` facet was the first user, this is the second. One
manifest, one `ManifestId`, one narrowing wall.

### An empty allow-list grants nothing

Not "unconstrained". A manifest that omits `secrets` authorises no
Secret at all. That is the reading that fails safe, and the one an
operator writing their first manifest expects least — so it is said
here, in the CRD schema, and in the module docs.

The exception is `imagePrefixes`, which cannot mean "no images" without
refusing every pod. An empty list means provenance is not checked *by
the manifest*, and an admitted pod says so in its `warnings` rather than
passing silently. "We did not look" and "we looked and it was fine" are
different facts.

## `parent` is the wall Gatekeeper structurally lacks

A `LexManifest` naming a parent is checked against it: a namespace lead
hands out authority they hold, never authority they do not.

```yaml
spec:
  parent: cluster/platform-default
```

A constraint language can only enumerate what is forbidden. It has
nowhere to put *"and this policy is itself bounded by that one"*. That
is the reason to build this rather than write more Gatekeeper
constraints — and it is the claim to judge the project on.

## The third wall: earned standing

The first two walls ask what the *pod* may do. The third asks what this
*submitter* has earned — and it can only ever take something away.

A manifest that names no `imagePrefixes` has declared no image policy.
Milestone 2 admits under that silence and says out loud that nobody
looked. That silence is a **waiver**, and a waiver is exactly the kind
of thing a track record should decide: a submitter with a record keeps
it, and one nobody has scored does not.

```sh
lex-k8s admit --manifest payments.json --trusted-keys trusted.json < review.json

REFUSED   payments/cache — 1 wall(s) tripped
  [trust] unchecked
    at:     image provenance
    reason: the manifest names no `imagePrefixes`, so images were not
            checked; the manifest waives that check, and
            system:serviceaccount:payments:intern has no earned standing
            to be waived for — declare the policy, or let the submitter
            earn a score
```

> **Trust narrows; it never widens.**

This wall can only refuse what the other two admitted. It cannot admit
anything they refused, which is what keeps the manifest the ceiling. A
score is never authority.

**The submitter is authenticated, not asserted.** It comes from the
`AdmissionReview`'s `userInfo.username`, which the API server fills in
after authenticating the requester — which is why there is no
`--signer` flag here, where lex-iac needs one. A webhook that let its
caller name the submitter would let any submitter spend another's
record. A review carrying no `userInfo` is not a submitter with a poor
record; it is no submitter at all, and gets the narrower reading.

**Without `--trusted-keys` nothing is consulted and nothing tightens.**
"We did not ask" and "we asked and they are not on it" are different
facts, and the log records which. An empty keyring trusts nobody, the
same way an empty allow-list grants nothing.

### Earning it

The keyring is an output of past admissions, not a configuration file.
`--audit-out` writes the `{seq, prev_hash, event, hash}` array
`lex attest import-apply` promotes:

```sh
lex-k8s admit --manifest payments.json --audit-out log.json < review.json

lex attest import-apply --audit log.json --gate kubernetes \
    --accepted pod_admitted --refused pod_refused
lex producer-trust recompute --tool system:serviceaccount:payments:deployer
lex producer-trust keyring --min-trust 700 --out trusted.json
```

Both verdicts are promoted, not only admissions: producer trust is
`passed / (passed + failed)`, so a corpus of admissions alone would
score every submitter 1.0 for ever.

**One attestation kind, two gates.** These promote as `PlanApply`, the
same variant lex-iac's Terraform decisions use — a plan-shaped
artifact, checked against a manifest, decided under a signer. A
Kubernetes-specific variant would split one submitter's record in two,
so what differs between the gates lives in the payload (`gate`,
`subject`), not in the discriminant. lex-lang never learns this repo's
vocabulary: the caller names the event kinds, and a promotable event
carries the three fields lex-lang *does* name — `artifact_sha256`,
`manifest` and `signer`. That is why the spec hash is spelled
`artifact_sha256` in the log while `PodEffects` still calls it
`spec_sha256`.

## A refusal is a typed record

Kubernetes has a place for this that most webhooks do not use:
`status.details.causes[]`. Each cause carries the wall, the reason, and
the field — so `kubectl` shows an operator the line of YAML to change,
and an agent gets something it can act on rather than a string to parse.

```json
{
  "reason": "narrowing",
  "message": "secret:root-ca-key: `Secret `root-ca-key`` is not among the 1 the manifest grants",
  "field": "containers[api].env[K].valueFrom",
  "grantAllows": ["stripe-live-key"]
}
```

`grantAllows` is ours rather than Kubernetes'. It is a list because the
point of a typed record is that a reader does not have to regex prose.

## Honest cautions

1. **A webhook is only a wall if it cannot be bypassed.** The shipped
   `ValidatingWebhookConfiguration` uses `failurePolicy: Fail`, which is
   not a tuning knob: under `Ignore`, a webhook outage means every pod is
   admitted unchecked. The consequence belongs in your runbook — if this
   webhook is down, admissions stop. And anyone with cluster-admin can
   delete the object; the audit chain records that they did, it does not
   stop them. The comparison to Gatekeeper is winnable on narrowing, not
   on tamper-resistance.
2. **`isolationFloor` is declared and not enforced here.** The
   RuntimeClass that would back it is deliberately in another repo, so a
   manifest asking for `microvm` is refused rather than accepted
   silently — an operator must not come away believing a boundary exists
   that does not. Spell it `unenforced-microvm` to say yes on purpose.
3. **The effect row is lossy, and that is structural.** Sidecars, CSI
   drivers and operators act on the pod's behalf; the row captures what
   the spec *declares*, not what the node does. Bounding the rest needs
   the RuntimeClass, which is not in this repo and by design never will
   be.
4. **Signing is asserted, not verified.** This crate has no keys, no
   registry access, and no business doing crypto in an admission path.
   It records what the snapshot claims. What milestone 3 adds is a
   record of *decisions*, earned per submitter — not verification of
   the images themselves, which still rests on the snapshot's word.
5. **A keyring cannot tell "never scored" from "scored badly".** Both
   read as absent, and this wall deliberately does not guess between
   them — `lex producer-trust recompute --tool <id>` is where an
   operator finds out which. The threshold also lives with whoever
   exported the keyring, not in the manifest, so two namespaces can
   disagree about what 700 means.
6. **The waiver is the only thing standing decides, and there is one of
   them.** `imagePrefixes` is currently the sole dimension a manifest
   can leave undeclared, so today the trust wall has exactly one lever.
   That is honest rather than elegant: more levers should arrive as
   more dimensions become waivable, not by inventing authority for a
   score to hand out.
7. **The dangerous-capability list is a list, and lists are wrong.** A
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
