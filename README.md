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

**Milestones 1–5 of [#1](https://github.com/alpibrusl/lex-k8s/issues/1).**
A pure function from a `PodSpec` and a cluster snapshot to effect rows
([#2](https://github.com/alpibrusl/lex-k8s/issues/2)), the `LexManifest`
CRD, the two admission walls and the hash-chained audit
([#3](https://github.com/alpibrusl/lex-k8s/issues/3)), attestation
([#4](https://github.com/alpibrusl/lex-k8s/issues/4)), the budget wall,
and the serving webhook
([#10](https://github.com/alpibrusl/lex-k8s/issues/10)).

**It runs in a cluster.** `./demo/kind.sh` goes from no cluster to a
refused pod with the wall's own reason on the terminal, and CI runs it
on every change — see [In a cluster](#in-a-cluster). Until milestone 5
none of this had ever run inside one, and that sentence was the largest
thing standing between the repo and a deployment.

## In a cluster

```sh
./demo/kind.sh          # create, deploy, and run all eight steps
KEEP=1 ./demo/kind.sh   # ...and leave the cluster up
```

Eight steps, no mock. A real API server calls a real webhook over TLS,
and every verdict comes from the same `admit()` / `narrow()` the CLI
calls:

1. cluster, image, CRD, RBAC, certificates, webhook — `failurePolicy: Fail`
2. a pod that reaches past the grant is **refused**
3. a NetworkPolicy lands, and **the same pod is admitted** — the spec did
   not change, the cluster did, and the wall read it from a live watch
4. a privileged pod with a hostPath mount and an ungranted secret is
   **refused**
5. a `LexManifest` that widens its parent is **refused by `/narrow`**
6. the audit chains, one per pod admission
7. the wall is scaled to zero and admissions **stop** — `failurePolicy:
   Fail` doing its job, on a pod that was admitted a moment earlier
8. a refusal is rewritten into an admission and the chain rebuilt — the
   chain accepts it, **the seal refuses it**
9. a decision file is deleted — **the ledger names the gap**
10. what the restart cost the record — see caution 9

### How it is wired

`lex-k8s serve` is the CLI's `admit` and `narrow` behind TLS, and it
decides nothing of its own. The two inputs the CLI takes as flags come
from watch caches instead:

| Flag, on the CLI | In the cluster | When it is missing |
| --- | --- | --- |
| `--manifest` | the one `LexManifest` in the pod's namespace | no manifest, no admission — and two is a refusal, not a coin toss |
| `--snapshot` | NetworkPolicy + RBAC reflectors | no policy selects the pod ⇒ **unrestricted egress**, which is what Kubernetes does |

Caches, not lookups, for the reason
[`src/cluster.rs`](src/cluster.rs) already gives: the API server is
calling *us*, inside its own request path, and calling back into it to
decide is a deadlock waiting for a bad afternoon. `/readyz` stays 503
until every cache has listed once, because a cold cache is
indistinguishable from a cluster with no policies — and that reads as
permission.

Serving is behind the `serve` feature so the decision half stays cheap
to depend on. A binary built without it says so rather than starting
something weaker.

### Sealing the decision log

This wall writes its chains to the **pod's own filesystem**, which is the
weakest place any consumer of lex-os's `Chain<E>` puts one. A hash chain
is tamper-*evident* only against someone who cannot recompute it — and
the hashes are derived from the contents, so whoever can reach that
volume can rewrite a refusal into an admission, rebuild every hash, and
hand you a log that verifies perfectly.

`--audit-key-file` seals every entry with Ed25519
([alpibrusl/lex-os#54](https://github.com/alpibrusl/lex-os/issues/54)),
which is the part they cannot recompute:

```sh
lex-k8s audit pubkey --key-file audit.key          # the half a verifier needs
lex-k8s audit verify --log decision.json           # the chain only
lex-k8s audit verify --log decision.json --trusted-key <public-hex>
```

Step 8 of the demo runs exactly that attack — `demo/forge-verdict.py`
needs no key and no privilege, only the file — and shows the chain
accepting it and the seal refusing it. Sealing is opt-in, and an
unsealed log is reported as unsealed rather than as passing: the wall
warns loudly at startup if it is writing one, and `audit verify` says
`NOT CHECKED` rather than `OK` when you give it no key.

### The ledger: a deleted decision is not a silent one

Sealing proves nobody *rewrote* a decision. It cannot prove a decision
that happened still exists — a seal covers what a record says, never
whether the record is still there. Each admission gets its own chain, so
`rm` on one file used to leave nothing to notice.

The wall keeps a **ledger**: one long-lived sealed chain it appends to
after every decision, carrying the subject, the verdict and the head of
that decision's own chain. A deleted file is then a head the ledger
names with nothing behind it.

```sh
lex-k8s audit reconcile --ledger /audit/ledger.json --decisions /audit                         --trusted-key <public-hex>
```

```
REFUSED — the ledger and the decisions disagree.
  DELETED?    witnessed head 95898f2e… has no file behind it
```

It checks **both** directions: a file the ledger never witnessed is a
planted decision, or a ledger that lost its tail, and either way the two
records disagree. `/narrow` is witnessed here too — before the ledger it
wrote no record at all, and a manifest that widens its parent is the
more consequential of the two decisions this wall makes.

On every append the wall prints a **signed checkpoint** to stdout —
`(domain, len, head)` over the ledger. That is the artifact that
outlives the pod, because a log collector already keeps stdout and the
pod does not own it. `audit reconcile --checkpoint` holds a ledger to
one, which catches the attack one level up: truncating the ledger's tail
to drop the entries witnessing the decisions you also deleted.

**What none of it survives.** The ledger lives on the same volume as the
decisions, so the disk going away takes both. Sealing stops a rewrite,
the ledger names a deletion, a checkpoint catches a truncation — and a
collector holding one checkpoint is what makes the last of those work.
Durable storage is a deployment decision this repo does not make for
you.

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

The webhook builds the snapshot from watch caches before it decides
([`src/serve/snapshot.rs`](src/serve/snapshot.rs)), and pins the
`resourceVersion` of every object it read into the snapshot's
`provenance` — which is hashed, so a verdict names the revision of the
cluster it was made on. Staleness is handled there, and it is a
separate problem from this one.

## Every container, not the first one

Init containers, native sidecars (`restartPolicy: Always`, k8s 1.29+),
and ephemeral containers all contribute authority:

- an **init container** running privileged has already been root on the
  node by the time the app container starts;
- a **sidecar** holds its authority for the pod's whole life;
- an **ephemeral container** is a live escalation path into a pod that
  was admitted long ago, and never appears in the create request.

## Four walls, because one cannot say all four things

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

`cluster/<name>` resolves to `<name>` in the namespace the wall runs in
(`lex-system`, or `--root-namespace`). The CRD is `scope: Namespaced`,
so no genuinely cluster-scoped `LexManifest` can exist — left alone,
every `parent: cluster/...` would be unresolvable in a real cluster,
which this wall refuses, correctly and uselessly. Putting the ceiling in
`lex-system` puts it where the authority to set it already lives, rather
than inventing a second CRD scope with its own narrowing rule. **An
unresolvable parent is a refusal**, not a pass: a child that could name
a parent nobody can read would be granting itself whatever it liked.

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

## The fourth wall: the budget

A namespace's committed spend, charged against
`budget.max_money_cents` — the same integer-cents ceiling lex-iac
charges a Terraform plan against, and the same house rule: **money
never touches a float**.

```sh
lex-k8s admit --manifest payments.json \
    --prices prices.json --spend spend.json < review.json

REFUSED   payments/api — 1 wall(s) tripped
  [budget] spend
    at:     resources.requests
    reason: this pod reserves USD 68.00/month (2000m CPU, 2048 MiB), which
            would put `payments` at 218.00 against a ceiling of 200.00
            (18.00 over) — this bounds committed reservation, not the invoice
```

> **Exceeding the budget refuses new admissions, never running pods.**

An admission webhook has no eviction path and must never grow one. A
namespace already over its ceiling keeps everything it is running; all
this wall does is stop the next thing. The alternative fails
catastrophically and asymmetrically: a price list edited by the wrong
hand would take production down, to prevent an overspend that had
already happened.

### A pod's cost is computable; a namespace's is not

This is the one place the Kubernetes gate has *more* to work with than
the Terraform one. lex-iac cannot price a plan and takes an estimator's
JSON; a pod declares what it wants reserved, and `requests × rate` is
arithmetic. So the pod's own forecast is computed here from the spec,
and only two things are supplied — what resources cost, and what the
namespace already commits. Both are inputs rather than lookups, for the
reason this repo keeps rediscovering: a webhook that phones a billing
API is a webhook that fails when billing does, and `failurePolicy:
Fail` turns that into a cluster that cannot schedule.

**Requests, not limits.** Requests are what the scheduler reserves and
what every cost tool bills against. A pod is charged for what it holds,
not for what it may burst to.

### Init containers are a peak, not a sum

Kubernetes' own effective-request rule, and getting it wrong is not a
rounding error:

```text
max( max over init containers,
     sum over app containers + sidecars )
```

Init containers run sequentially *before* the app containers, so a
migration that wants 2 cores for thirty seconds is not billed as if it
held them all month. Sidecars — `restartPolicy: Always` init containers
— are in the sum instead, because they run for the pod's whole life.
This repo already drew that distinction for authority; it turns out to
be load-bearing for money too. Ephemeral containers reserve nothing:
Kubernetes forbids `resources` on them, so a debug container cannot
change what a pod costs.

### An empty request is not a request for nothing

A container with no `resources.requests` is scheduled BestEffort and
uses whatever the node has spare. Pricing that at zero would make
deleting the `resources` block the cheapest way past any ceiling, so a
pod that cannot be priced is refused while a budget is being enforced.
The fourth outing for the rule PR #8 in lex-iac paid for.

The same rule upward: a manifest that declares **no** `budget`
authorises no spend, not unlimited spend. lex-os's default is
`max_money_cents: 0`, and the CLI says so loudly rather than leaving an
operator to work out why every pod is refused.

`currency` sits on the facet for the reason it does in lex-iac:
`max_money_cents` is a bare integer, so nothing in it says which
currency, and a child namespace that redenominated its budget would
have widened it. A report in another currency stops the wall rather
than being converted.

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
6. **The budget bounds committed reservation, not the invoice.**
   `requests × list rate` ignores utilisation, spot pricing,
   reservations and every negotiated discount. A reader who treats it
   as a meter will size the ceiling wrong. It is also per-namespace and
   monthly, and it trusts the spend report it is handed: a stale report
   understates what is committed, always in the direction that admits
   the pod.
7. **The waiver is the only thing standing decides, and there is one of
   them.** `imagePrefixes` is currently the sole dimension a manifest
   can leave undeclared, so today the trust wall has exactly one lever.
   That is honest rather than elegant: more levers should arrive as
   more dimensions become waivable, not by inventing authority for a
   score to hand out.
8. **The dangerous-capability list is a list, and lists are wrong.** A
   capability not on it still raises `exec`, to `sandboxed` rather than
   `full`. Getting the list wrong understates one pod; getting the
   default wrong would understate all of them.
9. **The audit record lives inside the thing it audits.** Three layers
   now stand on it — entries are sealed (a decision cannot be
   *rewritten*), a ledger witnesses every decision (a deletion is
   *named*), and a signed checkpoint goes to stdout on every append (a
   ledger truncated to hide both is *contradicted*). Steps 8 and 9 of
   the demo run the first two attacks for real. What none of them
   survives is the volume itself going away, which step 10 shows: the
   ledger sits beside the decisions. Only the checkpoints leave the pod,
   and only if something is collecting stdout. A durable volume or a
   collector is a deployment decision this repo does not make for you.
10. **`/narrow` decides without a chain of its own.** Manifest verdicts
    reach the log but not the audit record — the chain's vocabulary is
    pod-shaped. A manifest that widens its parent is the more
    consequential of the two decisions, so this asymmetry is backwards
    and is worth fixing.
11. **One replica, and no leader election.** Each replica keeps its own
    caches, and two caches can disagree for a moment after a
    NetworkPolicy changes — so two replicas can give two verdicts for
    one pod. One is honest for a demo and wrong for production.
12. **Certificates are read from disk and never rotated.**
    `deploy/bootstrap-certs.sh` mints a self-signed pair so the demo
    needs nothing but `openssl`; a real deployment wants cert-manager.
    A certificate the API server does not trust fails closed, which
    with `failurePolicy: Fail` means every admission in the cluster
    stops.

## Develop

```sh
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check

# the server, which is behind a feature flag — CI runs both, because a
# feature flag CI never turns on is code CI does not have
cargo test --features serve
cargo clippy --all-targets --features serve -- -D warnings

# the wall in a real cluster (needs kind, kubectl, docker, openssl)
./demo/kind.sh
```

## License

[EUPL-1.2](LICENSE).
