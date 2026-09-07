#!/usr/bin/env bash
# The kind demo (alpibrusl/lex-k8s#10).
#
# Milestones 1–4 decided correctly against real AdmissionReview
# documents on stdin. Nothing had ever run inside a cluster. This is
# that run, end to end, from no cluster to a refused pod with the wall's
# own reason on the terminal.
#
#   ./demo/kind.sh          # create, deploy, run all eight steps
#   KEEP=1 ./demo/kind.sh   # leave the cluster up afterwards
#
# Requires: kind, kubectl, docker, openssl.
set -euo pipefail

CLUSTER=${CLUSTER:-lex-k8s-demo}
IMAGE=${IMAGE:-lex-k8s:dev}
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
KEEP=${KEEP:-0}

bold() { printf '\n\033[1m%s\033[0m\n' "$*"; }
note() { printf '  %s\n' "$*"; }
fail() { printf '\n\033[31mFAILED: %s\033[0m\n' "$*" >&2; exit 1; }

cleanup() {
  rm -rf "${WORKDIR:-}"
  if [ "$KEEP" = "1" ]; then
    bold "cluster $CLUSTER left up (KEEP=1). Delete it with: kind delete cluster --name $CLUSTER"
  else
    kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

# A host build for the verification half of step 8: the wall runs in the
# cluster, but checking what it wrote is something an operator does from
# outside, with only the public key.
WORKDIR=$(mktemp -d)
cargo build --quiet --manifest-path "$ROOT/Cargo.toml"
LEXK8S="$ROOT/target/debug/lex-k8s"

bold "0. cluster, image, CRD, webhook"
kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
kind create cluster --name "$CLUSTER" >/dev/null 2>&1
note "cluster up: $(kubectl config current-context)"

docker build -t "$IMAGE" "$ROOT" >/dev/null 2>&1
kind load docker-image "$IMAGE" --name "$CLUSTER" >/dev/null 2>&1
note "image built and loaded: $IMAGE"

kubectl apply -f "$ROOT/deploy/crd.yaml" >/dev/null
kubectl apply -f "$ROOT/deploy/namespace.yaml" >/dev/null
kubectl apply -f "$ROOT/deploy/rbac.yaml" >/dev/null
kubectl apply -f "$ROOT/deploy/service.yaml" >/dev/null

CA_BUNDLE=$(NS=lex-system SERVICE=lex-k8s "$ROOT/deploy/bootstrap-certs.sh")
note "serving certificate minted; CA is ${#CA_BUNDLE} bytes of base64"

# The audit signing key (lex-os#54). Deterministic here so the demo can
# print the public half; a real deployment generates one and keeps the
# secret in a Secret nobody mounts twice.
AUDIT_SK=$(printf '07%.0s' $(seq 1 32))
kubectl -n lex-system delete secret lex-k8s-audit-key --ignore-not-found >/dev/null
kubectl -n lex-system create secret generic lex-k8s-audit-key \
  --from-literal=audit.key="$AUDIT_SK" >/dev/null
AUDIT_PK=$("$LEXK8S" audit pubkey --key "$AUDIT_SK")
note "audit signing key mounted; decisions will be sealed by ${AUDIT_PK:0:16}…"

kubectl apply -f "$ROOT/deploy/deployment.yaml" >/dev/null
kubectl -n lex-system rollout status deploy/lex-k8s --timeout=180s >/dev/null
note "wall is ready (every cache has listed once)"

# Registered last, and only once the wall is serving. With
# `failurePolicy: Fail`, registering a webhook that is not up yet stops
# admissions cluster-wide — including the wall's own restart.
# Both entries, not one. A webhook registered without a caBundle is not
# unconfigured — it is configured to be verified against the API
# server's own roots, which fails as "certificate signed by unknown
# authority" on a call the operator did not know was being made.
python3 "$ROOT/demo/inject-ca.py" "$ROOT/deploy/webhook.yaml" "$CA_BUNDLE" | kubectl apply -f - >/dev/null
note "ValidatingWebhookConfiguration registered on both entries, failurePolicy: Fail"

# The Service's endpoints are programmed asynchronously, and the first
# call through a webhook that is registered but not yet routable comes
# back as "connection refused" — which looks exactly like a broken wall.
# Waiting here keeps a startup race out of the demo's verdicts.
for i in $(seq 1 60); do
  if kubectl apply --dry-run=server -f "$ROOT/demo/manifests/00-platform.yaml" >/dev/null 2>&1; then
    break
  fi
  if [ "$i" = "60" ]; then
    fail "the webhook never became reachable: $(kubectl apply --dry-run=server -f "$ROOT/demo/manifests/00-platform.yaml" 2>&1)"
  fi
  sleep 1
done
note "the API server can reach the wall over TLS"

kubectl create namespace payments >/dev/null
kubectl -n payments create serviceaccount api >/dev/null

bold "1. the grants"
kubectl apply -f "$ROOT/demo/manifests/00-platform.yaml" >/dev/null
kubectl apply -f "$ROOT/demo/manifests/01-payments.yaml" >/dev/null
note "platform ceiling + payments grant applied"

bold "2. a pod that reaches past the grant is REFUSED"
# Before any NetworkPolicy exists, Kubernetes permits this pod to reach
# anything at all — which is `network: Full`, above what the manifest
# grants. That is the wall reading the cluster's real default, not a
# missing input.
if out=$(kubectl apply -f "$ROOT/demo/manifests/10-pod-within.yaml" 2>&1); then
  fail "the pod was admitted with no NetworkPolicy in the namespace: unrestricted egress should exceed an egress allow-list"
fi
echo "$out" | sed 's/^/  | /'
echo "$out" | grep -qi "egress" || fail "the refusal did not name egress"
note "refused, and the reason names the effect and the field"

bold "3. the same pod, once the cluster can actually bound it, is ADMITTED"
kubectl apply -f "$ROOT/demo/manifests/03-deny-all-egress.yaml" >/dev/null
# The pod did not change. The cluster did, and the wall read it from a
# live watch rather than a startup snapshot — which is the whole point
# of step 3 being separate from step 2.
for i in $(seq 1 30); do
  if kubectl apply -f "$ROOT/demo/manifests/10-pod-within.yaml" >/dev/null 2>&1; then break; fi
  sleep 1
done
kubectl -n payments get pod api >/dev/null 2>&1 \
  || fail "the pod was still refused after the NetworkPolicy landed: the cache is not live"
note "admitted — the pod is unchanged; the cache saw the NetworkPolicy"

bold "4. a pod beyond the grant is REFUSED, with every wall it tripped"
if out=$(kubectl apply -f "$ROOT/demo/manifests/11-pod-beyond.yaml" 2>&1); then
  fail "a privileged pod with a hostPath mount and an ungranted secret was admitted"
fi
echo "$out" | sed 's/^/  | /'
echo "$out" | grep -qi "privileged\|hostPath\|observability-token" \
  || fail "the refusal named none of the three things the pod asked for"

bold "5. a LexManifest that widens its parent is REFUSED by /narrow"
if out=$(kubectl apply -f "$ROOT/demo/manifests/02-widening.yaml" 2>&1); then
  fail "a manifest granting hostPath and an unnamed egress host was admitted"
fi
echo "$out" | sed 's/^/  | /'
echo "$out" | grep -qi "widens" || fail "the refusal did not say the child widens its parent"

bold "6. the audit chain, before anything restarts"
POD=$(kubectl -n lex-system get pod -l app=lex-k8s -o jsonpath='{.items[0].metadata.name}')
kubectl -n lex-system logs "$POD" | grep -E "decided|manifest (admitted|refused)" | sed 's/^/  | /'
CHAINS=$(kubectl -n lex-system exec "$POD" -- sh -c 'ls /audit | grep -v ledger.json | wc -l' | tr -d ' \r')
note "$CHAINS decision chains on the pod's volume, one per pod admission"
# Three pod admissions so far: refused (step 2), admitted (step 3),
# refused (step 4). `/narrow`'s two decisions are in the log but not on
# the volume — the manifest wall has no chain of its own yet, which is
# a gap worth naming rather than rounding off.
[ "${CHAINS:-0}" -ge 3 ] || fail "expected a chain per pod admission, found $CHAINS"

bold "7. the wall fails CLOSED"
# The pod under test here is one the wall *admits* — step 3 admitted
# exactly this spec. That is the point: if it is refused now, the only
# thing that changed is that the wall is unreachable, so the refusal
# can only be `failurePolicy: Fail` doing its job. Trying a pod that
# would be refused anyway would prove nothing at all.
kubectl -n lex-system scale deploy/lex-k8s --replicas=0 >/dev/null
# Waiting for the *endpoints* to drain, not for the Deployment to
# report zero: a terminating pod is still in the Service, and the API
# server will happily keep calling it.
for i in $(seq 1 60); do
  ADDRS=$(kubectl -n lex-system get endpointslices -l kubernetes.io/service-name=lex-k8s \
            -o jsonpath='{.items[*].endpoints[*].addresses[*]}' 2>/dev/null || true)
  [ -z "$ADDRS" ] && break
  [ "$i" = "60" ] && fail "the wall's endpoints never drained"
  sleep 1
done
note "the wall is down and out of the Service"

if out=$(sed 's/name: api/name: api-failclosed/' "$ROOT/demo/manifests/10-pod-within.yaml" \
           | kubectl apply -f - 2>&1); then
  fail "a pod was admitted with the wall unreachable: failurePolicy is not Fail"
fi
echo "$out" | sed 's/^/  | /'
echo "$out" | grep -qi "failed calling webhook" \
  || fail "the refusal was not the webhook being unreachable: $out"
note "admissions stop when the wall is down. That is the design, and it belongs in your runbook."

kubectl -n lex-system scale deploy/lex-k8s --replicas=1 >/dev/null
kubectl -n lex-system rollout status deploy/lex-k8s --timeout=180s >/dev/null
for i in $(seq 1 60); do
  sed 's/name: api/name: api-failclosed/' "$ROOT/demo/manifests/10-pod-within.yaml" \
    | kubectl apply -f - >/dev/null 2>&1 && break
  [ "$i" = "60" ] && fail "the wall came back but the pod is still refused"
  sleep 1
done
note "wall back up; the same pod is admitted again"

bold "8. the decision log is sealed"
# The chain alone is tamper-*evident* only against someone who cannot
# recompute it — and whoever can reach this volume can, because the
# hashes are derived. The seal is the part they cannot forge.
# A fresh pod name: step 7 restarted the Deployment, so the one captured
# in step 6 is gone.
POD=$(kubectl -n lex-system get pod -l app=lex-k8s -o jsonpath='{.items[0].metadata.name}')
# ...and a fresh *refusal*, because refusal-to-admission is the forgery
# worth demonstrating. Nobody rewrites a log to make themselves look
# worse.
kubectl apply -f "$ROOT/demo/manifests/11-pod-beyond.yaml" >/dev/null 2>&1 || true
CHAIN=$(kubectl -n lex-system exec "$POD" -- sh -c 'ls -t /audit | grep -v ledger.json | head -1' | tr -d '\r')
kubectl -n lex-system exec "$POD" -- cat "/audit/$CHAIN" > "$WORKDIR/decision.json"
"$LEXK8S" audit verify --log "$WORKDIR/decision.json" --trusted-key "$AUDIT_PK" | sed 's/^/  | /'

# And the attack: rewrite the verdict, rebuild the chain (free — the
# hashes are derived), and watch the chain accept it and the seal not.
python3 "$ROOT/demo/forge-verdict.py" "$WORKDIR/decision.json" "$WORKDIR/forged.json"
if "$LEXK8S" audit verify --log "$WORKDIR/forged.json" >/dev/null 2>&1; then
  note "the chain alone accepts the forged log — which is the whole point"
else
  fail "the forgery should be indistinguishable to the chain alone"
fi
if "$LEXK8S" audit verify --log "$WORKDIR/forged.json" --trusted-key "$AUDIT_PK" 2>&1 \
     | sed 's/^/  | /'; then
  fail "the seal must refuse a rewritten decision"
fi
note "sealed: a rewritten verdict passes the chain and fails the seal."

bold "9. a DELETED decision is named"
# Sealing proved nobody can rewrite a decision. It cannot prove one that
# happened still exists — a seal covers what a record says, never
# whether the record is still there. The ledger is the second record
# that counts them (alpibrusl/lex-k8s#13).
rm -rf "$WORKDIR/decisions"; mkdir -p "$WORKDIR/decisions"
for f in $(kubectl -n lex-system exec "$POD" -- sh -c 'ls /audit' | tr -d '\r'); do
  kubectl -n lex-system exec "$POD" -- cat "/audit/$f" > "$WORKDIR/decisions/$f"
done
"$LEXK8S" audit reconcile --ledger "$WORKDIR/decisions/ledger.json" \
  --decisions "$WORKDIR/decisions" --trusted-key "$AUDIT_PK" | sed 's/^/  | /'

# Now delete the refusal, the way anyone with the volume would.
VICTIM=$(ls -t "$WORKDIR/decisions" | grep -v ledger.json | head -1)
rm "$WORKDIR/decisions/$VICTIM"
note "deleted $VICTIM from the decision set"
if "$LEXK8S" audit reconcile --ledger "$WORKDIR/decisions/ledger.json" \
     --decisions "$WORKDIR/decisions" --trusted-key "$AUDIT_PK" 2>&1 | sed 's/^/  | /'; then
  fail "a deleted decision must be refused"
fi
note "the ledger names the gap. A seal could not have."

bold "10. what the restart cost the record"
AFTER=$(kubectl -n lex-system exec "$POD" -- sh -c 'ls /audit | grep -v ledger.json | wc -l' | tr -d ' \r')
note "before the restart: $CHAINS chains. After it: $AFTER."
[ "${AFTER:-0}" -lt "${CHAINS:-0}" ] \
  || fail "expected the restart to lose the local chains; this step is the honest one"
# Not a bug in this demo — the gap it exists to show, and the half that
# sealing does *not* close. Step 8 proved nobody can rewrite a decision.
# Nothing proves a decision that once existed still does: each admission
# gets its own chain, so a deleted file leaves no gap to notice, and a
# checkpoint cannot help — you cannot commit to the length of a set of
# files nobody is counting.
note "the earlier chains went with the pod — the ledger included, because it"
note "lives on the same volume. Sealing stops a rewrite and the ledger names a"
note "deletion, but neither survives the disk going away. What does survive is"
note "the signed checkpoint the wall prints on every append: a collector holds"
note "those, and a truncated ledger contradicts any one of them."

bold "the wall ran in a cluster."
note "Ten steps, no mock: a real API server called a real webhook over TLS,"
note "and every verdict came from the same admit()/narrow() the CLI calls."
