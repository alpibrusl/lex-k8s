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
  if [ "$KEEP" = "1" ]; then
    bold "cluster $CLUSTER left up (KEEP=1). Delete it with: kind delete cluster --name $CLUSTER"
  else
    kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

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
CHAINS=$(kubectl -n lex-system exec "$POD" -- sh -c 'ls /audit | wc -l' | tr -d ' \r')
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

bold "8. what the restart cost the record"
NEW_POD=$(kubectl -n lex-system get pod -l app=lex-k8s -o jsonpath='{.items[0].metadata.name}')
AFTER=$(kubectl -n lex-system exec "$NEW_POD" -- sh -c 'ls /audit | wc -l' | tr -d ' \r')
note "before the restart: $CHAINS chains. After it: $AFTER."
[ "${AFTER:-0}" -lt "${CHAINS:-0}" ] \
  || fail "expected the restart to lose the local chains; this step is the honest one"
# Not a bug in this demo — the gap it exists to show. The chain is
# tamper-evident but locally persisted and unsigned, so a pod that
# restarts (or is compromised) takes its own history with it. Fixing it
# means signed entries and storage the box cannot reach, which is
# alpibrusl/lex-os#54, upstream, where both gates get it at once.
note "the earlier chains went with the pod. Tamper-evident is not tamper-proof when"
note "the log lives inside the thing it is auditing — alpibrusl/lex-os#54."
note "The heads printed on stdout above are the part a collector keeps today."

bold "the wall ran in a cluster."
note "Eight steps, no mock: a real API server called a real webhook over TLS,"
note "and every verdict came from the same admit()/narrow() the CLI calls."
