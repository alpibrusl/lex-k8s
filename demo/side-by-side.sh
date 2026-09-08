#!/usr/bin/env bash
# The same four changes, applied twice: to a namespace the wall governs
# and to one it does not.
#
# `demo/kind.sh` proves the wall refuses. It cannot show what refusing
# is worth, because there is nothing next to it that accepted. This runs
# both columns in one cluster so the difference is the wall and nothing
# else -- same manifests, same images, same API server, same second.
#
#   ./demo/side-by-side.sh          # create, run, tear down
#   KEEP=1 ./demo/side-by-side.sh   # leave the cluster up
#
# Requires: kind, kubectl, docker, openssl, python3, cargo.
set -euo pipefail

CLUSTER=${CLUSTER:-lex-k8s-sbs}
IMAGE=${IMAGE:-lex-k8s:dev}
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
KEEP=${KEEP:-0}
GATED=payments
OPEN=payments-open

bold() { printf '\n\033[1m%s\033[0m\n' "$*"; }
note() { printf '  %s\n' "$*"; }
fail() { printf '\n\033[31mFAILED: %s\033[0m\n' "$*" >&2; exit 1; }

cleanup() {
  rm -rf "${WORKDIR:-}"
  if [ "$KEEP" = "1" ]; then
    bold "cluster $CLUSTER left up. Delete with: kind delete cluster --name $CLUSTER"
  else
    kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

WORKDIR=$(mktemp -d)
cargo build --quiet --manifest-path "$ROOT/Cargo.toml"
LEXK8S="$ROOT/target/debug/lex-k8s"

bold "0. one cluster, the wall deployed"
kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
kind create cluster --name "$CLUSTER" >/dev/null 2>&1
docker build -t "$IMAGE" "$ROOT" >/dev/null 2>&1
kind load docker-image "$IMAGE" --name "$CLUSTER" >/dev/null 2>&1
kubectl apply -f "$ROOT/deploy/crd.yaml" >/dev/null
kubectl apply -f "$ROOT/deploy/namespace.yaml" >/dev/null
kubectl apply -f "$ROOT/deploy/rbac.yaml" >/dev/null
kubectl apply -f "$ROOT/deploy/service.yaml" >/dev/null
CA_BUNDLE=$(NS=lex-system SERVICE=lex-k8s "$ROOT/deploy/bootstrap-certs.sh")
AUDIT_SK=$(printf '07%.0s' $(seq 1 32))
kubectl -n lex-system delete secret lex-k8s-audit-key --ignore-not-found >/dev/null
kubectl -n lex-system create secret generic lex-k8s-audit-key --from-literal=audit.key="$AUDIT_SK" >/dev/null
kubectl apply -f "$ROOT/deploy/deployment.yaml" >/dev/null
kubectl -n lex-system rollout status deploy/lex-k8s --timeout=180s >/dev/null
python3 "$ROOT/demo/inject-ca.py" "$ROOT/deploy/webhook.yaml" "$CA_BUNDLE" | kubectl apply -f - >/dev/null
note "wall up, webhook registered (failurePolicy: Fail)"

bold "1. two namespaces, identical but for one label"
kubectl create ns "$GATED" >/dev/null 2>&1 || true
kubectl create ns "$OPEN"  >/dev/null 2>&1 || true
kubectl label ns "$GATED" lex.dev/gated=true --overwrite >/dev/null
kubectl label ns "$OPEN"  lex.dev/gated- >/dev/null 2>&1 || true
# The pods name a ServiceAccount; without it the API server refuses on
# its own grounds and both columns read "refused" for reasons that have
# nothing to do with the wall. The first run of this demo did exactly
# that, which is a good argument for reading the reason and not the
# verdict.
kubectl -n "$GATED" create serviceaccount api >/dev/null 2>&1 || true
kubectl -n "$OPEN"  create serviceaccount api >/dev/null 2>&1 || true
note "$GATED  lex.dev/gated=true   <- the wall decides here"
note "$OPEN   (no label)           <- the wall is not consulted"

for i in $(seq 1 60); do
  kubectl apply --dry-run=server -f "$ROOT/demo/manifests/00-platform.yaml" >/dev/null 2>&1 && break
  [ "$i" = 60 ] && fail "the webhook never became reachable"
  sleep 1
done

kubectl apply -f "$ROOT/demo/manifests/00-platform.yaml" >/dev/null
kubectl apply -f "$ROOT/demo/manifests/01-payments.yaml" >/dev/null
# Egress has to be *knowable* before it can be within a grant. With no
# NetworkPolicy the cluster permits the pod to reach anything, which is
# `network: full` -- wider than the parent's allowlist -- so even the
# well-behaved pod is refused. Applying this does not change the pod; it
# changes what the cluster will let the pod do, which is the thing the
# wall reads. Both namespaces get it, so the columns differ by the label
# and nothing else.
kubectl apply -f "$ROOT/demo/manifests/03-deny-all-egress.yaml" >/dev/null
sed "s/namespace: $GATED/namespace: $OPEN/" "$ROOT/demo/manifests/03-deny-all-egress.yaml" | kubectl apply -f - >/dev/null
note "ceiling + the team's narrowed grant + a knowable egress applied"

bold "2. the same two changes, applied to both"
printf '\n  %-38s  %-22s  %s\n' "CHANGE" "$OPEN (ungoverned)" "$GATED (governed)"
printf '  %-38s  %-22s  %s\n' "--------------------------------------" "----------------------" "------------------"

REASONS="$WORKDIR/reasons.txt"; : > "$REASONS"

try() {              # try <label> <manifest>
  local label="$1" src="$2" out_open out_gated res_open res_gated
  sed "s/namespace: $GATED/namespace: $OPEN/" "$src" > "$WORKDIR/open.yaml"
  if out_open=$(kubectl apply -f "$WORKDIR/open.yaml" 2>&1); then res_open="admitted"; else res_open="refused"; fi
  if out_gated=$(kubectl apply -f "$src" 2>&1); then res_gated="admitted"; else
    res_gated="REFUSED"
    printf '%s\n' "$label:" >> "$REASONS"
    printf '%s\n\n' "$(echo "$out_gated" | sed -n 's/.*denied the request: //p' | head -1)" >> "$REASONS"
  fi
  local c_open c_gated
  [ "$res_open" = "admitted" ] && c_open="\033[33m$res_open\033[0m" || c_open="$res_open"
  [ "$res_gated" = "REFUSED" ] && c_gated="\033[32m$res_gated\033[0m" || c_gated="\033[32m$res_gated\033[0m"
  printf "  %-38s  %-31b  %b\n" "$label" "$c_open" "$c_gated"
}

try "a pod inside the grant"                   "$ROOT/demo/manifests/10-pod-within.yaml"
try "privileged + hostPath + ungranted secret" "$ROOT/demo/manifests/11-pod-beyond.yaml"

bold "3. what the wall said, in its own words"
sed 's/^/  /' "$REASONS"

bold "4. what the ungoverned namespace is now running"
# The refusal is abstract until you look at what was admitted instead.
kubectl -n "$OPEN" get pod debug -o jsonpath='{range .spec.containers[*]}  privileged: {.securityContext.privileged}{"\n"}{end}' 2>/dev/null
kubectl -n "$OPEN" get pod debug -o jsonpath='{range .spec.volumes[*]}{.hostPath.path}{"\n"}{end}' 2>/dev/null \
  | grep -v '^$' | sed 's|^|  hostPath mounted: |'
kubectl -n "$OPEN" get pod debug -o jsonpath='{range .spec.containers[*].env[*]}  reads secret: {.valueFrom.secretKeyRef.name}{"\n"}{end}' 2>/dev/null
note "the same three reaches the governed namespace refused, live on the node"

bold "5. one thing the wall does that has no ungoverned column"
# LexManifests are gated cluster-wide, not by the namespace label: they
# ARE the authority, so a namespace cannot opt out of having its own
# ceiling checked. There is no "without" to compare against either --
# without lex-k8s the CRD does not exist, and nothing anywhere reads a
# parent. So it gets its own line rather than a misleading second column.
if out=$(kubectl apply -f "$ROOT/demo/manifests/02-widening.yaml" 2>&1); then
  fail "a widening manifest was admitted"
else
  note "a child grant wider than its parent: REFUSED"
  echo "$out" | sed -n 's/.*denied the request: //p' | head -1 | fold -s -w 76 | sed 's/^/    /'
fi

bold "6. the decision is evidence, not just an answer"
POD=$(kubectl -n lex-system get pod -l app=lex-k8s -o jsonpath='{.items[0].metadata.name}')
kubectl -n lex-system exec "$POD" -- sh -c 'ls /var/lib/lex-k8s/decisions 2>/dev/null | head -3' 2>/dev/null | sed 's/^/  /' || note "(decision store not mounted in this build)"
AUDIT_PK=$("$LEXK8S" audit pubkey --key "$AUDIT_SK")
note "decisions are sealed by ${AUDIT_PK:0:16}… — an operator verifies them with the public half alone"

bold "7. what this does NOT show"
cat <<'LIMITS' | sed 's/^/  /'
Admission-time only. The wall gates pods and LexManifests; it does not
gate NetworkPolicy or RBAC, so an admitted pod's reach can still be
widened afterwards without another admission (lex-k8s finding 4).

A manifest naming no parent is allowed by design, on the assumption
that cluster RBAC governs who may write a root. A namespace editor who
can update their own manifest can therefore remove `spec.parent` and
leave the narrowing behind (finding 1). Do not read the third row above
as proof that a child cannot escape its ceiling — it proves only that a
child which *keeps* its parent cannot widen against it.
LIMITS
