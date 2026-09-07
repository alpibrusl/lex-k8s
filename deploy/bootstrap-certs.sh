#!/usr/bin/env bash
# Mint a self-signed serving certificate for the webhook and wire its CA
# into the ValidatingWebhookConfiguration.
#
# A real deployment uses cert-manager, which also rotates. This exists so
# the demo needs nothing but openssl and kubectl — and because a webhook
# whose certificate the API server does not trust fails closed, which
# with `failurePolicy: Fail` means every admission in the cluster stops.
# That failure is worth being able to reproduce on a laptop.
set -euo pipefail

NS=${NS:-lex-system}
SERVICE=${SERVICE:-lex-k8s}
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

DNS="${SERVICE}.${NS}.svc"

openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
  -keyout "$WORK/ca.key" -out "$WORK/ca.crt" \
  -subj "/CN=lex-k8s-ca" >/dev/null 2>&1

openssl req -newkey rsa:2048 -nodes \
  -keyout "$WORK/tls.key" -out "$WORK/tls.csr" \
  -subj "/CN=${DNS}" >/dev/null 2>&1

# The SAN is what the API server actually checks. A certificate with the
# name only in the subject is one modern Go will refuse, and the refusal
# arrives as a TLS error in the kube-apiserver log rather than anywhere
# obvious.
cat > "$WORK/san.cnf" <<EOF
subjectAltName = DNS:${DNS}, DNS:${SERVICE}.${NS}.svc.cluster.local, DNS:${SERVICE}.${NS}
extendedKeyUsage = serverAuth
EOF

openssl x509 -req -in "$WORK/tls.csr" -CA "$WORK/ca.crt" -CAkey "$WORK/ca.key" \
  -CAcreateserial -out "$WORK/tls.crt" -days 3650 \
  -extfile "$WORK/san.cnf" >/dev/null 2>&1

kubectl -n "$NS" delete secret lex-k8s-tls --ignore-not-found >/dev/null
kubectl -n "$NS" create secret tls lex-k8s-tls \
  --cert="$WORK/tls.crt" --key="$WORK/tls.key" >/dev/null

CA_BUNDLE=$(base64 < "$WORK/ca.crt" | tr -d '\n')
echo "$CA_BUNDLE"
