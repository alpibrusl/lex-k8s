# Deploying the wall

Applying this directory is not enough on its own, and the two things it
does not do are both silent. Found by deploying to a live k3s cluster
rather than to kind (#15).

## Order

```sh
# 1. The audit signing key. deployment.yaml MOUNTS this secret; nothing
#    here creates it. Without it the pod sits in ContainerCreating and
#    kubelet retries the mount forever -- no event surfaces unless you
#    `kubectl describe pod`.
kubectl -n lex-system create secret generic lex-k8s-audit-key \
  --from-literal=audit.key="$(openssl rand -hex 32)"

kubectl apply -f crd.yaml -f namespace.yaml -f rbac.yaml -f service.yaml

# 2. The serving certificate, and the CA the API server will check it
#    against. Both come from one mint; see the hazard below.
CA=$(NS=lex-system SERVICE=lex-k8s ./bootstrap-certs.sh)

kubectl apply -f deployment.yaml
kubectl -n lex-system rollout status deploy/lex-k8s

# 3. The webhook LAST, once the wall is serving. `failurePolicy: Fail`
#    means registering it before the wall is up stops admissions in
#    every gated namespace -- including, on a bad day, the wall's own
#    restart.
python3 ../demo/inject-ca.py webhook.yaml "$CA" | kubectl apply -f -
```

## The cert hazard

`bootstrap-certs.sh` mints a **new** CA every run. Running it again after
the wall is deployed leaves the pod serving the old certificate while the
webhook carries the new CA, and then every admission in a gated namespace
fails with:

```
failed calling webhook "pods.lex.dev": tls: failed to verify certificate:
  x509: certificate signed by unknown authority
```

That error names TLS and says nothing about the wall, so it reads like a
networking problem. If you re-mint, restart the deployment **and**
re-inject the caBundle from the same mint.

## What an outage costs

`failurePolicy: Fail` with the opt-in `namespaceSelector` means a wall
that is down blocks pod creation in **gated namespaces only**. Measured
with the deployment scaled to zero: a pod in a gated namespace is
refused (`failed calling webhook`), one in an ungated namespace is
admitted. The blast radius is the namespaces you opted in, not the
cluster.

That is a property of the opt-in selector. An exclusion-list design has
a different answer, and a worse one.
