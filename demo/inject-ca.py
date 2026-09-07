"""Put the CA that signed the serving certificate into both webhook entries.

A `ValidatingWebhookConfiguration` with no `caBundle` is not
unconfigured — it is configured to verify the webhook against the API
server's own trust roots, which fails as "certificate signed by unknown
authority". Getting one of the two entries and not the other is worse
still: half the wall works, and the half that does not fails on a call
the operator did not know was being made.

So the count is asserted rather than assumed.

    python3 demo/inject-ca.py deploy/webhook.yaml "$CA_BUNDLE" | kubectl apply -f -
"""

import sys

PLACEHOLDER = "      # caBundle: <injected by cert-manager, or `kubectl` after you mint one>"

src, ca = open(sys.argv[1]).read(), sys.argv[2]
found = src.count(PLACEHOLDER)
if found != 2:
    sys.exit(f"expected 2 caBundle placeholders in {sys.argv[1]}, found {found}")
print(src.replace(PLACEHOLDER, f"      caBundle: {ca}"))
