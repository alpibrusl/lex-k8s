//! `lex-k8s` — the admission wall, on the command line.
//!
//! ```sh
//! # what the API server would POST, decided locally
//! kubectl get pod api -o json | lex-k8s review --manifest payments.json \
//!     | lex-k8s admit --manifest payments.json --snapshot cluster.json
//!
//! lex-k8s admit --manifest m.json [--snapshot s.json] < review.json
//! lex-k8s compile --pod pod.json [--snapshot s.json]
//! lex-k8s manifest narrow --parent platform.json --child payments.json
//! ```
//!
//! Exit codes follow lex-os: `0` admitted, `8` refused, `2` the wall
//! could not run. The 8-versus-2 distinction is load-bearing — a
//! refusal is a decision, not a malfunction, and a pipeline that
//! conflates them will eventually read a broken wall as an admission.
//!
//! # The server is the same wall
//!
//! `admit` reads an `AdmissionReview` on stdin and writes the response
//! on stdout, which is exactly what a webhook does between its TLS
//! handshake and its HTTP reply. `lex-k8s serve` (feature `serve`) is
//! that wrapper: it resolves the manifest and the cluster snapshot from
//! watch caches instead of flags, and calls the same two functions.
//! Nothing decides in the server, so the fixture corpus still tests the
//! wall that actually runs.

use std::io::Read;
use std::process::ExitCode;

use lex_k8s::{
    admission::Spend, admit, narrow, reconcile, respond, review::cannot_run, AdmissionEvent,
    AdmissionReview, Chain, Checkpoint, ClusterSnapshot, Keyring, Ledger, LedgerEvent, LexManifest,
    PriceList, Reversibility, SigningKey, SpendReport, Standing, Verdict, VerifyingKey,
};

const USAGE: &str = "\
usage:
  lex-k8s admit    --manifest <LexManifest.json> [--snapshot <cluster.json>]
                   [--trusted-keys <keyring.json>] [--prices <prices.json>]
                   [--spend <spend.json>] [--audit-out <log.json>]
                   [--audit-key <hex> | --audit-key-file <path>] < review.json
  lex-k8s compile  --pod <pod.json> [--snapshot <cluster.json>]
  lex-k8s manifest narrow --parent <LexManifest.json> --child <LexManifest.json>
  lex-k8s audit verify --log <audit.json> [--trusted-key <hex>]...
  lex-k8s audit reconcile --ledger <ledger.json> --decisions <dir>
                   [--trusted-key <hex>]... [--checkpoint <cp.json>]
  lex-k8s audit pubkey [--key <hex> | --key-file <path>]
  lex-k8s serve    --cert <tls.crt> --key <tls.key> [--addr 0.0.0.0:8443]
                   [--trusted-keys <keyring.json>] [--prices <prices.json>]
                   [--spend <spend.json>] [--audit-dir <dir>]
                   [--audit-key-file <path>]
                   [--trusted-image-prefix <prefix>]... [--root-namespace <ns>]

`admit` reads an AdmissionReview on stdin and writes the response on stdout.
--trusted-keys takes the `{\"trusted\":[...]}` keyring written by
`lex producer-trust keyring --min-trust N`. A submitter that is not on it
is held to the narrower reading of the same manifest: waivers the
manifest grants — dimensions it declares no policy for — do not apply.
It never widens the manifest. The submitter is the API server's
authenticated `userInfo.username`, never a flag.

--prices and --spend enable the budget wall, and are only meaningful
together: --prices gives the cost of a core-month and a GiB-month, --spend
what the namespace already commits per month. The pod's own reservation is
computed from its `resources.requests`. Without both, no budget wall runs —
this refuses new admissions only, and never evicts a running pod.

--audit-out writes the hash-chained decision log, which is the input to
`lex attest import-apply --accepted pod_admitted --refused pod_refused`.

--audit-key/--audit-key-file seals every entry of that log with an Ed25519
key (lex-os#54). The hash chain is derived, so whoever can reach the file
can rewrite a refusal into an admission and recompute the hashes; the seal
is the part they cannot forge. `audit verify --trusted-key <public hex>`
is what checks it. Prefer the file: a secret in argv is a secret in `ps`.

Without --snapshot the cluster is read as having no NetworkPolicy, which in
Kubernetes means unrestricted egress — not none.

`audit reconcile` holds a ledger and a directory of decision chains to
each other, in both directions. A head the ledger witnesses with no file
behind it is a DELETED decision — which sealing cannot catch, because a
seal proves what a record says and not that the record still exists. A
file the ledger never witnessed is a planted one, or a ledger that lost
its tail. With --checkpoint it also catches a ledger truncated from the
end, which is the same attack one level up.

`serve` is the same wall behind TLS: POST /admit and POST /narrow, plus
/healthz and /readyz. The manifest governing a namespace and the cluster
snapshot come from watch caches rather than flags — the API server is
calling us inside its own request path, and calling back into it to
decide is a deadlock. /readyz stays 503 until every cache has listed
once, because an empty cache reads as \"no NetworkPolicy\", which means
unrestricted egress rather than none.

exit: 0 admitted, 8 refused, 2 the wall could not run";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    match refs.as_slice() {
        ["admit", rest @ ..] => cmd_admit(rest),
        ["compile", rest @ ..] => cmd_compile(rest),
        ["manifest", "narrow", rest @ ..] => cmd_narrow(rest),
        ["audit", "verify", rest @ ..] => cmd_audit_verify(rest),
        ["audit", "reconcile", rest @ ..] => cmd_audit_reconcile(rest),
        ["audit", "pubkey", rest @ ..] => cmd_audit_pubkey(rest),
        ["serve", rest @ ..] => cmd_serve(rest),
        ["--help"] | ["-h"] | [] => {
            println!("{USAGE}");
            ExitCode::from(0)
        }
        other => {
            eprintln!("unknown command: {}\n\n{USAGE}", other.join(" "));
            ExitCode::from(2)
        }
    }
}

/// Every value given for a flag, in order.
///
/// Both spellings: `--name value` and `--name=value`. The second is not
/// a nicety — it is how flags are written in a Kubernetes `args:` list,
/// where each element is one string, and a parser that only understood
/// the first would leave a Deployment printing its usage on a crash
/// loop with nothing to say why.
fn flags<'a>(args: &[&'a str], name: &str) -> Vec<&'a str> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = args[i];
        if a == name {
            if let Some(v) = args.get(i + 1) {
                out.push(*v);
            }
            i += 2;
            continue;
        }
        if let Some(rest) = a.strip_prefix(name) {
            if let Some(v) = rest.strip_prefix('=') {
                out.push(v);
            }
        }
        i += 1;
    }
    out
}

fn flag<'a>(args: &[&'a str], name: &str) -> Option<&'a str> {
    flags(args, name).into_iter().next()
}

fn read(path: &str) -> Result<String, ExitCode> {
    std::fs::read_to_string(path).map_err(|e| {
        eprintln!("could not read {path}: {e}");
        ExitCode::from(2)
    })
}

/// The snapshot, or the honest default.
///
/// Absent means **no NetworkPolicy selects the pod**, which Kubernetes
/// treats as unrestricted egress. Saying so out loud matters: an
/// operator who omits the flag should not think they have been given a
/// tighter answer than they have.
fn snapshot(args: &[&str]) -> Result<ClusterSnapshot, ExitCode> {
    match flag(args, "--snapshot") {
        None => {
            eprintln!(
                "note: no --snapshot, so the cluster is read as having no NetworkPolicy — \
                 which in Kubernetes means unrestricted egress, not none"
            );
            Ok(ClusterSnapshot::default())
        }
        Some(path) => {
            let src = read(path)?;
            serde_json::from_str(&src).map_err(|e| {
                eprintln!("could not read the snapshot {path}: {e}");
                ExitCode::from(2)
            })
        }
    }
}

/// Returns the resolved manifest and whether it *declared* a budget.
///
/// The second half matters only when the budget wall is running: a
/// manifest with no `budget` resolves to lex-os's default, whose
/// `max_money_cents` is **zero**. That is the right reading — a
/// manifest naming no budget authorises no spend, the same way an empty
/// allow-list grants nothing — but an operator who turns the wall on
/// and watches every pod get refused deserves to be told why rather
/// than left to work it out.
fn load_manifest(args: &[&str]) -> Result<(lex_os_manifest::Manifest, bool), ExitCode> {
    let Some(path) = flag(args, "--manifest") else {
        eprintln!("needs --manifest\n\n{USAGE}");
        return Err(ExitCode::from(2));
    };
    let src = read(path)?;
    LexManifest::read(&src)
        .map(|(crd, m)| {
            let declared = crd.spec.budget.is_some();
            (m, declared)
        })
        .map_err(|e| {
            eprintln!("could not read the LexManifest {path}: {e}");
            ExitCode::from(2)
        })
}

fn cmd_admit(args: &[&str]) -> ExitCode {
    let mut stdin = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut stdin) {
        eprintln!("could not read the AdmissionReview on stdin: {e}");
        return ExitCode::from(2);
    }

    // Read the review first: without a uid there is nothing to answer
    // to, and an untargeted response is one the API server discards.
    let review = match AdmissionReview::from_json(&stdin) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let request = match review.request() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };

    let (manifest, budget_declared) = match load_manifest(args) {
        Ok(m) => m,
        Err(c) => return c,
    };
    let snap = match snapshot(args) {
        Ok(s) => s,
        Err(c) => return c,
    };

    let keyring = match flag(args, "--trusted-keys") {
        None => None,
        Some(path) => {
            let src = match std::fs::read_to_string(path) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("could not read {path}: {e}");
                    return ExitCode::from(2);
                }
            };
            match Keyring::from_json(&src) {
                Ok(k) => {
                    if k.trusted.is_empty() {
                        eprintln!(
                            "warning: {path} trusts nobody, so no submitter gets the \
                             manifest's waivers"
                        );
                    }
                    Some(k)
                }
                Err(e) => {
                    eprintln!("could not read the keyring {path}: {e}");
                    return ExitCode::from(2);
                }
            }
        }
    };

    // The budget wall's two inputs are only meaningful together, so
    // half of it is a usage error rather than a silent half-check: a
    // pipeline that meant to enforce a budget and quietly did not is
    // worse off than one told what is missing.
    let spend = match (flag(args, "--prices"), flag(args, "--spend")) {
        (None, None) => None,
        (Some(_), None) | (None, Some(_)) => {
            eprintln!(
                "--prices and --spend go together: pricing a pod without knowing what \
                 the namespace already spends checks nothing\n\n{USAGE}"
            );
            return ExitCode::from(2);
        }
        (Some(p), Some(r)) => {
            if !budget_declared {
                eprintln!(
                    "warning: this LexManifest declares no `budget`, so it authorises \
                     no spend at all ({} minor units) and every priced pod will be \
                     refused — declare one, or drop --prices/--spend",
                    manifest.budget.max_money_cents
                );
            }
            let (prices_src, report_src) =
                match (std::fs::read_to_string(p), std::fs::read_to_string(r)) {
                    (Ok(a), Ok(b)) => (a, b),
                    (Err(e), _) => {
                        eprintln!("could not read {p}: {e}");
                        return ExitCode::from(2);
                    }
                    (_, Err(e)) => {
                        eprintln!("could not read {r}: {e}");
                        return ExitCode::from(2);
                    }
                };
            match (
                PriceList::from_json(&prices_src),
                SpendReport::from_json(&report_src),
            ) {
                (Ok(prices), Ok(report)) => Some(Spend { prices, report }),
                (Err(e), _) | (_, Err(e)) => {
                    eprintln!("{e}");
                    return ExitCode::from(2);
                }
            }
        }
    };

    let audit_key =
        match load_signing_key(flag(args, "--audit-key"), flag(args, "--audit-key-file")) {
            Ok(k) => k,
            Err(e) => {
                eprintln!("{e}");
                return ExitCode::from(2);
            }
        };

    let decision = match match &audit_key {
        Some(k) => lex_k8s::admit_sealed(
            &request.object_json(),
            &manifest,
            &snap,
            &request.meta(),
            keyring.as_ref(),
            spend.as_ref(),
            k,
        ),
        None => admit(
            &request.object_json(),
            &manifest,
            &snap,
            &request.meta(),
            keyring.as_ref(),
            spend.as_ref(),
        ),
    } {
        Ok(d) => d,
        Err(e) => {
            // Answer the API server rather than dying silently: with
            // `failurePolicy: Fail` a dead webhook and a 500 look the
            // same to the cluster, but only one of them says why.
            let out = cannot_run(&request.uid, &e.to_string());
            println!(
                "{}",
                serde_json::to_string_pretty(&out).expect("serialisable")
            );
            eprintln!("the wall could not run: {e}");
            return ExitCode::from(2);
        }
    };

    // Written before the response goes out, and a failure to write is
    // a failure of the wall: the promotion loop downstream reads this
    // file, and a decision nobody can keep is not a record.
    if let Some(path) = flag(args, "--audit-out") {
        match decision.audit.to_json() {
            Ok(json) => {
                if let Err(e) = std::fs::write(path, json) {
                    eprintln!("could not write the audit log {path}: {e}");
                    return ExitCode::from(2);
                }
            }
            Err(e) => {
                eprintln!("could not serialise the audit log: {e}");
                return ExitCode::from(2);
            }
        }
    }

    let out = respond(&request.uid, &decision);
    println!(
        "{}",
        serde_json::to_string_pretty(&out).expect("serialisable")
    );

    match &decision.verdict {
        Verdict::Admit => {
            eprintln!("ADMITTED  {}/{}", request.namespace, request.meta().name);
            for w in &decision.unchecked {
                eprintln!("  not checked: {w}");
            }
        }
        Verdict::Deny { all, .. } => {
            eprintln!(
                "REFUSED   {}/{} — {} wall(s) tripped",
                request.namespace,
                request.meta().name,
                all.len()
            );
            for r in all {
                eprintln!("  [{}] {}", r.wall.as_str(), r.effect);
                eprintln!("    at:     {}", r.source);
                eprintln!("    reason: {}", r.reason);
            }
        }
    }
    match decision.charged {
        Some(minor) => eprintln!(
            "spend:     this pod reserves {}.{:02} / month (forecast on requests, not a meter)",
            minor / 100,
            minor % 100
        ),
        None => eprintln!("spend:     unpriced — no --prices/--spend"),
    }
    match (&decision.signer, decision.standing) {
        (None, Standing::NotConsulted) => eprintln!("submitter: unauthenticated"),
        (None, _) => eprintln!("submitter: unauthenticated (no earned standing)"),
        (Some(w), Standing::NotConsulted) => eprintln!("submitter: {w} (trust not consulted)"),
        (Some(w), Standing::Trusted) => eprintln!("submitter: {w} (in the trusted keyring)"),
        (Some(w), Standing::Unknown) => {
            eprintln!("submitter: {w} (not in the trusted keyring — no waivers)")
        }
    }
    eprintln!(
        "audit: {} entries, head sha256:{}{}",
        decision.audit.len(),
        decision.audit.head(),
        if decision.audit.sealed_count() == decision.audit.len() && !decision.audit.is_empty() {
            " (sealed)"
        } else {
            " (UNSEALED — anyone who can reach the file can rewrite it)"
        }
    );
    ExitCode::from(decision.exit_code() as u8)
}

fn cmd_compile(args: &[&str]) -> ExitCode {
    let Some(pod_path) = flag(args, "--pod") else {
        eprintln!("compile needs --pod\n\n{USAGE}");
        return ExitCode::from(2);
    };
    let src = match read(pod_path) {
        Ok(s) => s,
        Err(c) => return c,
    };
    let snap = match snapshot(args) {
        Ok(s) => s,
        Err(c) => return c,
    };

    let pod = match lex_k8s::compile_str(&src, &snap) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("could not read {pod_path}: {e}");
            return ExitCode::from(2);
        }
    };

    println!("spec:   sha256:{}", pod.spec_sha256);
    println!("state:  sha256:{}", pod.snapshot_sha256);
    println!();
    println!("{:<50} {:<44} CLASS", "SOURCE", "EFFECT");
    for row in &pod.rows {
        let class = match row.reversibility {
            Reversibility::ReversibleCheap => "cheap",
            Reversibility::IrreversibleBounded => "bounded",
            Reversibility::IrreversibleConsequential => "CONSEQUENTIAL",
        };
        println!(
            "{:<50} {:<44} {class}",
            row.source.to_string(),
            row.effect.name()
        );
    }
    println!("\nthis pod demands:");
    println!("  filesystem: {:?}", pod.demands.filesystem);
    println!("  network:    {:?}", pod.demands.network);
    println!("  exec:       {:?}", pod.demands.exec);
    ExitCode::from(0)
}

fn cmd_narrow(args: &[&str]) -> ExitCode {
    let (Some(parent_path), Some(child_path)) = (flag(args, "--parent"), flag(args, "--child"))
    else {
        eprintln!("manifest narrow needs --parent and --child\n\n{USAGE}");
        return ExitCode::from(2);
    };
    let (parent_src, child_src) = match (read(parent_path), read(child_path)) {
        (Ok(p), Ok(c)) => (p, c),
        (Err(c), _) | (_, Err(c)) => return c,
    };

    let read_one = |src: &str, path: &str| {
        LexManifest::read(src).map_err(|e| {
            eprintln!("could not read {path}: {e}");
            ExitCode::from(2)
        })
    };
    let (parent, child) = match (
        read_one(&parent_src, parent_path),
        read_one(&child_src, child_path),
    ) {
        (Ok((_, p)), Ok((_, c))) => (p, c),
        (Err(c), _) | (_, Err(c)) => return c,
    };

    match narrow(&parent, &child) {
        Ok(()) => {
            println!("ACCEPTED — the child narrows its parent.");
            println!("  parent: {}", parent.content_id());
            println!("  child:  {}", child.content_id());
            ExitCode::from(0)
        }
        Err(e) => {
            println!("REFUSED — the child widens its parent.");
            println!("  {e}");
            println!(
                "\nA team lead hands out authority they hold, never authority they\n\
                 do not. This is the wall a constraint language has nowhere to put."
            );
            ExitCode::from(8)
        }
    }
}

/// `serve`, when the feature is on.
#[cfg(feature = "serve")]
fn cmd_serve(args: &[&str]) -> ExitCode {
    use std::path::PathBuf;

    let (Some(cert), Some(key)) = (flag(args, "--cert"), flag(args, "--key")) else {
        eprintln!("serve needs --cert and --key\n\n{USAGE}");
        return ExitCode::from(2);
    };
    let addr = match flag(args, "--addr") {
        None => None,
        Some(a) => match a.parse() {
            Ok(a) => Some(a),
            Err(e) => {
                eprintln!("--addr {a} is not an address: {e}");
                return ExitCode::from(2);
            }
        },
    };
    // Repeatable, because a cluster can trust more than one registry
    // and an operator should not have to encode a list into one flag.
    let trusted_image_prefixes: Vec<String> = flags(args, "--trusted-image-prefix")
        .into_iter()
        .map(str::to_string)
        .collect();

    let opts = lex_k8s::serve::Options {
        addr,
        cert: PathBuf::from(cert),
        key: PathBuf::from(key),
        trusted_keys: flag(args, "--trusted-keys").map(PathBuf::from),
        prices: flag(args, "--prices").map(PathBuf::from),
        spend: flag(args, "--spend").map(PathBuf::from),
        audit_dir: flag(args, "--audit-dir").map(PathBuf::from),
        audit_key_file: flag(args, "--audit-key-file").map(PathBuf::from),
        trusted_image_prefixes,
        root_namespace: flag(args, "--root-namespace").map(str::to_string),
    };

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "lex_k8s=info,kube=warn".into()),
        )
        .init();

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("could not start the runtime: {e}");
            return ExitCode::from(2);
        }
    };
    match runtime.block_on(lex_k8s::serve::run(opts)) {
        Ok(()) => ExitCode::from(0),
        Err(e) => {
            eprintln!("serve: {e}");
            ExitCode::from(2)
        }
    }
}

/// `serve`, when it was not built.
///
/// It says so rather than doing something weaker. A binary that
/// silently lacked its server would be discovered by an operator whose
/// admissions had stopped — which is the same "refuse, don't downgrade"
/// rule the simulated perimeter follows in lex-os.
#[cfg(not(feature = "serve"))]
fn cmd_serve(_args: &[&str]) -> ExitCode {
    eprintln!(
        "this lex-k8s was built without the `serve` feature, so it has no server.\n\
         Build it with `cargo build --release --features serve`, or use `admit` on \n\
         stdin — the decision is identical either way."
    );
    ExitCode::from(2)
}

/// `audit reconcile` — the ledger and the decisions, held to each other.
///
/// Sealing (#12) proves nobody rewrote a decision. It cannot prove a
/// decision that happened still exists: a seal covers what a record
/// says, not whether the record is still there. Only a second record
/// that counted them can do that.
fn cmd_audit_reconcile(args: &[&str]) -> ExitCode {
    let (Some(ledger_path), Some(dir)) = (flag(args, "--ledger"), flag(args, "--decisions")) else {
        eprintln!("audit reconcile needs --ledger and --decisions\n\n{USAGE}");
        return ExitCode::from(2);
    };
    let src = match read(ledger_path) {
        Ok(s) => s,
        Err(c) => return c,
    };
    let ledger: Ledger = match Chain::from_json(&src) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("could not read the ledger {ledger_path}: {e}");
            return ExitCode::from(2);
        }
    };
    if let Err(e) = ledger.verify() {
        println!("REFUSED — the ledger's own chain is broken.");
        println!("  {e}");
        return ExitCode::from(8);
    }

    // A ledger that does not begin at `wall_started` was truncated from
    // the front, and the chain cannot see that: a suffix re-chained
    // from GENESIS is well-formed. The first entry is the one position
    // the hash chain structurally cannot defend.
    match ledger.entries().first().map(|e| &e.event) {
        Some(LedgerEvent::WallStarted { .. }) => {}
        Some(other) => {
            println!("REFUSED — the ledger does not begin where a ledger begins.");
            println!(
                "  first entry is `{}`, not `wall_started`.",
                other.subject()
            );
            println!("  A chain re-based from its second entry verifies perfectly; this is");
            println!("  the one position the hashes cannot defend, so it is checked by name.");
            return ExitCode::from(8);
        }
        None => {
            println!("REFUSED — the ledger is empty, which no running wall ever writes.");
            return ExitCode::from(8);
        }
    }

    let trusted_hex = flags(args, "--trusted-key");
    let mut trusted = Vec::new();
    for h in &trusted_hex {
        match decode_key32(h).and_then(|b| {
            VerifyingKey::from_bytes(&b).map_err(|_| format!("`{h}` is not an Ed25519 public key"))
        }) {
            Ok(k) => trusted.push(k),
            Err(e) => {
                eprintln!("--trusted-key {e}");
                return ExitCode::from(2);
            }
        }
    }
    if !trusted.is_empty() {
        if let Err(e) = ledger.verify_seals(&trusted) {
            println!("REFUSED — the ledger's seals do not hold.");
            println!("  {e}");
            return ExitCode::from(8);
        }
    }

    // The truncation wall, one level up: a checkpoint the wall printed
    // to stdout, kept by a collector the pod does not own.
    if let Some(cp_path) = flag(args, "--checkpoint") {
        if trusted.is_empty() {
            eprintln!(
                "--checkpoint needs --trusted-key: a checkpoint nobody vouched for is one \
                 the ledger's own holder could have written"
            );
            return ExitCode::from(2);
        }
        let cp_src = match read(cp_path) {
            Ok(s) => s,
            Err(c) => return c,
        };
        let cp: Checkpoint = match serde_json::from_str(&cp_src) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("could not read the checkpoint {cp_path}: {e}");
                return ExitCode::from(2);
            }
        };
        let Some(verified) = trusted.iter().find_map(|k| cp.verify(k).ok()) else {
            println!("REFUSED — the checkpoint is not signed by any trusted key.");
            return ExitCode::from(8);
        };
        if let Err(e) = ledger.verify_against(&verified) {
            println!("REFUSED — the ledger contradicts a checkpoint.");
            println!("  {e}");
            return ExitCode::from(8);
        }
        println!(
            "checkpoint: OK — the ledger is at least the {} entries committed to.",
            verified.as_checkpoint().len
        );
    }

    // Every decision chain the directory actually holds.
    let mut found: Vec<String> = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("could not read the decisions directory {dir}: {e}");
            return ExitCode::from(2);
        }
    };
    for entry in entries.flatten() {
        let path = entry.path();
        // The ledger lives in the same directory and is not a decision.
        if path.file_name().and_then(|n| n.to_str()) == Some("ledger.json") {
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        match Chain::<AdmissionEvent>::from_json(&text) {
            Ok(c) => found.push(c.head()),
            Err(e) => {
                println!("REFUSED — {} is not a decision chain: {e}", path.display());
                return ExitCode::from(8);
            }
        }
    }

    let r = reconcile(&ledger, &found);
    println!(
        "ledger: {} entries, head sha256:{}",
        ledger.len(),
        ledger.head()
    );
    println!("matched: {} decision(s) witnessed and present", r.matched);
    if r.is_clean() {
        println!("\nACCEPTED — every witnessed decision is present, and every present");
        println!("decision was witnessed.");
        return ExitCode::from(0);
    }
    println!("\nREFUSED — the ledger and the decisions disagree.");
    for h in &r.missing {
        println!("  DELETED?    witnessed head {h} has no file behind it");
    }
    for h in &r.unwitnessed {
        println!("  UNWITNESSED file with head {h} that the ledger never recorded");
    }
    println!(
        "\nA missing file is the attack sealing cannot catch: a seal proves what a\n\
         record says, never that the record is still there."
    );
    ExitCode::from(8)
}

/// `audit pubkey` — the public half of an audit signing key.
///
/// An operator seals with the secret and verifies with the public key,
/// and those are different 32-byte hex strings. Deriving it here beats
/// having them keep track of a pair by hand, or — worse — reach for the
/// secret when a verifier asks for a key.
fn cmd_audit_pubkey(args: &[&str]) -> ExitCode {
    match load_signing_key(flag(args, "--key"), flag(args, "--key-file")) {
        Ok(Some(k)) => {
            println!("{}", hex::encode(k.verifying_key().to_bytes()));
            ExitCode::from(0)
        }
        Ok(None) => {
            eprintln!("audit pubkey needs --key or --key-file\n\n{USAGE}");
            ExitCode::from(2)
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(2)
        }
    }
}

/// Read a 32-byte hex signing key from a flag or a file.
///
/// Both spellings, and the file is the one to use: a secret in argv is a
/// secret in `ps` output and in shell history, and an audit key that
/// leaks is an audit log anyone can re-sign.
fn load_signing_key(
    key: Option<&str>,
    key_file: Option<&str>,
) -> Result<Option<SigningKey>, String> {
    let hex_key = match (key, key_file) {
        (None, None) => return Ok(None),
        (Some(k), _) => k.to_string(),
        (None, Some(p)) => std::fs::read_to_string(p)
            .map_err(|e| format!("cannot read {p}: {e}"))?
            .trim()
            .to_string(),
    };
    decode_key32(&hex_key).map(|b| Some(SigningKey::from_bytes(&b)))
}

fn decode_key32(hex_key: &str) -> Result<[u8; 32], String> {
    hex::decode(hex_key.trim())
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .ok_or_else(|| format!("`{hex_key}` is not 32 hex-encoded bytes"))
}

/// `audit verify` — the chain always, the seals when you supply a key.
///
/// Two walls, reported separately, because they catch different things
/// and a single `verified: true` would let a reader believe the log was
/// held to one nobody asked for:
///
/// - the **chain** catches an edited payload and a reordered entry, but
///   not a holder who edits and then recomputes every hash;
/// - the **seals** catch exactly that holder.
///
/// Supplying no key checks no seals, and says so rather than passing.
fn cmd_audit_verify(args: &[&str]) -> ExitCode {
    let Some(path) = flag(args, "--log") else {
        eprintln!("audit verify needs --log\n\n{USAGE}");
        return ExitCode::from(2);
    };
    let src = match read(path) {
        Ok(s) => s,
        Err(c) => return c,
    };
    let log: Chain<AdmissionEvent> = match Chain::from_json(&src) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("could not read the audit log {path}: {e}");
            return ExitCode::from(2);
        }
    };

    if let Err(e) = log.verify() {
        println!("REFUSED — the hash chain is broken.");
        println!("  {e}");
        return ExitCode::from(8);
    }

    let trusted_hex = flags(args, "--trusted-key");
    if trusted_hex.is_empty() {
        println!(
            "chain:  OK — {} entries, head sha256:{}",
            log.len(),
            log.head()
        );
        // Not a pass. A log whose seals nobody checked is not a log
        // whose seals passed, and on this wall the file lives inside the
        // pod it audits.
        println!(
            "seals:  NOT CHECKED — {} of {} entries carry one.",
            log.sealed_count(),
            log.len()
        );
        println!("        Pass --trusted-key <hex> to hold them to it.");
        return ExitCode::from(0);
    }

    let mut trusted = Vec::new();
    for h in &trusted_hex {
        match decode_key32(h).and_then(|b| {
            VerifyingKey::from_bytes(&b).map_err(|_| format!("`{h}` is not an Ed25519 public key"))
        }) {
            Ok(k) => trusted.push(k),
            Err(e) => {
                eprintln!("--trusted-key {e}");
                return ExitCode::from(2);
            }
        }
    }

    match log.verify_seals(&trusted) {
        Ok(()) => {
            println!(
                "chain:  OK — {} entries, head sha256:{}",
                log.len(),
                log.head()
            );
            println!("seals:  OK — every entry sealed by a trusted key.");
            ExitCode::from(0)
        }
        Err(e) => {
            println!("REFUSED — the seals do not hold.");
            println!("  {e}");
            println!(
                "\nA broken seal on an intact chain is the interesting case: it means \n\
                 somebody edited the log and recomputed the hashes. That is what the \n\
                 chain alone cannot see."
            );
            ExitCode::from(8)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::flags;

    /// Both spellings, and repeats of either. The `=` form is what a
    /// Kubernetes `args:` list gives you, and the space form is what a
    /// person types; a flag parser that took only one of them fails in
    /// whichever context it was not tested in.
    #[test]
    fn flags_read_both_spellings() {
        let args = [
            "--cert=/tls/tls.crt",
            "--key",
            "/tls/tls.key",
            "--trusted-image-prefix=registry.internal/",
            "--trusted-image-prefix",
            "ghcr.io/alpibrusl/",
        ];
        assert_eq!(flags(&args, "--cert"), vec!["/tls/tls.crt"]);
        assert_eq!(flags(&args, "--key"), vec!["/tls/tls.key"]);
        assert_eq!(
            flags(&args, "--trusted-image-prefix"),
            vec!["registry.internal/", "ghcr.io/alpibrusl/"]
        );
        assert!(flags(&args, "--audit-dir").is_empty());
    }

    /// A prefix is not a flag: `--audit` must not match `--audit-dir`,
    /// or a typo silently configures something else.
    #[test]
    fn a_prefix_of_a_flag_is_not_that_flag() {
        let args = ["--audit-dir=/audit"];
        assert!(flags(&args, "--audit").is_empty());
        assert_eq!(flags(&args, "--audit-dir"), vec!["/audit"]);
    }

    /// A flag with nothing after it yields nothing rather than
    /// swallowing the next flag as its value.
    #[test]
    fn a_trailing_flag_has_no_value() {
        assert!(flags(&["--cert"], "--cert").is_empty());
    }
}
