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
//! # There is no server here
//!
//! `admit` reads an `AdmissionReview` on stdin and writes the response
//! on stdout, which is exactly what a webhook does between its TLS
//! handshake and its HTTP reply. Wiring that up needs certificates, a
//! `ValidatingWebhookConfiguration` and a cluster to test against; the
//! deployment manifests are in `deploy/`, and the serving binary is
//! deliberately not in this milestone rather than shipped untested.

use std::io::Read;
use std::process::ExitCode;

use lex_k8s::{
    admit, narrow, respond, review::cannot_run, AdmissionReview, ClusterSnapshot, Keyring,
    LexManifest, Reversibility, Standing, Verdict,
};

const USAGE: &str = "\
usage:
  lex-k8s admit    --manifest <LexManifest.json> [--snapshot <cluster.json>]
                   [--trusted-keys <keyring.json>] [--audit-out <log.json>] < review.json
  lex-k8s compile  --pod <pod.json> [--snapshot <cluster.json>]
  lex-k8s manifest narrow --parent <LexManifest.json> --child <LexManifest.json>

`admit` reads an AdmissionReview on stdin and writes the response on stdout.
--trusted-keys takes the `{\"trusted\":[...]}` keyring written by
`lex producer-trust keyring --min-trust N`. A submitter that is not on it
is held to the narrower reading of the same manifest: waivers the
manifest grants — dimensions it declares no policy for — do not apply.
It never widens the manifest. The submitter is the API server's
authenticated `userInfo.username`, never a flag.

--audit-out writes the hash-chained decision log, which is the input to
`lex attest import-apply --accepted pod_admitted --refused pod_refused`.

Without --snapshot the cluster is read as having no NetworkPolicy, which in
Kubernetes means unrestricted egress — not none.

exit: 0 admitted, 8 refused, 2 the wall could not run";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    match refs.as_slice() {
        ["admit", rest @ ..] => cmd_admit(rest),
        ["compile", rest @ ..] => cmd_compile(rest),
        ["manifest", "narrow", rest @ ..] => cmd_narrow(rest),
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

fn flag<'a>(args: &[&'a str], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| *a == name)
        .and_then(|i| args.get(i + 1))
        .copied()
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

fn load_manifest(args: &[&str]) -> Result<lex_os_manifest::Manifest, ExitCode> {
    let Some(path) = flag(args, "--manifest") else {
        eprintln!("needs --manifest\n\n{USAGE}");
        return Err(ExitCode::from(2));
    };
    let src = read(path)?;
    LexManifest::read(&src).map(|(_, m)| m).map_err(|e| {
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

    let manifest = match load_manifest(args) {
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

    let decision = match admit(
        &request.object_json(),
        &manifest,
        &snap,
        &request.meta(),
        keyring.as_ref(),
    ) {
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
        "audit: {} entries, head sha256:{}",
        decision.audit.len(),
        decision.audit.head()
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
