//! What a pod is actually asking for.
//!
//! ```sh
//! cargo run --example compile_pod -- pod.json [snapshot.json]
//! cargo run --example compile_pod          # the built-in demo
//! ```
//!
//! With no arguments it runs the case milestone 2 exists to refuse: a
//! pod whose spec is exemplary and whose annotation claims a narrow
//! egress, on a cluster where a forgotten `legacy-allow-all`
//! NetworkPolicy also selects it.

use lex_k8s::{compile_str, ClusterSnapshot, Effect, EffectRow, Grant, Level, Reversibility};

const DEMO_POD: &str = include_str!("../tests/fixtures/lying_about_egress.json");
const DEMO_HONEST: &str = include_str!("../tests/fixtures/snapshot_locked_down.json");
const DEMO_LIE: &str = include_str!("../tests/fixtures/snapshot_policy_is_a_lie.json");

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [] => demo(),
        [pod] => report(
            &read(pod),
            &ClusterSnapshot::default(),
            pod,
            "(no snapshot)",
        ),
        [pod, snap] => {
            let snapshot: ClusterSnapshot = match serde_json::from_str(&read(snap)) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("could not read the snapshot {snap}: {e}");
                    std::process::exit(2);
                }
            };
            report(&read(pod), &snapshot, pod, snap);
        }
        _ => {
            eprintln!("usage: compile_pod [pod.json [snapshot.json]]");
            std::process::exit(2);
        }
    }
}

fn read(path: &str) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("could not read {path}: {e}");
        std::process::exit(2);
    })
}

/// The same pod, on two clusters. Nothing about the spec changes.
fn demo() {
    println!("The same pod. Two clusters. One of them admits it.\n");

    // The namespace's grant: read a Secret, reach the internal network,
    // no exec escapes. What an operator would write for a metrics
    // exporter.
    let granted = Grant::new(Level::ReadOnly, Level::Allowlist, Level::Sandboxed);
    println!("namespace grant:  {granted:?}\n");

    for (label, snap) in [
        ("a cluster with one egress policy", DEMO_HONEST),
        ("...and one with a forgotten legacy-allow-all", DEMO_LIE),
    ] {
        let snapshot: ClusterSnapshot = serde_json::from_str(snap).expect("fixture parses");
        let pod = compile_str(DEMO_POD, &snapshot).expect("fixture parses");

        println!("{label}");
        println!("  spec:      sha256:{}", &pod.spec_sha256[..16]);
        println!("  snapshot:  sha256:{}", &pod.snapshot_sha256[..16]);
        println!("  demands:   {:?}", pod.demands);
        match pod.within(&granted) {
            Ok(()) => println!("  verdict:   ADMITTED"),
            Err(e) => {
                println!("  verdict:   REFUSED");
                println!("             {e}");
                if let Some(row) = worst_egress(&pod.rows) {
                    println!("             {}", row.effect.explain());
                }
            }
        }
        println!();
    }

    println!(
        "The pod's own annotation says `lex.dev/egress: metrics.internal:9090`.\n\
         An annotation is a claim; a NetworkPolicy is the wall. The compiler\n\
         reports what the cluster enforces, which is why the second answer is no."
    );
}

fn worst_egress(rows: &[EffectRow]) -> Option<&EffectRow> {
    rows.iter()
        .find(|r| matches!(r.effect, Effect::Egress { .. }))
}

fn report(src: &str, snapshot: &ClusterSnapshot, pod_path: &str, snap_path: &str) {
    let pod = match compile_str(src, snapshot) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("could not read {pod_path}: {e}");
            std::process::exit(2);
        }
    };

    println!("pod:       {pod_path}");
    println!("snapshot:  {snap_path}");
    println!("spec:      sha256:{}", pod.spec_sha256);
    println!("state:     sha256:{}", pod.snapshot_sha256);
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

    let worst = pod.rows_at(Reversibility::IrreversibleConsequential);
    if !worst.is_empty() {
        println!("\nwhat outlives the pod:");
        for row in worst {
            println!("  {}", row.source);
            println!("    {}", row.effect.explain());
        }
    }

    let unreadable = pod.unreadable();
    if !unreadable.is_empty() {
        println!("\nread at their widest, because this build could not read them:");
        for row in unreadable {
            println!("  {} — {}", row.source, row.effect.explain());
        }
    }
}
