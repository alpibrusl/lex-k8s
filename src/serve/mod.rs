//! `lex-k8s serve` — the wall, behind TLS (alpibrusl/lex-k8s#10).
//!
//! Milestones 1–4 decided correctly against real `AdmissionReview`
//! documents on stdin. This is the wrapper the API server talks to, and
//! it is deliberately thin: it resolves the inputs the CLI takes as
//! flags out of watch caches, and calls the same [`crate::admit`] and
//! [`crate::narrow`]. Nothing decides here.
//!
//! # Why this is a feature, not the default build
//!
//! Serving needs an HTTP stack, a TLS terminator and a Kubernetes
//! client. The decision half needs serde. Keeping them apart means the
//! library stays cheap to depend on, and — more to the point — that
//! the fixture corpus still tests the wall that actually runs, because
//! there is only one of it.
//!
//! # What this does not do
//!
//! - **One replica, no leader election.** A second replica is another
//!   cache, and two caches can disagree for a moment. Honest for a
//!   demo; say so in the README rather than half-building HA.
//! - **Certificates are read from disk, not minted or rotated.** A real
//!   deployment uses cert-manager; `deploy/bootstrap-certs.sh` mints a
//!   self-signed pair so the demo needs nothing but `openssl`.
//! - **The audit chain is written locally.** That is the weakness
//!   alpibrusl/lex-os#54 raises, and it is worse in a Pod than on a
//!   laptop. Unfixed here on purpose: signing and off-box persistence
//!   belong upstream, where both gates get them at once.

pub mod cache;
pub mod handlers;
pub mod ledger;
pub mod snapshot;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::routing::{get, post};
use axum::Router;

use crate::admission::Spend;
use crate::{Keyring, PriceList, SigningKey, SpendReport};

/// Everything `serve` needs that is not in the cluster.
#[derive(Debug, Clone, Default)]
pub struct Options {
    pub addr: Option<SocketAddr>,
    pub cert: PathBuf,
    pub key: PathBuf,
    pub trusted_keys: Option<PathBuf>,
    pub prices: Option<PathBuf>,
    pub spend: Option<PathBuf>,
    pub audit_dir: Option<PathBuf>,
    /// Seals every decision's chain (lex-os#54). A path, not a hex
    /// string: this is a long-running process, and a secret in argv is
    /// a secret in `ps` for as long as the pod lives. Mount it from a
    /// Secret.
    pub audit_key_file: Option<PathBuf>,
    pub trusted_image_prefixes: Vec<String>,
    /// Where `parent: cluster/<name>` resolves. Defaults to
    /// `lex-system`.
    pub root_namespace: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    #[error("could not read {0}: {1}")]
    Read(String, String),
    #[error("{0}")]
    Input(String),
    #[error("could not reach the API server: {0}")]
    Kube(#[from] kube::Error),
    #[error("could not serve: {0}")]
    Io(#[from] std::io::Error),
}

/// Start the caches, then serve until killed.
pub async fn run(opts: Options) -> Result<(), ServeError> {
    // Explicit, before anything opens a connection. rustls only picks a
    // provider for you when exactly one is compiled in, and this
    // process links one on purpose (see the `axum-server` note in
    // Cargo.toml) — but "it happened to be the only one" is a property
    // of the dependency graph, which changes without this repo
    // changing. Saying which provider this is turns a future TLS
    // failure inside a cluster into a compile error here.
    if rustls::crypto::ring::default_provider()
        .install_default()
        .is_err()
    {
        tracing::debug!("a crypto provider was already installed");
    }

    let keyring = match &opts.trusted_keys {
        None => None,
        Some(p) => {
            let src = read(p)?;
            let k = Keyring::from_json(&src)
                .map_err(|e| ServeError::Input(format!("keyring {}: {e}", p.display())))?;
            if k.trusted.is_empty() {
                // An empty keyring trusts nobody, which is a real
                // configuration and not the same as not supplying one.
                // Loud, because the two are one flag apart and their
                // effects are opposite.
                tracing::warn!(
                    path = %p.display(),
                    "the keyring trusts nobody, so no submitter gets the manifest's waivers"
                );
            }
            Some(Arc::new(k))
        }
    };

    // The same rule the CLI enforces: pricing a pod without knowing
    // what the namespace already spends checks nothing, so half a
    // budget wall is a configuration error rather than a quiet
    // half-check.
    let spend = match (&opts.prices, &opts.spend) {
        (None, None) => None,
        (Some(_), None) | (None, Some(_)) => {
            return Err(ServeError::Input(
                "--prices and --spend go together: pricing a pod without knowing what \
                 the namespace already spends checks nothing"
                    .into(),
            ))
        }
        (Some(p), Some(r)) => {
            let prices = PriceList::from_json(&read(p)?)
                .map_err(|e| ServeError::Input(format!("prices {}: {e}", p.display())))?;
            let report = SpendReport::from_json(&read(r)?)
                .map_err(|e| ServeError::Input(format!("spend {}: {e}", r.display())))?;
            Some(Arc::new(Spend { prices, report }))
        }
    };

    if let Some(dir) = &opts.audit_dir {
        std::fs::create_dir_all(dir)?;
    }

    // Read before anything serves. A wall that was meant to seal its
    // decisions and silently did not is worse than one that refused to
    // start — the log would look fine right up until somebody needed it
    // to prove something.
    let audit_key = match &opts.audit_key_file {
        None => {
            if opts.audit_dir.is_some() {
                tracing::warn!(
                    "writing an UNSEALED decision log: anyone who can reach the volume can \
                     rewrite a refusal into an admission and recompute the hashes. Pass \
                     --audit-key-file to seal it (lex-os#54)"
                );
            }
            None
        }
        Some(p) => {
            let hex_key = read(p)?;
            let bytes: [u8; 32] = hex::decode(hex_key.trim())
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
                .ok_or_else(|| {
                    ServeError::Input(format!(
                        "{}: the audit signing key must be 32 hex-encoded bytes",
                        p.display()
                    ))
                })?;
            let key = SigningKey::from_bytes(&bytes);
            tracing::info!(
                signer = %hex::encode(key.verifying_key().to_bytes()),
                "sealing every decision"
            );
            Some(Arc::new(key))
        }
    };

    // Before the client, deliberately: a certificate the process cannot
    // read is a configuration error, and finding it out after six
    // reflectors have started listing the cluster wastes an API server's
    // afternoon to reach the same conclusion.
    let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(&opts.cert, &opts.key)
        .await
        .map_err(|e| {
            ServeError::Read(
                format!("{} / {}", opts.cert.display(), opts.key.display()),
                e.to_string(),
            )
        })?;

    let client = kube::Client::try_default().await?;
    let caches = cache::start(client);

    // One ledger for the life of the process (alpibrusl/lex-k8s#13).
    // It lives beside the decision chains, which means it dies with the
    // same pod — worth having anyway, because the signed checkpoint it
    // prints on every append goes to stdout, and that is the one place
    // a collector keeps something this pod does not own.
    let ledger = match &opts.audit_dir {
        None => None,
        Some(dir) => {
            let l = ledger::Ledger::start(
                Some(dir.join("ledger.json")),
                audit_key.as_deref().cloned(),
                Some(dir.display().to_string()),
            )
            .map_err(|e| ServeError::Input(e.to_string()))?;
            let (len, head) = l.state().map_err(|e| ServeError::Input(e.to_string()))?;
            tracing::info!(len, %head, "ledger started");
            Some(Arc::new(l))
        }
    };

    let wall = handlers::Wall {
        caches: caches.clone(),
        keyring,
        spend,
        trusted_image_prefixes: opts.trusted_image_prefixes.clone(),
        audit_dir: opts.audit_dir.clone(),
        audit_key,
        ledger,
        root_namespace: opts
            .root_namespace
            .clone()
            .unwrap_or_else(|| "lex-system".to_string()),
    };

    let app = Router::new()
        .route("/admit", post(handlers::admit_pod))
        .route("/narrow", post(handlers::narrow_manifest))
        .route("/healthz", get(handlers::healthz))
        .route("/readyz", get(handlers::readyz))
        .with_state(wall);

    let addr = opts
        .addr
        .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 8443)));

    tracing::info!(%addr, "serving /admit, /narrow, /healthz, /readyz over TLS");
    tracing::info!("caches starting; /readyz stays 503 until every one has listed");

    axum_server::bind_rustls(addr, tls)
        .serve(app.into_make_service())
        .await?;
    Ok(())
}

fn read(p: &std::path::Path) -> Result<String, ServeError> {
    std::fs::read_to_string(p).map_err(|e| ServeError::Read(p.display().to_string(), e.to_string()))
}
