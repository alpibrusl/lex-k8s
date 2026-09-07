//! The watch caches the wall decides from (alpibrusl/lex-k8s#10).
//!
//! Six reflectors, started before the server listens, and every read in
//! the admission path is a read of these. Nothing here is queried
//! during a decision — `src/cluster.rs` says why, and it is the reason
//! this file exists at all:
//!
//! > The API server is calling *us*, inside its request path. Calling
//! > back into it to decide is a deadlock waiting for a bad afternoon.
//!
//! # Not ready is not empty
//!
//! A reflector that has not finished its initial list holds an empty
//! store, and an empty store is indistinguishable from a cluster with
//! no policies — which reads as *unrestricted egress* and would admit
//! things the cluster forbids. So [`Caches::cold`] gates `/readyz`, and
//! the deployment's readiness probe keeps the Service's endpoints empty
//! until every store has synced once. With `failurePolicy: Fail` that
//! is the correct behaviour: admissions stop until the wall can
//! actually decide.
//!
//! `Store` has no synchronous readiness predicate — only an async
//! `wait_until_ready()` — so each store gets a flag a task flips when
//! its first list lands. A handler must never block on readiness: it is
//! inside the API server's request path, and waiting there is the
//! deadlock this whole design avoids.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use futures::StreamExt;
use k8s_openapi::api::networking::v1::NetworkPolicy;
use k8s_openapi::api::rbac::v1::{ClusterRole, ClusterRoleBinding, Role, RoleBinding};
use kube::api::{ApiResource, DynamicObject, GroupVersionKind};
use kube::runtime::reflector::store::Writer;
use kube::runtime::{reflector, watcher, WatchStreamExt};
use kube::{Api, Client, Resource};

/// The `LexManifest` CRD, as a dynamic kind.
///
/// Read dynamically rather than by deriving `kube::Resource` on
/// [`crate::LexManifest`]: the CRD type is a *serialisation* the
/// library already owns, and giving it a second identity as a
/// Kubernetes resource type would put a `kube` dependency in the middle
/// of a crate whose decision half is meant to build without one. The
/// object comes back as JSON and goes straight into
/// [`crate::LexManifest::read`] — the same entry point the CLI uses,
/// which is what keeps the two from drifting.
pub fn lex_manifest_kind() -> ApiResource {
    ApiResource::from_gvk(&GroupVersionKind::gvk("lex.dev", "v1alpha1", "LexManifest"))
}

/// One store plus whether its first list has landed.
#[derive(Clone)]
pub struct Cache<K: Resource + 'static>
where
    K::DynamicType: std::hash::Hash + Eq + Clone,
{
    pub store: reflector::Store<K>,
    ready: Arc<AtomicBool>,
}

impl<K: Resource + 'static> Cache<K>
where
    K::DynamicType: std::hash::Hash + Eq + Clone,
{
    pub fn ready(&self) -> bool {
        self.ready.load(Ordering::Relaxed)
    }
}

/// Every store the wall reads.
#[derive(Clone)]
pub struct Caches {
    pub manifests: Cache<DynamicObject>,
    pub policies: Cache<NetworkPolicy>,
    pub roles: Cache<Role>,
    pub cluster_roles: Cache<ClusterRole>,
    pub role_bindings: Cache<RoleBinding>,
    pub cluster_role_bindings: Cache<ClusterRoleBinding>,
}

impl Caches {
    /// Which stores are still cold, for `/readyz` to name them.
    ///
    /// All six must be warm, not any: a wall that decided while one
    /// cache was cold would be reading an absence as permission.
    pub fn cold(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        for (name, ready) in [
            ("lexmanifests", self.manifests.ready()),
            ("networkpolicies", self.policies.ready()),
            ("roles", self.roles.ready()),
            ("clusterroles", self.cluster_roles.ready()),
            ("rolebindings", self.role_bindings.ready()),
            ("clusterrolebindings", self.cluster_role_bindings.ready()),
        ] {
            if !ready {
                out.push(name);
            }
        }
        out
    }

    /// The `LexManifest` governing a namespace.
    ///
    /// Exactly one, by design — see [`ManifestLookup`].
    pub fn manifest_for(&self, namespace: &str) -> ManifestLookup {
        let found: Vec<Arc<DynamicObject>> = self
            .manifests
            .store
            .state()
            .into_iter()
            .filter(|o| o.metadata.namespace.as_deref() == Some(namespace))
            .collect();
        match found.len() {
            0 => ManifestLookup::None,
            1 => ManifestLookup::One(found.into_iter().next().expect("len 1")),
            _ => {
                let mut names: Vec<String> = found
                    .iter()
                    .map(|o| o.metadata.name.clone().unwrap_or_default())
                    .collect();
                names.sort();
                ManifestLookup::Ambiguous(names)
            }
        }
    }

    /// A manifest named as `<namespace>/<name>`, or `cluster/<name>`
    /// for the platform-level ceiling.
    ///
    /// # `cluster/` resolves to a namespace, and that is a real choice
    ///
    /// The fixtures write a root manifest as `metadata.namespace: ""`,
    /// which is what a cluster-scoped object looks like. **The CRD is
    /// `scope: Namespaced`**, so no such object can exist in a cluster:
    /// every `LexManifest` the API server stores has a namespace. Left
    /// alone, `parent: cluster/platform-default` would be unresolvable
    /// in every real deployment — which this wall refuses, correctly,
    /// and uselessly.
    ///
    /// So `cluster/<name>` resolves to `<name>` in `root_namespace`
    /// (`lex-system` by default): the namespace the wall itself runs
    /// in, which is already the one only cluster admins can write to.
    /// The ceiling lives where the authority to set it already lives,
    /// rather than in a second CRD scope that would need its own
    /// narrowing rule.
    ///
    /// A `""`-namespaced object is still matched, so the fixture corpus
    /// keeps meaning what it meant.
    pub fn manifest_by_reference(
        &self,
        reference: &str,
        root_namespace: &str,
    ) -> Option<Arc<DynamicObject>> {
        let (ns, name) = reference.split_once('/')?;
        let wanted = if ns == "cluster" { root_namespace } else { ns };
        self.manifests.store.state().into_iter().find(|o| {
            if o.metadata.name.as_deref() != Some(name) {
                return false;
            }
            match o.metadata.namespace.as_deref() {
                None | Some("") => ns == "cluster",
                Some(n) => n == wanted,
            }
        })
    }
}

/// Everything a store holds right now, as plain values.
///
/// One allocation per decision, deliberately: the alternative is
/// holding a read lock on the cache across the whole admission, and a
/// wall that can block its own watch loop is one that stops seeing the
/// cluster it is deciding about.
pub fn contents<K>(cache: &Cache<K>) -> Vec<K>
where
    K: Clone + Resource + 'static,
    K::DynamicType: std::hash::Hash + Eq + Clone,
{
    cache
        .store
        .state()
        .into_iter()
        .map(|o| (*o).clone())
        .collect()
}

/// What the manifest cache had for a namespace.
///
/// Three cases, and two of them are refusals. **No manifest is not an
/// empty manifest**: a namespace nobody granted anything to grants
/// nothing, which is the same rule as an empty allow-list one level up.
/// And two manifests is not "take the first" — a wall that picked would
/// let anyone who can create a `LexManifest` in a namespace choose which
/// ceiling applies to it.
pub enum ManifestLookup {
    One(Arc<DynamicObject>),
    None,
    Ambiguous(Vec<String>),
}

/// Start every reflector and return the stores.
///
/// The tasks are detached: `watcher` restarts its own stream after an
/// error, and a store that stops being fed goes **stale rather than
/// empty** — which is why staleness is pinned into the snapshot rather
/// than assumed away.
pub fn start(client: Client) -> Caches {
    Caches {
        manifests: spawn_dynamic(client.clone(), lex_manifest_kind()),
        policies: spawn::<NetworkPolicy>(client.clone()),
        roles: spawn::<Role>(client.clone()),
        cluster_roles: spawn::<ClusterRole>(client.clone()),
        role_bindings: spawn::<RoleBinding>(client.clone()),
        cluster_role_bindings: spawn::<ClusterRoleBinding>(client),
    }
}

fn drive<K>(writer: Writer<K>, api: Api<K>, kind: &'static str) -> Cache<K>
where
    K: Resource + Clone + std::fmt::Debug + Send + Sync + serde::de::DeserializeOwned + 'static,
    K::DynamicType: Eq + std::hash::Hash + Clone + Send + Sync,
{
    let store = writer.as_reader();
    let ready = Arc::new(AtomicBool::new(false));

    let flag = ready.clone();
    let watched = store.clone();
    tokio::spawn(async move {
        if watched.wait_until_ready().await.is_ok() {
            flag.store(true, Ordering::Relaxed);
            tracing::info!(kind, "cache warm");
        }
    });

    tokio::spawn(async move {
        let stream = reflector(writer, watcher(api, watcher::Config::default()))
            .default_backoff()
            .touched_objects();
        let mut stream = std::pin::pin!(stream);
        while let Some(event) = stream.next().await {
            if let Err(e) = event {
                tracing::warn!(error = %e, kind, "watch error; the stream will restart");
            }
        }
        tracing::error!(kind, "watch stream ended");
    });

    Cache { store, ready }
}

fn spawn<K>(client: Client) -> Cache<K>
where
    K: Resource<DynamicType = ()>
        + Clone
        + std::fmt::Debug
        + Send
        + Sync
        + serde::de::DeserializeOwned
        + 'static,
{
    drive(
        Writer::<K>::default(),
        Api::all(client),
        std::any::type_name::<K>(),
    )
}

fn spawn_dynamic(client: Client, ar: ApiResource) -> Cache<DynamicObject> {
    // A `DynamicObject`'s type is a value, not a type parameter, so its
    // writer cannot come from `Default` the way a typed one does. That
    // is the whole difference: everything downstream is identical.
    let api: Api<DynamicObject> = Api::all_with(client, &ar);
    drive(Writer::<DynamicObject>::new(ar), api, "LexManifest")
}
