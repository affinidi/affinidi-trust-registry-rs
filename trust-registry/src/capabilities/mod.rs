//! Pluggable capability modules (`governance/capability/*`).
//!
//! A capability is a named bundle of Trust Task handlers plus the manifest
//! describing it (see the `governance/_shared` `CapabilityManifest` spec).
//! Communities differ in which capabilities they need, so everything here is
//! **off by default**: a host with no enable record serves none of a
//! capability's task types.
//!
//! [`CapabilitySet`] owns the runtime composition: it knows the *available*
//! capability definitions (compiled in by the host), persists *enablement*
//! state (which are on, for which authority, with what config), and
//! rebuilds/swaps the live [`RegistryDispatcher`]s the transport bindings
//! dispatch through.
//!
//! # Enablement is per authority
//!
//! A registry can host several authorities (`ADMIN_AUTHORITIES`), and each
//! enables a capability for itself: the state is keyed by
//! [`EnablementKey`] — the capability and the authority its config names. Two
//! communities can each enable `git-trust` under their own authority, and each
//! one's grants, revokes and disable act only on its own enablement. A
//! capability that writes no records may be enabled with no authority; it then
//! acts under the registry's own DID, in a single slot.
//!
//! A capability's write task is executed through the dispatcher of the one
//! enablement it acts under ([`CapabilitySnapshot::tasks`]), chosen by the
//! [`TaskHandler`](crate::trust_tasks::TaskHandler) from the authorities the
//! issuer may act for. An issuer that may act for several authorities which
//! have all enabled the capability names the one it means in the request's
//! `ext` ([`EXT_NAMESPACE`] / [`EXT_AUTHORITY`]).
//!
//! # Changes are persisted before they take effect
//!
//! Enable and disable re-read the stored state, decide against it, and write
//! the one enablement they change with a compare-and-swap on its revision
//! ([`CapabilityStateStore::put`]); only then do they replace the in-memory
//! state and swap the dispatchers. A failed write changes nothing: memory,
//! store and dispatchers keep agreeing, and the retry the `internalError`
//! invites starts from the same state.
//!
//! # Replicas share the state of a shared store
//!
//! With the Redis or DynamoDB record backend the state lives beside the
//! records ([`TrustRecordAdminRepository::capability_store`](crate::storage::repository::TrustRecordAdminRepository::capability_store)),
//! so every replica on that backend sees one state. A write that lost a race
//! with another replica's ([`Put::Conflict`]) is decided again against the
//! state that won, so no update is lost. A replica converges on the others'
//! changes by re-reading the store ([`CapabilitySet::refresh`]): before it
//! authorises or serves any capability task or governance task (read-through,
//! so a disable made on one replica is honoured by the next task on every
//! other), and on an interval ([`CapabilitySet::spawn_refresher`]) for the
//! dispatcher handles a host reads directly.

// `TaskOutcome`'s error is a whole `trust-task-error` document, which is large
// by design; boxing it would only move the allocation onto every caller. The
// router allows this lint for the same reason.
#![allow(clippy::result_large_err)]

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::future::Future;
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::Arc;

use crate::specs::governance::capability::disable::v0_1 as disable_spec;
use crate::specs::governance::capability::enable::v0_1 as enable_spec;
use crate::specs::governance::capability::list::v0_1 as list_spec;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::RwLock;
use trust_tasks_rs::{Dispatcher, Payload as _, RejectReason, TrustTask, TypeUri};

use crate::domain::normalise_reference;
use crate::trust_tasks::descriptor::{TaskError, spec_error};
use crate::trust_tasks::proof::requires_proof;
use crate::trust_tasks::router::{new_id, reject_build_err, respond};
use crate::trust_tasks::{RegistryDispatcher, TaskFuture, TaskOutcome};

pub use enable_spec::CapabilityManifest;

/// The enablement-config member naming the authority a capability acts under.
/// Writes a capability makes are bound to it, so enabling a capability with an
/// authority is itself bound to it.
pub const CONFIG_AUTHORITY: &str = "authority";

/// The `ext` namespace (SPEC §4.5.1) of this registry's extension members.
pub const EXT_NAMESPACE: &str = "com.affinidi.trust-registry";

/// The member of a request's `ext.`[`EXT_NAMESPACE`] naming the authority a
/// capability task (`git-trust/grant`, `governance/capability/disable`, ...)
/// acts under. Needed only when the issuer may act for several authorities
/// that have each enabled the capability.
pub const EXT_AUTHORITY: &str = "authority";

/// Validates a per-community `config` document.
pub type ConfigValidator = Arc<dyn Fn(&Value) -> Result<(), String> + Send + Sync>;

/// Contributes a capability's dispatcher registrations, given one
/// enablement's state.
pub type RegisterFn =
    Arc<dyn Fn(RegistryDispatcher, &CapabilityState) -> RegistryDispatcher + Send + Sync>;

/// A capability the host can serve: its manifest plus the dispatcher
/// registrations it contributes when enabled.
///
/// A capability's tasks are writes unless it declares them as reads: every
/// task [`register`](Self::register) adds is handled as a write, so it needs a
/// proof from an admin, acts under an authority, is executed at most once and
/// is audited. Only tasks added by [`register_reads`](Self::register_reads)
/// are served as reads, on the read-only surface as well as the admin one.
pub struct CapabilityDefinition {
    pub manifest: CapabilityManifest,
    /// Contributes the capability's write tasks, as `.on::<P, _>()`
    /// registrations, to the admin surface only. Receives one enablement's
    /// state (version, config) so handlers can bind that authority's
    /// configuration: it is called once per enablement, and a task is
    /// executed through the registrations of the enablement it acts under.
    /// It must register the same task types whatever that state is: the set
    /// is read once, when the [`CapabilitySet`] is built, to decide which
    /// tasks are writes. A state under which it registers anything else is
    /// refused at enable, and a persisted one leaves that enablement
    /// unserved.
    pub register: RegisterFn,
    /// Contributes the capability's read-only tasks, served on both the admin
    /// and the read-only surface **without a proof, an admin check, an
    /// authority, the replay record or an audit entry**, to unauthenticated
    /// callers included. A task registered here must therefore not change any
    /// state, in the registry or elsewhere: that is the capability author's
    /// contract, which the registry cannot check. `None` = the capability has
    /// no read tasks. A task type registered here must not also be registered
    /// by [`register`](Self::register) or be one of the registry's own
    /// writes; [`CapabilitySet::new`] refuses such a definition. Like
    /// `register`, it must register the same task types whatever the state.
    /// With several enablements it is registered with the first (by
    /// authority), since a read acts under no authority.
    pub register_reads: Option<RegisterFn>,
    /// Validates a per-community `config` document. `None` = no config
    /// accepted beyond an empty object.
    pub validate_config: Option<ConfigValidator>,
    /// Whether the capability writes records, and so must be enabled with an
    /// `authority` its writes are bound to. Enabling one without an authority
    /// is refused, so no such capability can run unbound.
    pub requires_authority: bool,
}

/// A consistent view of one enablement: whether it is enabled, the authority
/// it acts under, and the dispatchers that serve it, all read together, so a
/// check against the authority holds for the dispatcher it is used with.
pub struct CapabilitySnapshot {
    pub enabled: bool,
    /// The authority the enablement's config names; `None` for an enablement
    /// with no authority, or one that is not enabled.
    pub authority: Option<String>,
    /// The live admin dispatcher (the governance tasks and the registry's
    /// own), read in the same snapshot.
    pub dispatcher: Arc<RegistryDispatcher>,
    /// The enablement's own write tasks, registered with its state: the
    /// dispatcher a task acting under this enablement is executed through.
    /// `None` when it is not enabled.
    pub tasks: Option<Arc<RegistryDispatcher>>,
}

/// Which enablement: a capability and the authority it was enabled for.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EnablementKey {
    /// The capability's slug, e.g. `git-trust`.
    pub capability: String,
    /// The authority its config names, normalised
    /// ([`normalise_reference`]). `None` for a capability enabled with no
    /// authority: one that writes no records, acting under the registry's own
    /// DID.
    pub authority: Option<String>,
}

impl EnablementKey {
    /// The key of `capability` enabled for `authority`, normalised.
    pub fn new(capability: impl Into<String>, authority: Option<&str>) -> Self {
        Self {
            capability: capability.into(),
            authority: authority.map(|a| normalise_reference(a.to_string())),
        }
    }

    /// The key an enablement with `config` is stored under.
    fn of_config(capability: &str, config: Option<&Value>) -> Self {
        Self::new(capability, config_authority(config).as_deref())
    }
}

/// The `authority` member of an enablement config, normalised.
fn config_authority(config: Option<&Value>) -> Option<String> {
    config
        .and_then(|c| c.get(CONFIG_AUTHORITY))
        .and_then(Value::as_str)
        .map(|a| normalise_reference(a.to_string()))
}

/// Persisted state of one enablement.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityState {
    pub version: String,
    pub enabled: bool,
    #[serde(default)]
    pub config: Option<Value>,
    pub enabled_at: DateTime<Utc>,
    /// The revision the store holds this state at: 0 for one never stored
    /// (or stored by a release that kept no revisions), and one more on every
    /// write ([`CapabilityStateStore::put`]). Set by the store; a state
    /// passed to `put` has its own revision ignored.
    #[serde(default)]
    pub revision: u64,
    /// The enable or disable that wrote this state: a fresh identifier per
    /// change, so a registry recognises its own write when the store reports
    /// a conflict for it (the DynamoDB SDK retrying an attempt that had
    /// landed, whose answer was lost). `None` for a state no change wrote
    /// (one written by an earlier release, or imported).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_id: Option<String>,
}

/// Every enablement the registry knows of, enabled or retained after a
/// disable.
pub type CapabilityStates = BTreeMap<EnablementKey, CapabilityState>;

/// What [`CapabilityStateStore::put`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Put {
    /// Stored, at this revision.
    Written(u64),
    /// The enablement is no longer stored at the revision expected: another
    /// writer changed it first. Nothing was written.
    Conflict,
}

/// Durable store for enablement state.
///
/// One entry per [`EnablementKey`], each at a revision. A write is a
/// compare-and-swap of one entry, atomic against every other writer of the
/// store, so two registries changing the state at once cannot lose an
/// update: the one that loses the race is told so, re-reads and decides
/// again.
#[async_trait::async_trait]
pub trait CapabilityStateStore: Send + Sync {
    /// Every stored enablement, each with the revision it is stored at
    /// ([`CapabilityState::revision`]), read at one point in time.
    async fn load(&self) -> Result<CapabilityStates, String>;

    /// Store `state` for `key` if the entry is still at revision `expected`
    /// (0: no entry), at revision `expected + 1`; otherwise write nothing and
    /// answer [`Put::Conflict`].
    async fn put(
        &self,
        key: &EnablementKey,
        expected: u64,
        state: &CapabilityState,
    ) -> Result<Put, String>;

    /// Whether another process (or another [`CapabilitySet`]) may change the
    /// store. A set over a shared store re-reads it before every capability
    /// task ([`CapabilitySet::refresh`]); over a store only it writes, it
    /// trusts what it holds.
    ///
    /// Defaults to `true`, the safe answer for a store that does not say: a
    /// set that re-reads a store nobody else writes only does extra reads,
    /// while one that trusts a store others write serves stale enablement.
    /// [`FileCapabilityStore`] answers `false`.
    fn is_shared(&self) -> bool {
        true
    }
}

/// The longest one read or write of the capability store may take. Store
/// calls are made while the set's state is serialised ([`CapabilitySet`]'s
/// `sync`), so a stalled call must not hold every capability task of this
/// registry: past this it is abandoned and reported as a storage error
/// (answered `unavailable`/`internalError`, both retryable).
pub const STORE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// `call`, abandoned after [`STORE_TIMEOUT`].
async fn bounded<T>(
    what: &str,
    call: impl Future<Output = Result<T, String>>,
) -> Result<T, String> {
    tokio::time::timeout(STORE_TIMEOUT, call)
        .await
        .unwrap_or_else(|_| {
            Err(format!(
                "the capability store did not answer the {what} within {STORE_TIMEOUT:?}"
            ))
        })
}

/// The name a shared store keeps an enablement under: its key as a JSON
/// array, `["git-trust","did:..."]` or `["badge",null]`, which no capability
/// slug or DID can make ambiguous.
#[cfg_attr(
    not(any(feature = "storage-redis", feature = "storage-ddb")),
    allow(dead_code)
)]
pub(crate) fn field(key: &EnablementKey) -> Result<String, String> {
    serde_json::to_string(&(&key.capability, &key.authority)).map_err(|e| e.to_string())
}

/// The enablement a [`field`] names.
#[cfg_attr(
    not(any(feature = "storage-redis", feature = "storage-ddb")),
    allow(dead_code)
)]
pub(crate) fn key_of(field: &str) -> Result<EnablementKey, String> {
    let (capability, authority): (String, Option<String>) = serde_json::from_str(field)
        .map_err(|e| format!("capability state field {field} is not an enablement: {e}"))?;
    Ok(EnablementKey::new(capability, authority.as_deref()))
}

/// An entry read from a store is refused if it is keyed under an authority
/// its config does not name: it would act under one authority while
/// listed under another.
fn check_entry(key: &EnablementKey, state: &CapabilityState) -> Result<(), String> {
    if config_authority(state.config.as_ref()) != key.authority {
        return Err(format!(
            "{key:?} is listed under an authority its config does not name"
        ));
    }
    Ok(())
}

/// The version of the state file format [`encode_states`] writes.
pub const STATE_FORMAT: u64 = 2;

/// One enablement as the state file stores it.
#[derive(Serialize, Deserialize)]
struct StoredEnablement {
    capability: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    authority: Option<String>,
    #[serde(flatten)]
    state: CapabilityState,
}

/// The state file: `{"format": 2, "enablements": [...]}`.
#[derive(Serialize, Deserialize)]
struct StateFile {
    format: u64,
    enablements: Vec<StoredEnablement>,
}

/// The state file text for `states`, in the per-authority format.
pub fn encode_states(states: &CapabilityStates) -> Result<String, String> {
    let file = StateFile {
        format: STATE_FORMAT,
        enablements: states
            .iter()
            .map(|(key, state)| StoredEnablement {
                capability: key.capability.clone(),
                authority: key.authority.clone(),
                state: state.clone(),
            })
            .collect(),
    };
    serde_json::to_string_pretty(&file).map_err(|e| e.to_string())
}

/// Read a state file: the per-authority format, or the single-slot format of
/// earlier releases (`{"<capability>": {state}}`), which is migrated by keying
/// each entry under the authority its config names. The migrated state is
/// written in the per-authority format on the next save.
pub fn decode_states(text: &str) -> Result<CapabilityStates, String> {
    let value: Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
    if value.get("format").is_some_and(Value::is_number) {
        let file: StateFile = serde_json::from_value(value).map_err(|e| e.to_string())?;
        if file.format != STATE_FORMAT {
            return Err(format!(
                "state format {} is not one this registry reads ({STATE_FORMAT})",
                file.format
            ));
        }
        let mut states = CapabilityStates::new();
        for stored in file.enablements {
            let key = EnablementKey::new(stored.capability, stored.authority.as_deref());
            check_entry(&key, &stored.state)?;
            if states.insert(key.clone(), stored.state).is_some() {
                return Err(format!("{key:?} is listed twice"));
            }
        }
        return Ok(states);
    }
    let legacy: BTreeMap<String, CapabilityState> =
        serde_json::from_value(value).map_err(|e| e.to_string())?;
    Ok(legacy
        .into_iter()
        .map(|(capability, state)| {
            (
                EnablementKey::of_config(&capability, state.config.as_ref()),
                state,
            )
        })
        .collect())
}

/// JSON-file-backed store, for a registry that is the only process using it
/// (the CSV, in-memory and fjall backends). A write re-reads the file, checks
/// the entry's revision, and writes a temporary file, syncs it, renames it
/// over the state file and syncs the directory, so the file is either the old
/// state or the new one, across a power loss too.
///
/// The compare-and-swap is atomic between the users of one
/// `FileCapabilityStore` (and its clones), not between processes: two
/// registries must not share one state file. Replicas share their state
/// through a shared record backend instead (Redis, DynamoDB).
#[derive(Clone)]
pub struct FileCapabilityStore {
    path: PathBuf,
    /// Serialises the read-check-write of a put.
    lock: Arc<std::sync::Mutex<()>>,
}

impl FileCapabilityStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            lock: Arc::default(),
        }
    }

    /// The state file.
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    fn read(&self) -> Result<CapabilityStates, String> {
        match std::fs::read_to_string(&self.path) {
            Ok(text) => decode_states(&text)
                .map_err(|e| format!("capability state {} is corrupt: {e}", self.path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(CapabilityStates::new()),
            Err(e) => Err(format!(
                "cannot read capability state {}: {e}",
                self.path.display()
            )),
        }
    }

    fn write(&self, state: &CapabilityStates) -> Result<(), String> {
        let json = encode_states(state)?;
        let parent = self.path.parent().filter(|p| !p.as_os_str().is_empty());
        if let Some(parent) = parent {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let tmp = self.path.with_extension("json.tmp");
        let mut file = std::fs::File::create(&tmp).map_err(|e| e.to_string())?;
        file.write_all(json.as_bytes()).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        drop(file);
        std::fs::rename(&tmp, &self.path).map_err(|e| e.to_string())?;
        // The rename is in place; a failed directory sync only weakens its
        // durability across a power loss, so it is reported, not returned:
        // returning it would leave memory behind the file it just replaced.
        let dir = parent.map_or_else(|| PathBuf::from("."), PathBuf::from);
        if let Err(e) = std::fs::File::open(&dir).and_then(|d| d.sync_all()) {
            tracing::warn!(
                "capability state {} saved, but its directory could not be synced: {e}",
                self.path.display()
            );
        }
        Ok(())
    }

    fn put_blocking(
        &self,
        key: &EnablementKey,
        expected: u64,
        state: &CapabilityState,
    ) -> Result<Put, String> {
        let _held = self.lock.lock().unwrap_or_else(|p| p.into_inner());
        let mut states = self.read()?;
        if states.get(key).map_or(0, |s| s.revision) != expected {
            return Ok(Put::Conflict);
        }
        let revision = expected + 1;
        states.insert(
            key.clone(),
            CapabilityState {
                revision,
                ..state.clone()
            },
        );
        self.write(&states)?;
        Ok(Put::Written(revision))
    }
}

#[async_trait::async_trait]
impl CapabilityStateStore for FileCapabilityStore {
    async fn load(&self) -> Result<CapabilityStates, String> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || store.read())
            .await
            .map_err(|e| format!("the state read did not finish: {e}"))?
    }

    async fn put(
        &self,
        key: &EnablementKey,
        expected: u64,
        state: &CapabilityState,
    ) -> Result<Put, String> {
        let (store, key, state) = (self.clone(), key.clone(), state.clone());
        tokio::task::spawn_blocking(move || store.put_blocking(&key, expected, &state))
            .await
            .map_err(|e| format!("the state write did not finish: {e}"))?
    }

    /// Only this process writes the file.
    fn is_shared(&self) -> bool {
        false
    }
}

/// In-memory store for tests and ephemeral deployments. Its clones share one
/// state, so several [`CapabilitySet`]s over clones of one store behave as
/// replicas over a shared backend.
#[derive(Default, Clone)]
pub struct MemoryCapabilityStore {
    state: Arc<std::sync::Mutex<CapabilityStates>>,
}

#[async_trait::async_trait]
impl CapabilityStateStore for MemoryCapabilityStore {
    async fn load(&self) -> Result<CapabilityStates, String> {
        Ok(self.state.lock().unwrap_or_else(|p| p.into_inner()).clone())
    }

    async fn put(
        &self,
        key: &EnablementKey,
        expected: u64,
        state: &CapabilityState,
    ) -> Result<Put, String> {
        let mut states = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if states.get(key).map_or(0, |s| s.revision) != expected {
            return Ok(Put::Conflict);
        }
        let revision = expected + 1;
        states.insert(
            key.clone(),
            CapabilityState {
                revision,
                ..state.clone()
            },
        );
        Ok(Put::Written(revision))
    }

    /// A clone may be another set's store.
    fn is_shared(&self) -> bool {
        true
    }
}

/// Import a state file into a shared store: each of its enablements is
/// written to `shared` only if `shared` has never held that enablement
/// (`put` at revision 0), so nothing the shared state already says — enabled
/// or disabled, by any replica — is overwritten. Once every entry is written
/// or found present, the file is renamed to `<file>.imported`; that rename is
/// what marks the import done.
///
/// - A failed write (the store unreachable mid-import) fails the import and
///   leaves the file in place; the next start repeats the whole import, which
///   skips what already landed and writes the rest, so no enablement of the
///   file is lost.
/// - With several replicas each upgrading with a file of its own, each
///   file is merged in on its replica's first start: enablements the shared
///   state has never seen are added, the rest are kept as the shared state
///   has them.
/// - Once renamed, the file is never imported again (after the shared state is
///   cleared, say), and a downgraded registry does not serve its stale state
///   until the operator renames it back.
///
/// Answers how many enablements were written.
pub async fn import_state_file(
    shared: &dyn CapabilityStateStore,
    file: &FileCapabilityStore,
) -> Result<usize, String> {
    let local = bounded("read of the state file", file.load()).await?;
    if local.is_empty() {
        return Ok(0);
    }
    let mut imported = 0;
    for (key, state) in &local {
        match bounded("import write", shared.put(key, 0, state)).await? {
            Put::Written(_) => imported += 1,
            Put::Conflict => tracing::info!(
                "capability enablement {key:?} from {} not imported: the shared state already \
                 holds it",
                file.path().display()
            ),
        }
    }
    let mut renamed = file.path().as_os_str().to_owned();
    renamed.push(".imported");
    let renamed = PathBuf::from(renamed);
    match std::fs::rename(file.path(), &renamed) {
        Ok(()) => tracing::info!(
            "imported {imported} of {} capability enablement(s) from {} into the shared record \
             backend; the file is no longer read and was renamed to {}",
            local.len(),
            file.path().display(),
            renamed.display()
        ),
        // Harmless: the next start repeats the import, which writes nothing
        // the shared state already holds, and tries the rename again.
        Err(e) => tracing::warn!(
            "imported {imported} of {} capability enablement(s) from {} into the shared record \
             backend, but could not rename it to {}: {e}; it will be merged again (writing \
             nothing the shared state already holds) on the next start",
            local.len(),
            file.path().display(),
            renamed.display()
        ),
    }
    Ok(imported)
}

/// A live, swappable dispatcher the transport bindings read through.
pub type DispatcherHandle = Arc<RwLock<Arc<RegistryDispatcher>>>;

/// Errors from enable/disable. The governance handlers below answer each with
/// the specification's extension code for it
/// (`governance/capability/enable:unknownCapability`, ...).
#[derive(Debug, Clone, PartialEq)]
pub enum CapabilityError {
    /// Not built into this host, or not at the requested version.
    UnknownCapability(String),
    /// Already enabled for this authority.
    AlreadyEnabled,
    /// Not enabled for this authority.
    NotEnabled,
    /// The config, manifest or delegate of an enable is not acceptable.
    ConfigInvalid(String),
    /// Several authorities have enabled the capability and the request does
    /// not say which it acts on.
    AuthorityRequired(String),
    /// The state could not be saved; nothing changed.
    Storage(String),
}

/// Which enablement a task dispatched by the
/// [`TaskHandler`](crate::trust_tasks::TaskHandler) acts on, established
/// before dispatch from the authorities the issuer may act for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Acting {
    /// This enablement.
    Enablement(EnablementKey),
    /// No enablement the request may act on: the capability is not enabled
    /// for the authority it acts under.
    NotEnabled,
}

tokio::task_local! {
    static ACTING: Acting;
}

/// Run `task` acting on `acting`: the governance handlers (`disable`) read it
/// to know which enablement they change.
pub async fn acting_as<F: Future>(acting: Acting, task: F) -> F::Output {
    ACTING.scope(acting, task).await
}

/// The enablement the running task acts on, when the
/// [`TaskHandler`](crate::trust_tasks::TaskHandler) established one.
fn acting() -> Option<Acting> {
    ACTING.try_with(Clone::clone).ok()
}

/// The authority a request names in `ext.`[`EXT_NAMESPACE`]`.`[`EXT_AUTHORITY`],
/// normalised. An `ext` member of the wrong type is refused.
pub fn requested_authority(payload: &Value) -> Result<Option<String>, String> {
    match payload
        .get("ext")
        .and_then(|ext| ext.get(EXT_NAMESPACE))
        .and_then(|ns| ns.get(EXT_AUTHORITY))
    {
        None => Ok(None),
        Some(Value::String(authority)) => Ok(Some(normalise_reference(authority.clone()))),
        Some(_) => Err(format!(
            "ext.{EXT_NAMESPACE}.{EXT_AUTHORITY} must be a DID string"
        )),
    }
}

/// One line of [`CapabilitySet::list`].
#[derive(Debug, Clone)]
pub struct ListedCapability {
    pub manifest: CapabilityManifest,
    /// The enablement's authority; `None` for an entry with no authority or a
    /// capability nobody has enabled.
    pub authority: Option<String>,
    /// The enablement's state; `None` for a capability nobody has enabled.
    pub state: Option<CapabilityState>,
}

/// Runtime composition of base handlers + enabled capability handlers.
pub struct CapabilitySet {
    available: BTreeMap<String, CapabilityDefinition>,
    state: RwLock<CapabilityStates>,
    store: Arc<dyn CapabilityStateStore>,
    /// Builds the always-on base registrations (admin surface).
    base: Box<dyn Fn() -> RegistryDispatcher + Send + Sync>,
    /// Builds the always-on read-only registrations (HTTP surface).
    base_query: Box<dyn Fn() -> RegistryDispatcher + Send + Sync>,
    dispatcher: DispatcherHandle,
    query_dispatcher: DispatcherHandle,
    /// Each enabled enablement's own write tasks. Swapped with the live
    /// dispatchers, under the state lock.
    tasks: RwLock<BTreeMap<EnablementKey, Arc<RegistryDispatcher>>>,
    /// Which tasks each available capability serves, enabled or not.
    classification: Classification,
    /// Serialises this set's reads of the store with its changes, so an
    /// older read can never replace the state a later one, or a change,
    /// put in place.
    sync: tokio::sync::Mutex<()>,
    /// How many reads of the store have begun, and the outcome of the last
    /// one: callers waiting for a read share one that began after they
    /// arrived ([`Self::read_coalesced`]).
    reads: std::sync::atomic::AtomicU64,
    last_read: std::sync::Mutex<Result<(), CapabilityError>>,
    /// The background re-read ([`Self::spawn_refresher`]), awaited by
    /// [`Self::join_refresher`].
    refresher: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    weak: std::sync::Weak<Self>,
}

/// How many times a change is decided again after losing a race with
/// another writer of the store.
const MAX_CHANGE_ATTEMPTS: usize = 8;

/// The interval a set over a shared store re-reads it on by default
/// ([`CapabilitySet::spawn_refresher`]).
pub const DEFAULT_REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

/// Task slug -> the capability that serves it, as a write or as a declared
/// read, learned once when the [`CapabilitySet`] is built.
#[derive(Default)]
struct Classification {
    writes: BTreeMap<String, String>,
    reads: BTreeMap<String, String>,
}

impl Classification {
    /// Refuse `state` for `capability` if under it the definition registers a
    /// task other than the ones it was classified with: a write it did not
    /// register under the probe state would be handled as a read, and a read
    /// could put a write on the read-only surface.
    fn check(
        &self,
        capability: &str,
        definition: &CapabilityDefinition,
        state: &CapabilityState,
    ) -> Result<(), String> {
        let owned = |kind: &BTreeMap<String, String>, slug: &str| {
            kind.get(slug).is_some_and(|owner| owner == capability)
        };
        for slug in slugs_of(&(definition.register)(Dispatcher::new(), state))? {
            if !owned(&self.writes, &slug) {
                return Err(format!(
                    "{capability} registers {slug} under this state, which it does not \
                     register otherwise; a capability must register the same tasks whatever \
                     its state"
                ));
            }
        }
        if let Some(register_reads) = &definition.register_reads {
            for slug in slugs_of(&register_reads(Dispatcher::new(), state))? {
                if !owned(&self.reads, &slug) {
                    return Err(format!(
                        "{capability} declares {slug} as a read under this state, which it does \
                         not declare otherwise; a capability must register the same tasks \
                         whatever its state"
                    ));
                }
            }
        }
        Ok(())
    }
}

/// The state [`CapabilitySet::new`] registers a definition with to learn
/// which task types it serves.
fn probe_state() -> CapabilityState {
    CapabilityState {
        version: String::new(),
        enabled: true,
        config: None,
        enabled_at: DateTime::<Utc>::UNIX_EPOCH,
        revision: 0,
        change_id: None,
    }
}

/// The task slugs `register` adds to an empty dispatcher.
fn registered_slugs(register: &RegisterFn) -> Result<BTreeSet<String>, String> {
    slugs_of(&register(Dispatcher::new(), &probe_state()))
}

fn slugs_of(dispatcher: &RegistryDispatcher) -> Result<BTreeSet<String>, String> {
    dispatcher
        .registered_uris()
        .into_iter()
        .map(|uri| {
            uri.parse::<TypeUri>()
                .map(|uri| uri.slug().to_string())
                .map_err(|e| format!("capability registers an invalid Type URI {uri}: {e}"))
        })
        .collect()
}

/// Which task slugs each capability serves as a write.
///
/// Refuses a definition that registers a task the registry itself serves
/// (`reserved`), and one that declares as a read a task that is also a write,
/// its own, another capability's or the registry's, so no write can be served
/// on the read-only surface.
fn classify(
    available: &BTreeMap<String, CapabilityDefinition>,
    reserved: &BTreeSet<String>,
) -> Result<Classification, String> {
    let mut writes: BTreeMap<String, String> = BTreeMap::new();
    let mut reads: BTreeMap<String, String> = BTreeMap::new();
    for (capability, definition) in available {
        for slug in registered_slugs(&definition.register)? {
            if let Some(other) = writes.insert(slug.clone(), capability.clone()) {
                return Err(format!(
                    "capabilities {other} and {capability} both register the task {slug}"
                ));
            }
        }
        if let Some(register_reads) = &definition.register_reads {
            for slug in registered_slugs(register_reads)? {
                reads.insert(slug, capability.clone());
            }
        }
    }
    for (slug, capability) in writes.iter().chain(&reads) {
        if reserved.contains(slug) {
            return Err(format!(
                "capability {capability} registers {slug}, which the registry itself serves"
            ));
        }
    }
    for (slug, capability) in &reads {
        if writes.contains_key(slug) || requires_proof(slug) {
            return Err(format!(
                "capability {capability} declares {slug} as a read, but it is a write"
            ));
        }
    }
    Ok(Classification { writes, reads })
}

/// The live dispatchers and the per-enablement task dispatchers for `state`.
struct Composed {
    admin: RegistryDispatcher,
    query: RegistryDispatcher,
    tasks: BTreeMap<EnablementKey, Arc<RegistryDispatcher>>,
}

impl CapabilitySet {
    /// Build the set: load persisted state, then compose the initial
    /// dispatchers (base + every already-enabled capability), so a restart
    /// converges to the persisted enablement.
    pub async fn new(
        available: Vec<CapabilityDefinition>,
        store: Box<dyn CapabilityStateStore>,
        base: Box<dyn Fn() -> RegistryDispatcher + Send + Sync>,
        base_query: Box<dyn Fn() -> RegistryDispatcher + Send + Sync>,
    ) -> Result<Arc<Self>, String> {
        let store: Arc<dyn CapabilityStateStore> = Arc::from(store);
        let state = bounded("read", store.load()).await?;
        let available: BTreeMap<String, CapabilityDefinition> = available
            .into_iter()
            .map(|d| (d.manifest.capability.to_string(), d))
            .collect();
        let mut reserved = slugs_of(&base())?;
        reserved.extend(slugs_of(&base_query())?);
        reserved.extend(
            [
                list_spec::Payload::type_uri(),
                enable_spec::Payload::type_uri(),
                disable_spec::Payload::type_uri(),
            ]
            .iter()
            .map(|uri| uri.slug().to_string()),
        );
        let classification = classify(&available, &reserved)?;
        Ok(Arc::new_cyclic(|weak: &std::sync::Weak<Self>| {
            let composed = compose(
                &base,
                &base_query,
                &available,
                &classification,
                &state,
                weak,
            );
            Self {
                dispatcher: Arc::new(RwLock::new(Arc::new(composed.admin))),
                query_dispatcher: Arc::new(RwLock::new(Arc::new(composed.query))),
                tasks: RwLock::new(composed.tasks),
                weak: weak.clone(),
                sync: tokio::sync::Mutex::new(()),
                reads: std::sync::atomic::AtomicU64::new(0),
                last_read: std::sync::Mutex::new(Ok(())),
                refresher: std::sync::Mutex::new(None),
                classification,
                available,
                state: RwLock::new(state),
                store,
                base,
                base_query,
            }
        }))
    }

    /// The full (admin) dispatcher handle for the DIDComm/TSP bindings.
    ///
    /// It serves a capability's write tasks only while exactly one authority
    /// has the capability enabled, with that enablement's state; with several,
    /// dispatching a capability task directly (without the
    /// [`TaskHandler`](crate::trust_tasks::TaskHandler), which chooses the
    /// enablement) answers it as unsupported rather than pick one.
    pub fn dispatcher(&self) -> DispatcherHandle {
        self.dispatcher.clone()
    }

    /// The read-only dispatcher handle for the HTTP binding.
    pub fn query_dispatcher(&self) -> DispatcherHandle {
        self.query_dispatcher.clone()
    }

    /// The manifest of an available capability.
    pub fn manifest(&self, capability: &str) -> Option<&CapabilityManifest> {
        self.available.get(capability).map(|d| &d.manifest)
    }

    /// Enable `capability` for the authority its config names (or, for a
    /// capability that writes no records and is given no authority, in the
    /// registry's own slot): validate, persist, then swap dispatchers.
    ///
    /// `version` must be the version of the capability's manifest: the host
    /// serves no other. `delegate` is always refused: this registry has no
    /// delegation mechanism, so it cannot honour one (it is a parameter so
    /// that the refusal is made here, for every caller).
    pub async fn enable(
        &self,
        capability: &str,
        version: &str,
        config: Option<Value>,
        delegate: Option<String>,
    ) -> Result<CapabilityState, CapabilityError> {
        let definition = self.available.get(capability).ok_or_else(|| {
            CapabilityError::UnknownCapability(format!("{capability} is not built into this host"))
        })?;
        let served = definition.manifest.version.to_string();
        if version != served {
            return Err(CapabilityError::UnknownCapability(format!(
                "{capability} is served at version {served} only, not {version}"
            )));
        }
        if delegate.is_some() {
            return Err(CapabilityError::ConfigInvalid(
                "`delegate` is refused: this registry serves only built-in capabilities and has \
                 no delegation mechanism"
                    .to_string(),
            ));
        }
        if let Some(validate) = &definition.validate_config {
            let empty = Value::Object(serde_json::Map::new());
            validate(config.as_ref().unwrap_or(&empty)).map_err(CapabilityError::ConfigInvalid)?;
        }
        let named = config.as_ref().and_then(|c| c.get(CONFIG_AUTHORITY));
        if named.is_some_and(|a| !a.is_string())
            || (definition.requires_authority && !named.is_some_and(Value::is_string))
        {
            return Err(CapabilityError::ConfigInvalid(format!(
                "{capability} writes records and must be enabled with an `{CONFIG_AUTHORITY}` DID"
            )));
        }
        // Store the authority in the one form it is keyed and compared in.
        let config = config.map(|mut config| {
            if let Some(authority) = config_authority(Some(&config)) {
                config[CONFIG_AUTHORITY] = Value::String(authority);
            }
            config
        });
        let key = EnablementKey::of_config(capability, config.as_ref());
        let entry = CapabilityState {
            version: version.to_string(),
            enabled: true,
            config,
            enabled_at: Utc::now(),
            revision: 0,
            change_id: None,
        };
        self.classification
            .check(capability, definition, &entry)
            .map_err(CapabilityError::ConfigInvalid)?;
        self.change(key, move |current| {
            if current.is_some_and(|s| s.enabled) {
                return Err(CapabilityError::AlreadyEnabled);
            }
            Ok(entry.clone())
        })
        .await
    }

    /// Disable the enablement of `capability` for `authority` (`None`: the
    /// registry's own slot). Disable is not delete: the state is retained with
    /// `enabled: false` for audit; registry records are untouched.
    pub async fn disable(
        &self,
        capability: &str,
        authority: Option<&str>,
    ) -> Result<(), CapabilityError> {
        let key = EnablementKey::new(capability, authority);
        self.change(key, |current| match current {
            Some(entry) if entry.enabled => Ok(CapabilityState {
                enabled: false,
                ..entry.clone()
            }),
            _ => Err(CapabilityError::NotEnabled),
        })
        .await
        .map(|_| ())
    }

    /// Change the enablement `key` to what `decide` makes of its stored state
    /// (`None`: not stored), and answer the state written.
    ///
    /// Re-reads the store and decides against what it holds, then writes the
    /// one entry with a compare-and-swap on the revision read. When another
    /// writer (another replica) changed the entry in between, the write is
    /// refused and the change is decided again against the state that won,
    /// so no update is lost and a decision is never made on a stale state.
    ///
    /// Runs in a task of its own: a caller that stops waiting (a handler
    /// aborted by a timeout or a shutdown) cannot stop it between the write
    /// and the swap, so the store, the memory and the dispatchers still
    /// agree.
    ///
    /// Each store call is bounded by [`STORE_TIMEOUT`]. A write that timed
    /// out, or whose answer was lost, may still have landed: the change is
    /// then reported as a storage error although the store holds it, and this
    /// set's memory catches up on its next read of the store (the next
    /// capability task on a shared store, or the next change). A retry of
    /// the same change then answers as it would after a success
    /// (`alreadyEnabled`, `notEnabled`).
    ///
    /// A write can also land and be answered as a conflict: the DynamoDB SDK
    /// retries an attempt that timed out (3 s) although it had landed, and
    /// the retry's condition fails against the write itself. Each change
    /// stamps what it writes with its own [`CapabilityState::change_id`], so
    /// when the re-read after a conflict finds its own stamp, the change
    /// answers as written instead of `alreadyEnabled` / `notEnabled`.
    async fn change(
        &self,
        key: EnablementKey,
        decide: impl Fn(Option<&CapabilityState>) -> Result<CapabilityState, CapabilityError>
        + Send
        + 'static,
    ) -> Result<CapabilityState, CapabilityError> {
        let set = self.weak.upgrade().ok_or_else(|| {
            CapabilityError::Storage("the capability set is shutting down".to_string())
        })?;
        let arrived = self.reads_started();
        let change_id = uuid::Uuid::new_v4().to_string();
        tokio::spawn(async move {
            let _serial = set.sync.lock().await;
            for attempt in 0..MAX_CHANGE_ATTEMPTS {
                if attempt == 0 {
                    // A read that began after this change arrived is as
                    // fresh as one it would make (the write is checked
                    // against the revision anyway); its failure fails the
                    // change at once instead of queueing another read behind
                    // a stalled store.
                    set.read_coalesced(arrived).await?;
                } else {
                    // Back off a little more after each lost race, so
                    // replicas contending for one enablement spread out.
                    tokio::time::sleep(std::time::Duration::from_millis(5 << attempt)).await;
                    set.read_store().await?;
                }
                let current = set.state.read().await.get(&key).cloned();
                if let Some(landed) = current
                    .as_ref()
                    .filter(|s| s.change_id.as_deref() == Some(change_id.as_str()))
                {
                    // This change's own write landed although the store
                    // answered it as a conflict (a retried attempt).
                    return Ok(landed.clone());
                }
                let expected = current.as_ref().map_or(0, |s| s.revision);
                let next = CapabilityState {
                    change_id: Some(change_id.clone()),
                    ..decide(current.as_ref())?
                };
                match bounded("write", set.store.put(&key, expected, &next))
                    .await
                    .map_err(CapabilityError::Storage)?
                {
                    Put::Written(revision) => {
                        let next = CapabilityState { revision, ..next };
                        let mut state = set.state.write().await;
                        state.insert(key, next.clone());
                        set.rebuild(&state).await;
                        return Ok(next);
                    }
                    Put::Conflict => {
                        tracing::debug!(
                            "capability enablement {key:?} was changed by another replica; \
                             deciding again"
                        );
                    }
                }
            }
            Err(CapabilityError::Storage(format!(
                "capability enablement {key:?} kept changing under this change; gave up after \
                 {MAX_CHANGE_ATTEMPTS} attempts"
            )))
        })
        .await
        .map_err(|e| CapabilityError::Storage(format!("the state change did not finish: {e}")))?
    }

    /// Read the store and adopt what it holds as the state, swapping the
    /// dispatchers if it differs. Call with [`Self::sync`] held.
    ///
    /// Every read is counted when it begins, and its outcome kept, failure
    /// included, so callers that were waiting for a read can share it
    /// ([`Self::read_coalesced`]).
    async fn read_store(&self) -> Result<(), CapabilityError> {
        // Until this read finishes, a caller sharing it must not see the
        // previous read's success: if it never finishes (a panic in the
        // spawned task, or the future dropped), the counter has moved past
        // callers that arrived after that older read began.
        *self.last_read.lock().unwrap_or_else(|p| p.into_inner()) = Err(CapabilityError::Storage(
            "the capability store read did not finish".into(),
        ));
        self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let outcome = self.adopt_store().await;
        *self.last_read.lock().unwrap_or_else(|p| p.into_inner()) = outcome.clone();
        outcome
    }

    async fn adopt_store(&self) -> Result<(), CapabilityError> {
        let loaded = bounded("read", self.store.load())
            .await
            .map_err(CapabilityError::Storage)?;
        if *self.state.read().await != loaded {
            let mut state = self.state.write().await;
            *state = loaded;
            self.rebuild(&state).await;
        }
        Ok(())
    }

    /// How many reads of the store have begun.
    fn reads_started(&self) -> u64 {
        self.reads.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// A read of the store no older than the call that counted `arrived`
    /// reads begun: the last read's outcome, failure included, when it began
    /// after that (reads are serialised by [`Self::sync`], held here, so none
    /// is in progress); a read of its own otherwise. However many callers
    /// wait on a stalled store, each waits for at most the read in progress
    /// when it arrived and the one after it.
    async fn read_coalesced(&self, arrived: u64) -> Result<(), CapabilityError> {
        if self.reads_started() > arrived {
            return self
                .last_read
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone();
        }
        self.read_store().await
    }

    /// Converge on changes other registries made to a shared store: re-read
    /// it and adopt what it holds. Does nothing over a store only this set
    /// writes ([`CapabilityStateStore::is_shared`]).
    ///
    /// The [`TaskHandler`](crate::trust_tasks::TaskHandler) calls this before
    /// it authorises or serves any capability or governance task, so the
    /// decision is made on the state as it was read after the task arrived:
    /// a disable made on another replica is honoured from the next task on.
    /// Concurrent callers share one read that began after they called, and
    /// its outcome: when the store stalls, every caller waiting fails with
    /// the one read that timed out, after at most two [`STORE_TIMEOUT`]s
    /// (the read in progress when it arrived, and the next), however many
    /// are waiting.
    ///
    /// An error (the store unreachable, or no answer within
    /// [`STORE_TIMEOUT`]) leaves the state as it was; the handler then
    /// refuses the task as unavailable rather than decide on a state it could
    /// not confirm.
    ///
    /// It is also how this set catches up on its own write whose answer was
    /// lost (a timeout after the write was sent): the change was reported as
    /// failed, but if it landed, the next read adopts it.
    pub async fn refresh(&self) -> Result<(), CapabilityError> {
        if !self.store.is_shared() {
            return Ok(());
        }
        let set = self.weak.upgrade().ok_or_else(|| {
            CapabilityError::Storage("the capability set is shutting down".to_string())
        })?;
        let arrived = self.reads_started();
        // In a task of its own, so a caller that stops waiting cannot stop
        // it between adopting the state and swapping the dispatchers.
        tokio::spawn(async move {
            let _serial = set.sync.lock().await;
            set.read_coalesced(arrived).await
        })
        .await
        .map_err(|e| CapabilityError::Storage(format!("the state refresh did not finish: {e}")))?
    }

    /// Whether `slug` is a task whose handling depends on the enablement
    /// state: a capability's own task (write or read), or a
    /// `governance/capability/*` task.
    pub fn serves(&self, slug: &str) -> bool {
        self.classification.writes.contains_key(slug)
            || self.classification.reads.contains_key(slug)
            || [
                list_spec::Payload::type_uri(),
                enable_spec::Payload::type_uri(),
                disable_spec::Payload::type_uri(),
            ]
            .iter()
            .any(|uri| uri.slug() == slug)
    }

    /// Re-read a shared store every `every`, so the dispatcher handles a host
    /// reads directly ([`dispatcher`](Self::dispatcher),
    /// [`query_dispatcher`](Self::query_dispatcher)) converge on other
    /// registries' changes within that interval. Tasks handled by the
    /// [`TaskHandler`](crate::trust_tasks::TaskHandler) do not wait for it:
    /// they re-read the store first ([`refresh`](Self::refresh)). Answers
    /// whether it started one: not over a store only this set writes. Ends
    /// with `shutdown` (without waiting for a read in progress), or when the
    /// set is dropped; [`join_refresher`](Self::join_refresher) awaits it. A
    /// second call replaces the first refresher, which is stopped.
    pub fn spawn_refresher(
        self: &Arc<Self>,
        every: std::time::Duration,
        shutdown: tokio_util::sync::CancellationToken,
    ) -> bool {
        if !self.store.is_shared() {
            return false;
        }
        let weak = self.weak.clone();
        let task = tokio::spawn(async move {
            let mut ticks = tokio::time::interval(every);
            ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            ticks.tick().await;
            loop {
                tokio::select! {
                    _ = ticks.tick() => {}
                    _ = shutdown.cancelled() => return,
                }
                let Some(set) = weak.upgrade() else { return };
                // The read runs in a task of its own (`refresh`), so leaving
                // it on shutdown cannot split adopting a state from swapping
                // the dispatchers.
                tokio::select! {
                    refreshed = set.refresh() => if let Err(e) = refreshed {
                        tracing::warn!(
                            "could not re-read the shared capability state (capability tasks \
                             are refused until it can be read): {e:?}"
                        );
                    },
                    _ = shutdown.cancelled() => return,
                }
            }
        });
        let previous = self
            .refresher
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .replace(task);
        if let Some(previous) = previous {
            previous.abort();
        }
        true
    }

    /// Wait for the refresher ([`spawn_refresher`](Self::spawn_refresher)) to
    /// end, once its shutdown token is cancelled (it returns at once then); one
    /// still running after [`STORE_TIMEOUT`] is aborted. Does nothing when
    /// none was started, or it was already joined.
    pub async fn join_refresher(&self) {
        let task = self
            .refresher
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take();
        let Some(mut task) = task else { return };
        match tokio::time::timeout(STORE_TIMEOUT, &mut task).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) if e.is_cancelled() => {}
            Ok(Err(e)) => tracing::error!("the capability state refresher failed: {e}"),
            Err(_) => {
                tracing::warn!("the capability state refresher did not stop in time; aborted");
                task.abort();
            }
        }
    }

    /// List capabilities, one entry per enablement: the enabled ones, and with
    /// `include_available` also each available capability no authority has
    /// enabled (with no state) and each retained, disabled enablement.
    pub async fn list(&self, include_available: bool) -> Vec<ListedCapability> {
        let state = self.state.read().await;
        let mut listed = Vec::new();
        for (slug, definition) in &self.available {
            let mut any_enabled = false;
            for (key, entry) in of_capability(&state, slug) {
                any_enabled |= entry.enabled;
                if entry.enabled || include_available {
                    listed.push(ListedCapability {
                        manifest: definition.manifest.clone(),
                        authority: key.authority.clone(),
                        state: Some(entry.clone()),
                    });
                }
            }
            if !any_enabled && include_available {
                listed.push(ListedCapability {
                    manifest: definition.manifest.clone(),
                    authority: None,
                    state: None,
                });
            }
        }
        listed
    }

    /// The authorities `capability` is enabled for (`None`: the registry's own
    /// slot), in order.
    pub async fn authorities(&self, capability: &str) -> Vec<Option<String>> {
        self.state
            .read()
            .await
            .iter()
            .filter(|(key, s)| key.capability == capability && s.enabled)
            .map(|(key, _)| key.authority.clone())
            .collect()
    }

    /// Whether and under what authority `capability` is enabled for
    /// `authority`, with the dispatchers that go with that state. Enable and
    /// disable swap the dispatchers while holding the state lock, so reading
    /// them under it cannot pair one state with another's dispatcher.
    pub async fn snapshot(&self, capability: &str, authority: Option<&str>) -> CapabilitySnapshot {
        let key = EnablementKey::new(capability, authority);
        let state = self.state.read().await;
        let entry = state.get(&key).filter(|s| s.enabled);
        CapabilitySnapshot {
            enabled: entry.is_some(),
            authority: entry.and_then(|s| config_authority(s.config.as_ref())),
            dispatcher: self.dispatcher.read().await.clone(),
            tasks: match entry {
                Some(_) => self.tasks.read().await.get(&key).cloned(),
                None => None,
            },
        }
    }

    /// Whether `slug` is a write task of an available capability, enabled or
    /// not. Every task a capability does not declare as a read is one.
    pub fn is_write(&self, slug: &str) -> bool {
        self.classification.writes.contains_key(slug)
    }

    /// The capability `slug` is a write task of, if any.
    pub fn write_owner(&self, slug: &str) -> Option<&str> {
        self.classification.writes.get(slug).map(String::as_str)
    }

    /// Whether `capability` writes records and so needs an authority.
    pub fn requires_authority(&self, capability: &str) -> bool {
        self.available
            .get(capability)
            .is_some_and(|d| d.requires_authority)
    }

    async fn rebuild(&self, state: &CapabilityStates) {
        let composed = compose(
            &self.base,
            &self.base_query,
            &self.available,
            &self.classification,
            state,
            &self.weak,
        );
        *self.dispatcher.write().await = Arc::new(composed.admin);
        *self.query_dispatcher.write().await = Arc::new(composed.query);
        *self.tasks.write().await = composed.tasks;
    }
}

/// The enablements of `capability`, whatever their authority.
fn of_capability<'a>(
    state: &'a CapabilityStates,
    capability: &'a str,
) -> impl Iterator<Item = (&'a EnablementKey, &'a CapabilityState)> {
    state
        .iter()
        .filter(move |(key, _)| key.capability == capability)
}

/// Base registrations plus the governance surface plus every enabled
/// capability's registrations. The admin surface gets enable/disable/list and
/// the tasks of every capability with exactly one enablement; the read-only
/// (query) surface gets only list and the tasks capabilities declare as reads.
/// Each enablement also gets a dispatcher of its own write tasks.
///
/// An enablement whose state makes its capability register tasks other than
/// the ones it was classified with ([`Classification::check`]) is left out
/// everywhere, so none of its tasks can run unclassified.
fn compose(
    base: &(impl Fn() -> RegistryDispatcher + ?Sized),
    base_query: &(impl Fn() -> RegistryDispatcher + ?Sized),
    available: &BTreeMap<String, CapabilityDefinition>,
    classification: &Classification,
    state: &CapabilityStates,
    set: &std::sync::Weak<CapabilitySet>,
) -> Composed {
    let mut admin = with_governance(base(), set, true);
    let mut query = with_governance(base_query(), set, false);
    let mut tasks = BTreeMap::new();
    for (slug, definition) in available {
        let served: Vec<(&EnablementKey, &CapabilityState)> = of_capability(state, slug)
            .filter(|(_, entry)| entry.enabled)
            .filter(
                |(key, entry)| match classification.check(slug, definition, entry) {
                    Ok(()) => true,
                    Err(e) => {
                        tracing::error!(
                            "capability {slug} is enabled for {key:?} but not served: {e}"
                        );
                        false
                    }
                },
            )
            .collect();
        for (key, entry) in &served {
            tasks.insert(
                (*key).clone(),
                Arc::new((definition.register)(Dispatcher::new(), entry)),
            );
        }
        if let (Some(register_reads), Some((_, entry))) =
            (&definition.register_reads, served.first())
        {
            admin = register_reads(admin, entry);
            query = register_reads(query, entry);
        }
        if let [(_, entry)] = served.as_slice() {
            admin = (definition.register)(admin, entry);
        }
    }
    Composed {
        admin,
        query,
        tasks,
    }
}

/// `dispatcher` with `list`, and on the admin surface `enable` and `disable`.
fn with_governance(
    mut dispatcher: RegistryDispatcher,
    set: &std::sync::Weak<CapabilitySet>,
    admin: bool,
) -> RegistryDispatcher {
    let list_set = set.clone();
    dispatcher = dispatcher.on::<list_spec::Payload, _>(move |doc| -> TaskFuture {
        let set = list_set.clone();
        Box::pin(handle_list(set, doc))
    });
    if admin {
        let enable_set = set.clone();
        dispatcher = dispatcher.on::<enable_spec::Payload, _>(move |doc| -> TaskFuture {
            let set = enable_set.clone();
            Box::pin(handle_enable(set, doc))
        });
        let disable_set = set.clone();
        dispatcher = dispatcher.on::<disable_spec::Payload, _>(move |doc| -> TaskFuture {
            let set = disable_set.clone();
            Box::pin(handle_disable(set, doc))
        });
    }
    dispatcher
}

// --- governance wire handlers -------------------------------------------------

fn upgraded(set: &std::sync::Weak<CapabilitySet>) -> Result<Arc<CapabilitySet>, RejectReason> {
    set.upgrade().ok_or(RejectReason::InternalError {
        reason: "capability set is shutting down".to_string(),
    })
}

/// The error response for `e` on `doc`, with the task's own code for it.
fn reject_of<P>(doc: &TrustTask<P>, e: CapabilityError) -> trust_tasks_rs::ErrorResponse {
    match e {
        CapabilityError::UnknownCapability(detail) => {
            spec_error(doc, TaskError::UnknownCapability, detail)
        }
        CapabilityError::AlreadyEnabled => spec_error(
            doc,
            TaskError::AlreadyEnabled,
            "the capability is already enabled for this authority",
        ),
        CapabilityError::NotEnabled => spec_error(
            doc,
            TaskError::NotEnabled,
            "the capability is not enabled for this authority",
        ),
        CapabilityError::ConfigInvalid(detail) => spec_error(doc, TaskError::ConfigInvalid, detail),
        CapabilityError::AuthorityRequired(reason) => {
            doc.reject_with(new_id(), RejectReason::MalformedRequest { reason })
        }
        // Retryable: a failed save changed nothing, so the retry starts from
        // the same state.
        CapabilityError::Storage(reason) => {
            doc.reject_with(new_id(), RejectReason::InternalError { reason })
        }
    }
}

async fn handle_enable(
    set: std::sync::Weak<CapabilitySet>,
    doc: TrustTask<enable_spec::Payload>,
) -> TaskOutcome {
    let set = match upgraded(&set) {
        Ok(set) => set,
        Err(reason) => return Err(doc.reject_with(new_id(), reason)),
    };
    let capability = doc.payload.capability.to_string();
    let version = doc.payload.version.to_string();
    // A manifest is optional for a built-in capability; one that is sent must
    // be the host's own, since the host serves only what it has built in.
    if let (Some(sent), Some(own)) = (&doc.payload.manifest, set.manifest(&capability))
        && serde_json::to_value(sent).ok() != serde_json::to_value(own).ok()
    {
        return Err(reject_of(
            &doc,
            CapabilityError::ConfigInvalid(format!(
                "the manifest sent is not this host's built-in {capability} manifest"
            )),
        ));
    }
    // Codegen models the optional object as a Map defaulting to empty.
    let config = (!doc.payload.config.is_empty())
        .then(|| serde_json::Value::Object(doc.payload.config.clone().into_iter().collect()));
    let delegate = doc.payload.delegate.clone();
    match set.enable(&capability, &version, config, delegate).await {
        Ok(entry) => {
            let response: Result<enable_spec::Response, _> = enable_spec::Response::builder()
                .capability(capability)
                .version(Some(entry.version))
                .enabled(true)
                .enabled_at(Some(entry.enabled_at))
                .try_into();
            respond(&doc, response.map_err(|e| reject_build_err(&doc, e))?)
        }
        Err(e) => Err(reject_of(&doc, e)),
    }
}

/// The authority a disable acts on: the enablement the
/// [`TaskHandler`](crate::trust_tasks::TaskHandler) chose, or — dispatched
/// directly, by a host — the one the request names in `ext`, or the only one.
async fn disable_target(
    set: &CapabilitySet,
    capability: &str,
    payload: &disable_spec::Payload,
) -> Result<Option<String>, CapabilityError> {
    match acting() {
        Some(Acting::Enablement(key)) if key.capability == capability => Ok(key.authority),
        Some(_) => Err(CapabilityError::NotEnabled),
        None => {
            let payload = serde_json::to_value(payload)
                .map_err(|e| CapabilityError::AuthorityRequired(e.to_string()))?;
            if let Some(authority) =
                requested_authority(&payload).map_err(CapabilityError::AuthorityRequired)?
            {
                return Ok(Some(authority));
            }
            match set.authorities(capability).await.as_slice() {
                [] => Err(CapabilityError::NotEnabled),
                [only] => Ok(only.clone()),
                _ => Err(CapabilityError::AuthorityRequired(format!(
                    "{capability} is enabled for several authorities; name one in \
                     ext.{EXT_NAMESPACE}.{EXT_AUTHORITY}"
                ))),
            }
        }
    }
}

async fn handle_disable(
    set: std::sync::Weak<CapabilitySet>,
    doc: TrustTask<disable_spec::Payload>,
) -> TaskOutcome {
    let set = match upgraded(&set) {
        Ok(set) => set,
        Err(reason) => return Err(doc.reject_with(new_id(), reason)),
    };
    let capability = doc.payload.capability.to_string();
    let outcome = match disable_target(&set, &capability, &doc.payload).await {
        Ok(authority) => set.disable(&capability, authority.as_deref()).await,
        Err(e) => Err(e),
    };
    match outcome {
        Ok(()) => {
            let response: Result<disable_spec::Response, _> = disable_spec::Response::builder()
                .capability(capability)
                .enabled(false)
                .try_into();
            respond(&doc, response.map_err(|e| reject_build_err(&doc, e))?)
        }
        Err(e) => Err(reject_of(&doc, e)),
    }
}

/// One entry of the list response's `ext.`[`EXT_NAMESPACE`]`.entries`, which
/// says which enablement `capabilities[i]` is: the list specification's
/// entries have no member for it. A vendor extension: SPEC §4.5.1 leaves the
/// structure under a namespace to its owner, so no generated type exists.
#[derive(Serialize)]
struct ListedEntry {
    capability: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    authority: Option<String>,
}

/// The value of the list response's `ext.`[`EXT_NAMESPACE`] (see
/// [`ListedEntry`]).
#[derive(Serialize)]
struct ListedExt {
    entries: Vec<ListedEntry>,
}

/// The list specification carries its own generated copy of the shared
/// `governance/_shared` `CapabilityManifest`; the two copies are the same
/// schema, so every member maps across unchanged. The string members are
/// re-validated by the list copy's own constraints (identical to the enable
/// copy's), hence `TryFrom`.
impl TryFrom<&enable_spec::CapabilityManifest> for list_spec::CapabilityManifest {
    type Error = String;

    fn try_from(m: &enable_spec::CapabilityManifest) -> Result<Self, String> {
        use enable_spec::CapabilityManifestConsentClassValue as From;
        use list_spec::CapabilityManifestConsentClassValue as To;
        let text = |e: list_spec::error::ConversionError| e.to_string();
        let consent_class = m
            .consent_class
            .iter()
            .map(|(operation, class)| {
                let class = match class {
                    From::Normal => To::Normal,
                    From::Elevated => To::Elevated,
                    From::Destructive => To::Destructive,
                };
                (operation.clone(), class)
            })
            .collect();
        let ext = m
            .ext
            .as_ref()
            .map(|ext| {
                ext.iter()
                    .map(|(key, value)| {
                        Ok((
                            list_spec::ExtKey::try_from(key.as_str()).map_err(text)?,
                            value.clone(),
                        ))
                    })
                    .collect::<Result<HashMap<_, _>, String>>()
                    .map(list_spec::Ext::from)
            })
            .transpose()?;
        Ok(Self {
            capability: m.capability.as_str().try_into().map_err(text)?,
            config_schema: m.config_schema.clone(),
            consent_class,
            description: m
                .description
                .as_ref()
                .map(|d| d.as_str().try_into())
                .transpose()
                .map_err(text)?,
            ext,
            external_adapters: m
                .external_adapters
                .iter()
                .map(
                    |adapter| list_spec::CapabilityManifestExternalAdaptersItem {
                        kind: adapter.kind.clone(),
                        ref_: adapter.ref_.clone(),
                    },
                )
                .collect(),
            lifecycle_hooks: m.lifecycle_hooks.clone(),
            roles: m.roles.clone(),
            specs: m.specs.clone(),
            title: m
                .title
                .as_ref()
                .map(|t| t.as_str().try_into())
                .transpose()
                .map_err(text)?,
            version: m.version.as_str().try_into().map_err(text)?,
            vocabulary: m.vocabulary.as_ref().map(|vocabulary| {
                list_spec::CapabilityManifestVocabulary {
                    actions: vocabulary.actions.clone(),
                    resource_pattern: vocabulary.resource_pattern.clone(),
                }
            }),
        })
    }
}

async fn handle_list(
    set: std::sync::Weak<CapabilitySet>,
    doc: TrustTask<list_spec::Payload>,
) -> TaskOutcome {
    let set = match upgraded(&set) {
        Ok(set) => set,
        Err(reason) => return Err(doc.reject_with(new_id(), reason)),
    };
    // Absence means `enabled` — the most restrictive listing.
    let status = doc
        .payload
        .status
        .unwrap_or(list_spec::PayloadStatus::Enabled);
    let (include_enabled, include_available) = match status {
        list_spec::PayloadStatus::Enabled => (true, false),
        list_spec::PayloadStatus::Available => (false, true),
        list_spec::PayloadStatus::All => (true, true),
    };
    let mut entries: Vec<list_spec::ResponseCapabilitiesItem> = Vec::new();
    let mut described: Vec<ListedEntry> = Vec::new();
    for listed in set.list(include_available).await {
        let enabled = listed.state.as_ref().is_some_and(|s| s.enabled);
        if (enabled && !include_enabled) || (!enabled && !include_available) {
            continue;
        }
        // A retained, disabled enablement is reported once, as the
        // capability being available, not once per authority that left it.
        if !enabled && listed.state.is_some() {
            continue;
        }
        let manifest = list_spec::CapabilityManifest::try_from(&listed.manifest)
            .map_err(|e| reject_build_err(&doc, e))?;
        let enabled_at = listed
            .state
            .as_ref()
            .filter(|_| enabled)
            .map(|s| s.enabled_at);
        described.push(ListedEntry {
            capability: listed.manifest.capability.to_string(),
            authority: listed.authority.filter(|_| enabled),
        });
        let entry: Result<list_spec::ResponseCapabilitiesItem, _> =
            list_spec::ResponseCapabilitiesItem::builder()
                .manifest(manifest)
                .enabled(enabled)
                .enabled_at(enabled_at)
                .try_into();
        entries.push(entry.map_err(|e| reject_build_err(&doc, e))?);
    }
    let namespace =
        list_spec::ExtKey::try_from(EXT_NAMESPACE).map_err(|e| reject_build_err(&doc, e))?;
    let entries_ext = serde_json::to_value(ListedExt { entries: described })
        .map_err(|e| reject_build_err(&doc, e))?;
    let ext = list_spec::Ext::from(HashMap::from([(namespace, entries_ext)]));
    let response: Result<list_spec::Response, _> = list_spec::Response::builder()
        .capabilities(entries)
        .ext(Some(ext))
        .try_into();
    respond(&doc, response.map_err(|e| reject_build_err(&doc, e))?)
}

#[cfg(test)]
pub(crate) mod conformance;
#[cfg(feature = "storage-ddb")]
pub mod dynamodb;
pub mod git_trust;
#[cfg(feature = "storage-redis")]
pub mod redis;

#[cfg(test)]
mod tests {
    // `deprecated`: exercises the superseded 0.1 query types on purpose.
    #![allow(clippy::unwrap_used, clippy::expect_used, deprecated)]

    use super::*;
    use trust_tasks_rs::{Dispatcher, Payload, TrustTask};

    fn manifest(slug: &str) -> CapabilityManifest {
        CapabilityManifest::builder()
            .capability(slug)
            .version("0.1")
            .specs(vec![format!("{slug}/*")])
            .try_into()
            .unwrap()
    }

    /// A document carrying `payload`, typed by its generated payload type.
    fn doc<P: Payload + Serialize>(payload: P) -> TrustTask<Value> {
        TrustTask::new(
            new_id(),
            P::type_uri(),
            serde_json::to_value(payload).unwrap(),
        )
    }

    fn enable_payload(capability: &str, version: &str) -> enable_spec::Payload {
        enable_spec::Payload::builder()
            .capability(capability)
            .version(version)
            .try_into()
            .unwrap()
    }

    fn disable_payload(capability: &str) -> disable_spec::Payload {
        disable_spec::Payload::builder()
            .capability(capability)
            .try_into()
            .unwrap()
    }

    fn list_payload(status: Option<list_spec::PayloadStatus>) -> list_spec::Payload {
        list_spec::Payload::builder()
            .status(status)
            .try_into()
            .unwrap()
    }

    /// A capability whose handler answers `registry/recognition` (a type the
    /// empty base does not register).
    fn test_capability(slug: &str) -> CapabilityDefinition {
        use crate::specs::registry::recognition::v0_1 as recognition;
        CapabilityDefinition {
            manifest: manifest(slug),
            register: Arc::new(|d: RegistryDispatcher, _state: &CapabilityState| {
                d.on::<recognition::Payload, _>(|doc| -> crate::trust_tasks::TaskFuture {
                    Box::pin(async move {
                        Ok(doc.respond_with(
                            "urn:uuid:test-reply".to_string(),
                            // Raw JSON: a test-only capability's marker answer,
                            // not a registry/recognition response.
                            serde_json::json!({ "handled": true }),
                        ))
                    })
                })
            }),
            register_reads: None,
            validate_config: Some(Arc::new(|config: &Value| {
                if config.get("bad").is_some() {
                    Err("bad key".to_string())
                } else {
                    Ok(())
                }
            })),
            requires_authority: false,
        }
    }

    fn empty_base() -> Box<dyn Fn() -> RegistryDispatcher + Send + Sync> {
        Box::new(Dispatcher::new)
    }

    async fn set_with(slug: &str) -> Arc<CapabilitySet> {
        CapabilitySet::new(
            vec![test_capability(slug)],
            Box::new(MemoryCapabilityStore::default()),
            empty_base(),
            empty_base(),
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn a_record_writing_capability_needs_an_authority() {
        let mut definition = test_capability("writer");
        definition.requires_authority = true;
        let set = CapabilitySet::new(
            vec![definition],
            Box::new(MemoryCapabilityStore::default()),
            empty_base(),
            empty_base(),
        )
        .await
        .unwrap();

        assert!(matches!(
            set.enable("writer", "0.1", None, None).await,
            Err(CapabilityError::ConfigInvalid(_))
        ));
        set.enable(
            "writer",
            "0.1",
            Some(serde_json::json!({ "authority": "did:example:a" })),
            None,
        )
        .await
        .unwrap();
        let snapshot = set.snapshot("writer", Some("did:example:a")).await;
        assert!(snapshot.enabled);
        assert_eq!(snapshot.authority.as_deref(), Some("did:example:a"));
    }

    fn recognition_doc() -> TrustTask<Value> {
        use crate::specs::registry::recognition::v0_1 as recognition;
        let query: recognition::Payload = recognition::Payload::builder()
            .entity_id("e")
            .authority_id("a")
            .action("x")
            .resource("r")
            .try_into()
            .unwrap();
        TrustTask::new(
            "urn:uuid:q".to_string(),
            recognition::Payload::type_uri(),
            serde_json::to_value(query).unwrap(),
        )
    }

    async fn dispatch_ok(set: &CapabilitySet) -> bool {
        let d = set.dispatcher().read().await.clone();
        crate::trust_tasks::handle_document(&d, recognition_doc())
            .await
            .is_ok()
    }

    #[tokio::test]
    async fn disabled_capability_does_not_serve() {
        let set = set_with("demo").await;
        assert!(!dispatch_ok(&set).await, "off by default");
    }

    #[tokio::test]
    async fn enable_serves_and_disable_stops() {
        let set = set_with("demo").await;
        set.enable("demo", "0.1", None, None).await.unwrap();
        assert!(dispatch_ok(&set).await);

        set.disable("demo", None).await.unwrap();
        assert!(!dispatch_ok(&set).await, "disable swaps the handler out");
    }

    #[tokio::test]
    async fn error_taxonomy() {
        let set = set_with("demo").await;
        assert!(matches!(
            set.enable("nope", "0.1", None, None).await.unwrap_err(),
            CapabilityError::UnknownCapability(_)
        ));
        assert_eq!(
            set.enable("demo", "0.1", Some(serde_json::json!({"bad": 1})), None)
                .await
                .unwrap_err(),
            CapabilityError::ConfigInvalid("bad key".to_string())
        );
        set.enable("demo", "0.1", None, None).await.unwrap();
        assert_eq!(
            set.enable("demo", "0.1", None, None).await.unwrap_err(),
            CapabilityError::AlreadyEnabled
        );
        set.disable("demo", None).await.unwrap();
        assert_eq!(
            set.disable("demo", None).await.unwrap_err(),
            CapabilityError::NotEnabled
        );
    }

    #[tokio::test]
    async fn state_persists_and_restart_converges() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("capabilities.json");
        {
            let set = CapabilitySet::new(
                vec![test_capability("demo")],
                Box::new(FileCapabilityStore::new(&path)),
                empty_base(),
                empty_base(),
            )
            .await
            .unwrap();
            set.enable("demo", "0.1", None, None).await.unwrap();
        }
        // "Restart": a fresh set over the same store serves immediately.
        let set = CapabilitySet::new(
            vec![test_capability("demo")],
            Box::new(FileCapabilityStore::new(&path)),
            empty_base(),
            empty_base(),
        )
        .await
        .unwrap();
        assert!(dispatch_ok(&set).await, "enablement survives restart");
    }

    #[tokio::test]
    async fn enable_and_list_work_over_the_wire() {
        let set = set_with("demo").await;

        // governance/capability/enable as a dispatched document.
        let enable_doc = doc(enable_payload("demo", "0.1"));
        let d = set.dispatcher().read().await.clone();
        let out = crate::trust_tasks::handle_document(&d, enable_doc)
            .await
            .expect("enable succeeds");
        let enabled: enable_spec::Response = serde_json::from_value(out.payload).unwrap();
        assert!(enabled.enabled);
        assert!(
            dispatch_ok(&set).await,
            "capability serves after wire enable"
        );

        // list over the read-only surface reports it.
        let list_doc = doc(list_payload(None));
        let q = set.query_dispatcher().read().await.clone();
        let out = crate::trust_tasks::handle_document(&q, list_doc)
            .await
            .expect("list succeeds");
        let listed: list_spec::Response = serde_json::from_value(out.payload).unwrap();
        assert_eq!(listed.capabilities.len(), 1);

        // enable/disable are NOT on the read-only surface.
        let enable_on_query = doc(enable_payload("demo", "0.1"));
        assert!(
            crate::trust_tasks::handle_document(&q, enable_on_query)
                .await
                .is_err(),
            "writes must not route on the query surface"
        );
    }

    fn answers_handled<P: Payload + Send + 'static>(d: RegistryDispatcher) -> RegistryDispatcher {
        d.on::<P, _>(|doc| -> crate::trust_tasks::TaskFuture {
            Box::pin(async move {
                Ok(doc.respond_with(
                    "urn:uuid:test-reply".to_string(),
                    // Raw JSON: a test-only capability's marker answer.
                    serde_json::json!({ "handled": true }),
                ))
            })
        })
    }

    /// A capability with one write (`registry/recognition` 0.1) and one
    /// declared read (`registry/authorization` 0.1).
    fn capability_with_a_read(slug: &str) -> CapabilityDefinition {
        use crate::specs::registry::authorization::v0_1 as authorization;
        use crate::specs::registry::recognition::v0_1 as recognition;
        let mut definition = test_capability(slug);
        definition.register = Arc::new(|d: RegistryDispatcher, _: &CapabilityState| {
            answers_handled::<recognition::Payload>(d)
        });
        definition.register_reads = Some(Arc::new(|d: RegistryDispatcher, _: &CapabilityState| {
            answers_handled::<authorization::Payload>(d)
        }));
        definition
    }

    fn slugs(handle: &DispatcherHandle) -> BTreeSet<String> {
        slugs_of(&handle.try_read().expect("unlocked")).expect("valid URIs")
    }

    /// A capability's tasks are writes unless declared as reads: only the
    /// declared reads reach the read-only surface, whatever is enabled.
    #[tokio::test]
    async fn only_declared_reads_are_served_on_the_read_only_surface() {
        let set = CapabilitySet::new(
            vec![capability_with_a_read("demo")],
            Box::new(MemoryCapabilityStore::default()),
            empty_base(),
            empty_base(),
        )
        .await
        .unwrap();
        set.enable("demo", "0.1", None, None).await.unwrap();

        let admin = slugs(&set.dispatcher());
        assert!(admin.contains("registry/recognition"));
        assert!(admin.contains("registry/authorization"));
        let query = slugs(&set.query_dispatcher());
        assert!(!query.contains("registry/recognition"));
        assert!(query.contains("registry/authorization"));

        assert!(set.is_write("registry/recognition"));
        assert_eq!(set.write_owner("registry/recognition"), Some("demo"));
        assert!(!set.is_write("registry/authorization"));
    }

    /// The classification is known before the capability is enabled, so a
    /// task never changes kind when its capability is switched on.
    #[tokio::test]
    async fn writes_are_known_while_the_capability_is_off() {
        let set = set_with("demo").await;
        assert!(set.is_write("registry/recognition"));
        assert!(!slugs(&set.query_dispatcher()).contains("registry/recognition"));
    }

    #[tokio::test]
    async fn git_trust_tasks_are_not_on_the_read_only_surface() {
        let repo = Arc::new(crate::storage::adapters::local_storage::LocalStorage::new());
        let base_repo = repo.clone();
        let query_repo = repo.clone();
        let set = CapabilitySet::new(
            vec![git_trust::definition(repo).unwrap()],
            Box::new(MemoryCapabilityStore::default()),
            Box::new(move || crate::trust_tasks::build_dispatcher(base_repo.clone())),
            Box::new(move || crate::trust_tasks::build_query_dispatcher(query_repo.clone())),
        )
        .await
        .unwrap();
        let state = BTreeMap::from([(
            EnablementKey::new("git-trust", Some("did:example:a")),
            CapabilityState {
                enabled: true,
                config: Some(serde_json::json!({ "authority": "did:example:a" })),
                ..probe_state()
            },
        )]);
        let composed = compose(
            &*set.base,
            &*set.base_query,
            &set.available,
            &set.classification,
            &state,
            &set.weak,
        );

        let query = slugs_of(&composed.query).unwrap();
        assert!(!query.contains("git-trust/grant"));
        assert!(!query.contains("git-trust/revoke"));
        assert!(
            slugs_of(&composed.admin)
                .unwrap()
                .contains("git-trust/grant")
        );
        assert!(set.is_write("git-trust/grant"));
    }

    fn allows_extra(state: &CapabilityState) -> bool {
        state
            .config
            .as_ref()
            .is_some_and(|c| c.get("extra").is_some())
    }

    /// A capability whose `register` adds `registry/authorization` only when
    /// its config says `extra`: a task the probe state never shows.
    fn state_dependent_write(slug: &str) -> CapabilityDefinition {
        use crate::specs::registry::authorization::v0_1 as authorization;
        use crate::specs::registry::recognition::v0_1 as recognition;
        let mut definition = test_capability(slug);
        definition.register = Arc::new(|d: RegistryDispatcher, state: &CapabilityState| {
            let d = answers_handled::<recognition::Payload>(d);
            if allows_extra(state) {
                answers_handled::<authorization::Payload>(d)
            } else {
                d
            }
        });
        definition
    }

    /// A capability whose `register_reads` adds `registry/authorization` only
    /// when its config says `extra`.
    fn state_dependent_read(slug: &str) -> CapabilityDefinition {
        use crate::specs::registry::authorization::v0_1 as authorization;
        let mut definition = test_capability(slug);
        definition.register_reads = Some(Arc::new(
            |d: RegistryDispatcher, state: &CapabilityState| {
                if allows_extra(state) {
                    answers_handled::<authorization::Payload>(d)
                } else {
                    d
                }
            },
        ));
        definition
    }

    async fn set_of(
        definition: CapabilityDefinition,
        store: MemoryCapabilityStore,
    ) -> Arc<CapabilitySet> {
        CapabilitySet::new(
            vec![definition],
            Box::new(store),
            empty_base(),
            empty_base(),
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn enabling_a_state_that_adds_an_unclassified_task_is_refused() {
        for definition in [state_dependent_write("demo"), state_dependent_read("demo")] {
            let set = set_of(definition, MemoryCapabilityStore::default()).await;
            let refused = set
                .enable(
                    "demo",
                    "0.1",
                    Some(serde_json::json!({ "extra": true })),
                    None,
                )
                .await;
            assert!(
                matches!(refused, Err(CapabilityError::ConfigInvalid(_))),
                "{refused:?}"
            );
            assert!(!set.snapshot("demo", None).await.enabled);
            assert!(!slugs(&set.dispatcher()).contains("registry/authorization"));
            assert!(!slugs(&set.query_dispatcher()).contains("registry/authorization"));

            set.enable("demo", "0.1", None, None)
                .await
                .expect("the classified state is accepted");
        }
    }

    /// A persisted state (written before the check, or by hand) that makes a
    /// capability register an unclassified task leaves the whole capability
    /// unserved on both surfaces.
    #[tokio::test]
    async fn a_persisted_state_that_adds_an_unclassified_task_is_not_served() {
        for definition in [state_dependent_write("demo"), state_dependent_read("demo")] {
            let store = MemoryCapabilityStore::default();
            store
                .put(
                    &EnablementKey::new("demo", None),
                    0,
                    &CapabilityState {
                        config: Some(serde_json::json!({ "extra": true })),
                        ..probe_state()
                    },
                )
                .await
                .unwrap();
            let set = set_of(definition, store).await;
            for handle in [set.dispatcher(), set.query_dispatcher()] {
                let served = slugs(&handle);
                assert!(!served.contains("registry/authorization"));
                assert!(!served.contains("registry/recognition"));
            }
        }
    }

    /// The free-standing helpers treat a capability's write as a write when
    /// given the capability set.
    #[tokio::test]
    async fn the_standalone_helpers_classify_capability_writes() {
        use crate::specs::registry::recognition::v0_1 as recognition;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let runs = Arc::new(AtomicUsize::new(0));
        let counted = runs.clone();
        let mut definition = test_capability("demo");
        definition.register = Arc::new(move |d: RegistryDispatcher, _: &CapabilityState| {
            let counted = counted.clone();
            d.on::<recognition::Payload, _>(move |doc| -> crate::trust_tasks::TaskFuture {
                counted.fetch_add(1, Ordering::SeqCst);
                // Raw JSON: a test-only capability's empty answer.
                Box::pin(async move { Ok(doc.respond_with(new_id(), serde_json::json!({}))) })
            })
        });
        let set = set_of(definition, MemoryCapabilityStore::default()).await;
        set.enable("demo", "0.1", None, None).await.unwrap();

        let verifier =
            trust_tasks_rs::erase_verifier(trust_tasks_proof::affinidi::Verifier::for_did_key());
        assert_eq!(
            crate::trust_tasks::verify_write_proof(&verifier, Some(&set), &recognition_doc()).await,
            Err(RejectReason::ProofRequired)
        );

        let dispatcher = set.dispatcher().read().await.clone();
        let store = crate::dedup::MemoryMessageIdStore::default();
        for _ in 0..2 {
            crate::dedup::dispatch_idempotent(&dispatcher, &store, Some(&set), recognition_doc())
                .await
                .expect("answered");
        }
        assert_eq!(runs.load(Ordering::SeqCst), 1, "the redelivery is replayed");
    }

    async fn refused(definitions: Vec<CapabilityDefinition>) -> String {
        match CapabilitySet::new(
            definitions,
            Box::new(MemoryCapabilityStore::default()),
            empty_base(),
            empty_base(),
        )
        .await
        {
            Ok(_) => panic!("the set should be refused"),
            Err(e) => e,
        }
    }

    #[tokio::test]
    async fn a_task_declared_as_both_read_and_write_is_refused() {
        use crate::specs::registry::recognition::v0_1 as recognition;
        let mut definition = test_capability("demo");
        definition.register_reads = Some(Arc::new(|d: RegistryDispatcher, _: &CapabilityState| {
            answers_handled::<recognition::Payload>(d)
        }));
        assert!(
            refused(vec![definition])
                .await
                .contains("declares registry/recognition as a read")
        );
    }

    #[tokio::test]
    async fn a_registry_write_declared_as_a_read_is_refused() {
        use crate::specs::registry::record::put::v0_3 as put;
        let mut definition = test_capability("demo");
        definition.register_reads = Some(Arc::new(|d: RegistryDispatcher, _: &CapabilityState| {
            answers_handled::<put::Payload>(d)
        }));
        assert!(
            refused(vec![definition])
                .await
                .contains("registry/record/put")
        );
    }

    #[tokio::test]
    async fn two_capabilities_registering_one_task_are_refused() {
        assert!(
            refused(vec![test_capability("one"), test_capability("two")])
                .await
                .contains("both register")
        );
    }

    #[tokio::test]
    async fn a_capability_registering_a_registry_task_is_refused() {
        let error = match CapabilitySet::new(
            vec![test_capability("demo")],
            Box::new(MemoryCapabilityStore::default()),
            empty_base(),
            Box::new(|| {
                answers_handled::<crate::specs::registry::recognition::v0_1::Payload>(
                    Dispatcher::new(),
                )
            }),
        )
        .await
        {
            Ok(_) => panic!("the set should be refused"),
            Err(e) => e,
        };
        assert!(error.contains("which the registry itself serves"));
    }

    #[tokio::test]
    async fn list_defaults_to_enabled_only() {
        let set = set_with("demo").await;
        assert!(set.list(false).await.is_empty());
        assert_eq!(set.list(true).await.len(), 1, "available listing");
        set.enable("demo", "0.1", None, None).await.unwrap();
        assert_eq!(set.list(false).await.len(), 1);
    }

    // --- a failed save changes nothing ----------------------------------------

    /// A shared store whose next save fails, once, and whose reads fail while
    /// `fail_load` is set.
    #[derive(Default)]
    struct FailingOnce {
        inner: MemoryCapabilityStore,
        fail_next: std::sync::atomic::AtomicBool,
        fail_load: std::sync::atomic::AtomicBool,
    }

    #[async_trait::async_trait]
    impl CapabilityStateStore for Arc<FailingOnce> {
        async fn load(&self) -> Result<CapabilityStates, String> {
            if self.fail_load.load(std::sync::atomic::Ordering::SeqCst) {
                return Err("unreachable".to_string());
            }
            self.inner.load().await
        }
        fn is_shared(&self) -> bool {
            true
        }
        async fn put(
            &self,
            key: &EnablementKey,
            expected: u64,
            state: &CapabilityState,
        ) -> Result<Put, String> {
            if self
                .fail_next
                .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                return Err("disk full".to_string());
            }
            self.inner.put(key, expected, state).await
        }
    }

    #[tokio::test]
    async fn a_failed_save_leaves_memory_disk_and_dispatchers_agreeing() {
        let store = Arc::new(FailingOnce::default());
        let set = CapabilitySet::new(
            vec![test_capability("demo")],
            Box::new(store.clone()),
            empty_base(),
            empty_base(),
        )
        .await
        .unwrap();

        store
            .fail_next
            .store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(matches!(
            set.enable("demo", "0.1", None, None).await,
            Err(CapabilityError::Storage(_))
        ));
        assert!(!set.snapshot("demo", None).await.enabled);
        assert!(set.list(false).await.is_empty());
        assert!(!dispatch_ok(&set).await);
        assert!(store.load().await.unwrap().is_empty());
        set.enable("demo", "0.1", None, None)
            .await
            .expect("the retry starts from the same state");
        assert!(dispatch_ok(&set).await);

        store
            .fail_next
            .store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(matches!(
            set.disable("demo", None).await,
            Err(CapabilityError::Storage(_))
        ));
        assert!(set.snapshot("demo", None).await.enabled);
        assert!(dispatch_ok(&set).await, "still served, as the disk says");
        assert!(store.load().await.unwrap().values().all(|s| s.enabled));
        set.disable("demo", None).await.expect("the retry disables");
        assert!(!dispatch_ok(&set).await);
    }

    // --- version, delegate and manifest ---------------------------------------

    #[tokio::test]
    async fn only_the_manifest_version_is_enabled() {
        let set = set_with("demo").await;
        assert!(matches!(
            set.enable("demo", "9.9", None, None).await,
            Err(CapabilityError::UnknownCapability(_))
        ));
        assert!(matches!(
            set.enable(
                "demo",
                "0.1",
                None,
                Some("did:example:companion".to_string())
            )
            .await,
            Err(CapabilityError::ConfigInvalid(_))
        ));
        assert!(!set.snapshot("demo", None).await.enabled);
    }

    async fn wire(set: &CapabilitySet, doc: TrustTask<Value>) -> Result<Value, (String, bool)> {
        let d = set.dispatcher().read().await.clone();
        crate::trust_tasks::handle_document(&d, doc)
            .await
            .map(|out| out.payload)
            .map_err(|err| (err.payload.code.to_string(), err.payload.retryable))
    }

    #[tokio::test]
    async fn enable_and_disable_answer_their_specifications_codes() {
        let set = set_with("demo").await;
        let refused = |code: &str| Err((code.to_string(), false));
        assert_eq!(
            wire(&set, doc(enable_payload("nope", "0.1"))).await,
            refused("governance/capability/enable:unknownCapability")
        );
        assert_eq!(
            wire(&set, doc(enable_payload("demo", "0.2"))).await,
            refused("governance/capability/enable:unknownCapability")
        );
        let mut bad_config = enable_payload("demo", "0.1");
        bad_config.config = serde_json::Map::from_iter([("bad".to_string(), Value::from(1))]);
        assert_eq!(
            wire(&set, doc(bad_config)).await,
            refused("governance/capability/enable:configInvalid")
        );
        let mut delegated = enable_payload("demo", "0.1");
        delegated.delegate = Some("did:example:companion".to_string());
        delegated.manifest = Some(manifest("demo"));
        assert_eq!(
            wire(&set, doc(delegated)).await,
            refused("governance/capability/enable:configInvalid")
        );
        let mut other = manifest("demo");
        other.title = Some("Not the built-in one".parse().unwrap());
        let mut foreign_manifest = enable_payload("demo", "0.1");
        foreign_manifest.manifest = Some(other);
        assert_eq!(
            wire(&set, doc(foreign_manifest)).await,
            refused("governance/capability/enable:configInvalid")
        );
        let mut own_manifest = enable_payload("demo", "0.1");
        own_manifest.manifest = Some(manifest("demo"));
        wire(&set, doc(own_manifest))
            .await
            .expect("the host's own manifest is accepted");
        assert_eq!(
            wire(&set, doc(enable_payload("demo", "0.1"))).await,
            refused("governance/capability/enable:alreadyEnabled")
        );

        wire(&set, doc(disable_payload("demo")))
            .await
            .expect("disabled");
        assert_eq!(
            wire(&set, doc(disable_payload("demo"))).await,
            refused("governance/capability/disable:notEnabled")
        );
    }

    // --- enablement per authority ----------------------------------------------

    async fn writer_set() -> Arc<CapabilitySet> {
        let mut definition = test_capability("writer");
        definition.requires_authority = true;
        set_of(definition, MemoryCapabilityStore::default()).await
    }

    fn for_authority(authority: &str) -> Option<Value> {
        Some(serde_json::json!({ "authority": authority }))
    }

    #[tokio::test]
    async fn each_authority_enables_and_disables_its_own() {
        let set = writer_set().await;
        set.enable("writer", "0.1", for_authority("did:example:a"), None)
            .await
            .unwrap();
        set.enable("writer", "0.1", for_authority("did:example:b"), None)
            .await
            .expect("another authority enables independently");
        assert_eq!(
            set.enable("writer", "0.1", for_authority("did:example:a"), None)
                .await
                .unwrap_err(),
            CapabilityError::AlreadyEnabled
        );
        assert_eq!(
            set.authorities("writer").await,
            vec![
                Some("did:example:a".to_string()),
                Some("did:example:b".to_string())
            ]
        );
        for authority in ["did:example:a", "did:example:b"] {
            let snapshot = set.snapshot("writer", Some(authority)).await;
            assert!(snapshot.enabled && snapshot.tasks.is_some());
            assert_eq!(snapshot.authority.as_deref(), Some(authority));
        }
        // With two, the live admin dispatcher does not pick one.
        assert!(!slugs(&set.dispatcher()).contains("registry/recognition"));

        set.disable("writer", Some("did:example:a")).await.unwrap();
        assert!(!set.snapshot("writer", Some("did:example:a")).await.enabled);
        assert!(set.snapshot("writer", Some("did:example:b")).await.enabled);
        assert!(slugs(&set.dispatcher()).contains("registry/recognition"));
    }

    #[tokio::test]
    async fn a_did_scid_authority_is_one_enablement_with_or_without_its_locator() {
        let set = writer_set().await;
        set.enable(
            "writer",
            "0.1",
            for_authority("did:scid:vh:1:abc?src=example.com"),
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            set.enable("writer", "0.1", for_authority("did:scid:vh:1:abc"), None)
                .await
                .unwrap_err(),
            CapabilityError::AlreadyEnabled
        );
        assert_eq!(
            set.snapshot("writer", Some("did:scid:vh:1:abc"))
                .await
                .authority
                .as_deref(),
            Some("did:scid:vh:1:abc")
        );
    }

    #[tokio::test]
    async fn list_reports_each_enablement_with_its_authority() {
        let set = writer_set().await;
        for authority in ["did:example:a", "did:example:b"] {
            set.enable("writer", "0.1", for_authority(authority), None)
                .await
                .unwrap();
        }
        let list = |status: Option<list_spec::PayloadStatus>| {
            let set = set.clone();
            async move {
                let q = set.query_dispatcher().read().await.clone();
                let out = crate::trust_tasks::handle_document(&q, doc(list_payload(status)))
                    .await
                    .expect("listed");
                serde_json::from_value::<list_spec::Response>(out.payload).unwrap()
            }
        };
        // The registry's vendor extension: opaque to the spec (SPEC §4.5.1),
        // so its content is compared as JSON.
        let entries = |out: &list_spec::Response| {
            let namespace = list_spec::ExtKey::try_from(EXT_NAMESPACE).unwrap();
            out.ext.as_ref().unwrap()[&namespace]["entries"].clone()
        };
        let out = list(None).await;
        assert_eq!(out.capabilities.len(), 2);
        assert_eq!(
            entries(&out),
            serde_json::json!([
                { "capability": "writer", "authority": "did:example:a" },
                { "capability": "writer", "authority": "did:example:b" },
            ])
        );
        assert!(
            list(Some(list_spec::PayloadStatus::Available))
                .await
                .capabilities
                .is_empty()
        );

        set.disable("writer", Some("did:example:a")).await.unwrap();
        set.disable("writer", Some("did:example:b")).await.unwrap();
        let out = list(Some(list_spec::PayloadStatus::All)).await;
        assert_eq!(out.capabilities.len(), 1, "{out:?}");
        assert!(!out.capabilities[0].enabled);
        assert_eq!(
            entries(&out),
            serde_json::json!([{ "capability": "writer" }])
        );
    }

    // --- the state file ---------------------------------------------------------

    #[tokio::test]
    async fn the_single_slot_state_file_is_migrated() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("capabilities.json");
        std::fs::write(
            &path,
            serde_json::json!({
                "git-trust": {
                    "version": "0.1",
                    "enabled": true,
                    "config": { "authority": "did:scid:vh:1:abc?src=example.com" },
                    "enabledAt": "2026-01-01T00:00:00Z",
                    "delegate": "did:example:ignored",
                },
                "demo": {
                    "version": "0.1",
                    "enabled": false,
                    "config": null,
                    "enabledAt": "2026-01-01T00:00:00Z",
                }
            })
            .to_string(),
        )
        .unwrap();
        let store = FileCapabilityStore::new(&path);
        let states = store.load().await.expect("the old format loads");
        let keys: Vec<&EnablementKey> = states.keys().collect();
        assert_eq!(
            keys,
            vec![
                &EnablementKey::new("demo", None),
                &EnablementKey::new("git-trust", Some("did:scid:vh:1:abc")),
            ]
        );

        // Any write rewrites the whole file in the per-authority format; the
        // migrated entries start at revision 0.
        let demo = EnablementKey::new("demo", None);
        assert_eq!(states[&demo].revision, 0);
        assert_eq!(
            store.put(&demo, 0, &states[&demo]).await.unwrap(),
            Put::Written(1)
        );
        let written: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(written["format"], STATE_FORMAT);
        assert_eq!(written["enablements"][1]["authority"], "did:scid:vh:1:abc");
        assert!(written["enablements"][1].get("delegate").is_none());
        assert_eq!(written["enablements"][0]["revision"], 1);
        let reloaded = store.load().await.unwrap();
        assert_eq!(reloaded.keys().collect::<Vec<_>>(), keys);
        assert_eq!(reloaded[&demo].revision, 1);
    }

    /// A state file written by this release (with revisions) is read by the
    /// releases before it, which ignore the member: a downgrade keeps the
    /// state.
    #[test]
    fn a_state_file_with_revisions_reads_without_them() {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        #[allow(dead_code)]
        struct EarlierState {
            version: String,
            enabled: bool,
            #[serde(default)]
            config: Option<Value>,
            enabled_at: DateTime<Utc>,
        }
        #[derive(Deserialize)]
        #[allow(dead_code)]
        struct EarlierEnablement {
            capability: String,
            #[serde(default)]
            authority: Option<String>,
            #[serde(flatten)]
            state: EarlierState,
        }
        #[derive(Deserialize)]
        #[allow(dead_code)]
        struct EarlierFile {
            format: u64,
            enablements: Vec<EarlierEnablement>,
        }
        let states = BTreeMap::from([(
            EnablementKey::new("demo", None),
            CapabilityState {
                revision: 7,
                ..probe_state()
            },
        )]);
        let text = encode_states(&states).unwrap();
        let earlier: EarlierFile = serde_json::from_str(&text).unwrap();
        assert_eq!(earlier.format, STATE_FORMAT);
        assert!(earlier.enablements[0].state.enabled);
        assert_eq!(decode_states(&text).unwrap(), states);
    }

    #[test]
    fn a_state_file_of_an_unknown_format_is_refused() {
        assert!(decode_states(r#"{ "format": 3, "enablements": [] }"#).is_err());
    }

    // --- the store conformance suite, and replicas over one store -------------

    fn memory_fixture() -> conformance::CapabilityStoreFixture {
        conformance::CapabilityStoreFixture::new(|| {
            Box::pin(async {
                let store = MemoryCapabilityStore::default();
                (
                    Box::new(store.clone()) as Box<dyn CapabilityStateStore>,
                    Box::new(store) as Box<dyn CapabilityStateStore>,
                )
            })
        })
    }

    /// Two handles on one file (one store and its clone, as one process
    /// holds it), each test in a file of its own.
    fn file_fixture() -> conformance::CapabilityStoreFixture {
        conformance::CapabilityStoreFixture::new(|| {
            Box::pin(async {
                let path = std::env::temp_dir()
                    .join(format!("tr-capabilities-{}.json", uuid::Uuid::new_v4()));
                let store = FileCapabilityStore::new(path);
                (
                    Box::new(store.clone()) as Box<dyn CapabilityStateStore>,
                    Box::new(store) as Box<dyn CapabilityStateStore>,
                )
            })
        })
    }

    conformance::capability_store_conformance_tests!(memory_caps, Some(memory_fixture()));
    conformance::capability_store_conformance_tests!(file_caps, Some(file_fixture()));
    conformance::replica_tests!(memory_replicas, Some(memory_fixture()));

    /// A set over a store only it writes (a state file) does not re-read it
    /// before tasks: it trusts what it holds.
    #[tokio::test]
    async fn a_set_over_its_own_file_does_not_re_read_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("capabilities.json");
        let set = CapabilitySet::new(
            vec![test_capability("demo")],
            Box::new(FileCapabilityStore::new(&path)),
            empty_base(),
            empty_base(),
        )
        .await
        .unwrap();
        std::fs::write(&path, "not json").unwrap();
        set.refresh().await.expect("not read, so not refused");
        assert!(!set.spawn_refresher(
            std::time::Duration::from_millis(10),
            tokio_util::sync::CancellationToken::new()
        ));
    }

    /// A shared store that cannot be read fails the refresh, and leaves the
    /// state as it was.
    #[tokio::test]
    async fn an_unreadable_shared_store_fails_the_refresh() {
        let store = Arc::new(FailingOnce::default());
        let set = CapabilitySet::new(
            vec![test_capability("demo")],
            Box::new(store.clone()),
            empty_base(),
            empty_base(),
        )
        .await
        .unwrap();
        set.enable("demo", "0.1", None, None).await.unwrap();
        store
            .fail_load
            .store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(matches!(
            set.refresh().await,
            Err(CapabilityError::Storage(_))
        ));
        assert!(set.snapshot("demo", None).await.enabled);
    }

    /// A shared store whose calls never answer once `stalled` is set.
    #[derive(Default)]
    struct Stalling {
        inner: MemoryCapabilityStore,
        stalled: std::sync::atomic::AtomicBool,
    }

    #[async_trait::async_trait]
    impl CapabilityStateStore for Arc<Stalling> {
        async fn load(&self) -> Result<CapabilityStates, String> {
            if self.stalled.load(std::sync::atomic::Ordering::SeqCst) {
                std::future::pending::<()>().await;
            }
            self.inner.load().await
        }
        async fn put(
            &self,
            key: &EnablementKey,
            expected: u64,
            state: &CapabilityState,
        ) -> Result<Put, String> {
            if self.stalled.load(std::sync::atomic::Ordering::SeqCst) {
                std::future::pending::<()>().await;
            }
            self.inner.put(key, expected, state).await
        }
    }

    /// A store call that never answers is abandoned after STORE_TIMEOUT, so
    /// it fails the task instead of holding every capability task of the
    /// registry; once the store answers again, so does the set.
    #[tokio::test(start_paused = true)]
    async fn a_stalled_store_call_is_abandoned() {
        let store = Arc::new(Stalling::default());
        let set = CapabilitySet::new(
            vec![test_capability("demo")],
            Box::new(store.clone()),
            empty_base(),
            empty_base(),
        )
        .await
        .unwrap();
        store
            .stalled
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let started = tokio::time::Instant::now();
        assert!(matches!(
            set.refresh().await,
            Err(CapabilityError::Storage(_))
        ));
        assert!(matches!(
            set.enable("demo", "0.1", None, None).await,
            Err(CapabilityError::Storage(_))
        ));
        assert!(started.elapsed() <= STORE_TIMEOUT * 2 + std::time::Duration::from_secs(1));
        store
            .stalled
            .store(false, std::sync::atomic::Ordering::SeqCst);
        set.enable("demo", "0.1", None, None)
            .await
            .expect("the store answers again");
        assert!(dispatch_ok(&set).await);
    }

    /// Callers waiting on a stalled store share the read that stalls: five
    /// refreshes and three changes arriving together all fail within one
    /// STORE_TIMEOUT, not one after another.
    #[tokio::test(start_paused = true)]
    async fn waiters_on_a_stalled_store_share_its_failure() {
        let store = Arc::new(Stalling::default());
        let set = CapabilitySet::new(
            vec![test_capability("demo")],
            Box::new(store.clone()),
            empty_base(),
            empty_base(),
        )
        .await
        .unwrap();
        store
            .stalled
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let started = tokio::time::Instant::now();
        let refreshes = futures::future::join_all((0..5).map(|_| set.refresh()));
        let changes = futures::future::join_all((0..3).map(|n| {
            set.enable(
                "demo",
                "0.1",
                Some(serde_json::json!({ CONFIG_AUTHORITY: format!("did:example:{n}") })),
                None,
            )
        }));
        let (refreshes, changes) = tokio::join!(refreshes, changes);
        assert!(
            refreshes
                .iter()
                .all(|r| matches!(r, Err(CapabilityError::Storage(_))))
        );
        assert!(
            changes
                .iter()
                .all(|r| matches!(r, Err(CapabilityError::Storage(_))))
        );
        let elapsed = started.elapsed();
        assert!(
            elapsed < STORE_TIMEOUT + std::time::Duration::from_secs(1),
            "{elapsed:?}"
        );
    }

    /// A shared store whose next put lands but is answered as a conflict, as
    /// a DynamoDB SDK retry of a landed attempt is.
    #[derive(Default)]
    struct LandsAsConflict {
        inner: MemoryCapabilityStore,
        next: std::sync::atomic::AtomicBool,
    }

    #[async_trait::async_trait]
    impl CapabilityStateStore for Arc<LandsAsConflict> {
        async fn load(&self) -> Result<CapabilityStates, String> {
            self.inner.load().await
        }
        async fn put(
            &self,
            key: &EnablementKey,
            expected: u64,
            state: &CapabilityState,
        ) -> Result<Put, String> {
            let written = self.inner.put(key, expected, state).await?;
            if self.next.swap(false, std::sync::atomic::Ordering::SeqCst) {
                return Ok(Put::Conflict);
            }
            Ok(written)
        }
    }

    /// A change whose own write landed but was answered as a conflict
    /// answers as written, not as `alreadyEnabled` / `notEnabled`; another
    /// change's write still answers as before.
    #[tokio::test]
    async fn a_change_recognises_its_own_write_after_a_conflict() {
        let store = Arc::new(LandsAsConflict::default());
        let set = CapabilitySet::new(
            vec![test_capability("demo")],
            Box::new(store.clone()),
            empty_base(),
            empty_base(),
        )
        .await
        .unwrap();
        store.next.store(true, std::sync::atomic::Ordering::SeqCst);
        let enabled = set.enable("demo", "0.1", None, None).await.unwrap();
        assert_eq!(enabled.revision, 1, "written once");
        assert!(enabled.change_id.is_some());
        assert!(dispatch_ok(&set).await);
        store.next.store(true, std::sync::atomic::Ordering::SeqCst);
        set.disable("demo", None).await.expect("its own disable");
        assert!(!dispatch_ok(&set).await);
        assert_eq!(
            set.disable("demo", None).await,
            Err(CapabilityError::NotEnabled),
            "a later disable still answers notEnabled"
        );
    }

    /// The background refresher brings a set's dispatcher handles in line
    /// with another set's change, without any task.
    #[tokio::test]
    async fn the_refresher_converges_the_dispatcher_handles() {
        let store = MemoryCapabilityStore::default();
        let set_over = |store: MemoryCapabilityStore| async move {
            CapabilitySet::new(
                vec![test_capability("demo")],
                Box::new(store),
                empty_base(),
                empty_base(),
            )
            .await
            .unwrap()
        };
        let (a, b) = (set_over(store.clone()).await, set_over(store).await);
        let shutdown = tokio_util::sync::CancellationToken::new();
        assert!(
            b.spawn_refresher(std::time::Duration::from_millis(20), shutdown.clone()),
            "a shared store is re-read"
        );
        a.enable("demo", "0.1", None, None).await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while !dispatch_ok(&b).await {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("B's dispatcher serves A's enable");
        shutdown.cancel();
        tokio::time::timeout(std::time::Duration::from_secs(1), b.join_refresher())
            .await
            .expect("the refresher stops at once on shutdown");
    }
}
