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
//! Enable and disable build the changed state as a copy, save the copy, and
//! only then replace the in-memory state and swap the dispatchers. A failed
//! save changes nothing: memory, disk and dispatchers keep agreeing, and the
//! retry the `internalError` invites starts from the same state.

// `TaskOutcome`'s error is a whole `trust-task-error` document, which is large
// by design; boxing it would only move the allocation onto every caller. The
// router allows this lint for the same reason.
#![allow(clippy::result_large_err)]

use std::collections::{BTreeMap, BTreeSet};
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
use crate::trust_tasks::payloads::reserialize;
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
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityState {
    pub version: String,
    pub enabled: bool,
    #[serde(default)]
    pub config: Option<Value>,
    pub enabled_at: DateTime<Utc>,
}

/// Every enablement the registry knows of, enabled or retained after a
/// disable.
pub type CapabilityStates = BTreeMap<EnablementKey, CapabilityState>;

/// Durable store for enablement state.
pub trait CapabilityStateStore: Send + Sync {
    fn load(&self) -> Result<CapabilityStates, String>;
    fn save(&self, state: &CapabilityStates) -> Result<(), String>;
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
            if config_authority(stored.state.config.as_ref()) != key.authority {
                return Err(format!(
                    "{key:?} is listed under an authority its config does not name"
                ));
            }
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

/// JSON-file-backed store. A save writes a temporary file, syncs it, renames
/// it over the state file and syncs the directory, so the file is either the
/// old state or the new one, across a power loss too.
pub struct FileCapabilityStore {
    path: PathBuf,
}

impl FileCapabilityStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl CapabilityStateStore for FileCapabilityStore {
    fn load(&self) -> Result<CapabilityStates, String> {
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

    fn save(&self, state: &CapabilityStates) -> Result<(), String> {
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
}

/// In-memory store for tests and ephemeral deployments.
#[derive(Default)]
pub struct MemoryCapabilityStore {
    state: std::sync::Mutex<CapabilityStates>,
}

impl CapabilityStateStore for MemoryCapabilityStore {
    fn load(&self) -> Result<CapabilityStates, String> {
        Ok(self.state.lock().unwrap_or_else(|p| p.into_inner()).clone())
    }
    fn save(&self, state: &CapabilityStates) -> Result<(), String> {
        *self.state.lock().unwrap_or_else(|p| p.into_inner()) = state.clone();
        Ok(())
    }
}

/// A live, swappable dispatcher the transport bindings read through.
pub type DispatcherHandle = Arc<RwLock<Arc<RegistryDispatcher>>>;

/// Errors from enable/disable. The governance handlers below answer each with
/// the specification's extension code for it
/// (`governance/capability/enable:unknownCapability`, ...).
#[derive(Debug, PartialEq)]
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
    weak: std::sync::Weak<Self>,
}

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
    pub fn new(
        available: Vec<CapabilityDefinition>,
        store: Box<dyn CapabilityStateStore>,
        base: Box<dyn Fn() -> RegistryDispatcher + Send + Sync>,
        base_query: Box<dyn Fn() -> RegistryDispatcher + Send + Sync>,
    ) -> Result<Arc<Self>, String> {
        let store: Arc<dyn CapabilityStateStore> = Arc::from(store);
        let state = store.load()?;
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
        };
        self.classification
            .check(capability, definition, &entry)
            .map_err(CapabilityError::ConfigInvalid)?;
        self.change(move |state| {
            if state.get(&key).is_some_and(|s| s.enabled) {
                return Err(CapabilityError::AlreadyEnabled);
            }
            let mut next = state.clone();
            next.insert(key, entry.clone());
            Ok((next, entry))
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
        self.change(move |state| {
            if !state.get(&key).is_some_and(|s| s.enabled) {
                return Err(CapabilityError::NotEnabled);
            }
            let mut next = state.clone();
            if let Some(entry) = next.get_mut(&key) {
                entry.enabled = false;
            }
            Ok((next, ()))
        })
        .await
    }

    /// Apply the change `decide` makes to the state, under the state lock, in
    /// a task of its own: a caller that stops waiting (a handler aborted by a
    /// timeout or a shutdown) cannot stop it between the save and the swap,
    /// so the file, the memory and the dispatchers still agree.
    async fn change<T: Send + 'static>(
        &self,
        decide: impl FnOnce(&CapabilityStates) -> Result<(CapabilityStates, T), CapabilityError>
        + Send
        + 'static,
    ) -> Result<T, CapabilityError> {
        let set = self.weak.upgrade().ok_or_else(|| {
            CapabilityError::Storage("the capability set is shutting down".to_string())
        })?;
        tokio::spawn(async move {
            let mut state = set.state.write().await;
            let (next, out) = decide(&state)?;
            set.commit(&mut state, next).await?;
            Ok(out)
        })
        .await
        .map_err(|e| CapabilityError::Storage(format!("the state change did not finish: {e}")))?
    }

    /// Persist `next`, then make it the state and swap the dispatchers. On a
    /// failed save nothing changes.
    async fn commit(
        &self,
        state: &mut CapabilityStates,
        next: CapabilityStates,
    ) -> Result<(), CapabilityError> {
        let store = self.store.clone();
        let to_save = next.clone();
        tokio::task::spawn_blocking(move || store.save(&to_save))
            .await
            .map_err(|e| CapabilityError::Storage(format!("the state save did not finish: {e}")))?
            .map_err(CapabilityError::Storage)?;
        *state = next;
        self.rebuild(state).await;
        Ok(())
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
/// entries have no member for it.
#[derive(Serialize)]
struct ListedEntry {
    capability: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    authority: Option<String>,
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
        // The list spec carries its own copy of the shared manifest type.
        let manifest: list_spec::CapabilityManifest =
            reserialize(&listed.manifest).map_err(|e| reject_build_err(&doc, e))?;
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
    let ext: list_spec::Ext = reserialize(&serde_json::json!({
        EXT_NAMESPACE: { "entries": described }
    }))
    .map_err(|e| reject_build_err(&doc, e))?;
    let response: Result<list_spec::Response, _> = list_spec::Response::builder()
        .capabilities(entries)
        .ext(Some(ext))
        .try_into();
    respond(&doc, response.map_err(|e| reject_build_err(&doc, e))?)
}

pub mod git_trust;

#[cfg(test)]
mod tests {
    // `deprecated`: exercises the superseded 0.1 query types on purpose.
    #![allow(clippy::unwrap_used, clippy::expect_used, deprecated)]

    use super::*;
    use trust_tasks_rs::{Dispatcher, Payload, TrustTask};

    fn manifest(slug: &str) -> CapabilityManifest {
        serde_json::from_value(serde_json::json!({
            "capability": slug,
            "version": "0.1",
            "specs": [format!("{slug}/*")]
        }))
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

    fn set_with(slug: &str) -> Arc<CapabilitySet> {
        CapabilitySet::new(
            vec![test_capability(slug)],
            Box::new(MemoryCapabilityStore::default()),
            empty_base(),
            empty_base(),
        )
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
        TrustTask::new(
            "urn:uuid:q".to_string(),
            recognition::Payload::type_uri(),
            serde_json::json!({
                "entity_id": "e", "authority_id": "a", "action": "x", "resource": "r"
            }),
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
        let set = set_with("demo");
        assert!(!dispatch_ok(&set).await, "off by default");
    }

    #[tokio::test]
    async fn enable_serves_and_disable_stops() {
        let set = set_with("demo");
        set.enable("demo", "0.1", None, None).await.unwrap();
        assert!(dispatch_ok(&set).await);

        set.disable("demo", None).await.unwrap();
        assert!(!dispatch_ok(&set).await, "disable swaps the handler out");
    }

    #[tokio::test]
    async fn error_taxonomy() {
        let set = set_with("demo");
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
        .unwrap();
        assert!(dispatch_ok(&set).await, "enablement survives restart");
    }

    #[tokio::test]
    async fn enable_and_list_work_over_the_wire() {
        use trust_tasks_rs::Payload as _;
        let set = set_with("demo");

        // governance/capability/enable as a dispatched document.
        let enable_doc = TrustTask::new(
            "urn:uuid:en".to_string(),
            enable_spec::Payload::type_uri(),
            serde_json::json!({ "capability": "demo", "version": "0.1" }),
        );
        let d = set.dispatcher().read().await.clone();
        let out = crate::trust_tasks::handle_document(&d, enable_doc)
            .await
            .expect("enable succeeds");
        assert_eq!(out.payload["enabled"], serde_json::json!(true));
        assert!(
            dispatch_ok(&set).await,
            "capability serves after wire enable"
        );

        // list over the read-only surface reports it.
        let list_doc = TrustTask::new(
            "urn:uuid:ls".to_string(),
            list_spec::Payload::type_uri(),
            serde_json::json!({}),
        );
        let q = set.query_dispatcher().read().await.clone();
        let out = crate::trust_tasks::handle_document(&q, list_doc)
            .await
            .expect("list succeeds");
        assert_eq!(out.payload["capabilities"].as_array().unwrap().len(), 1);

        // enable/disable are NOT on the read-only surface.
        let enable_on_query = TrustTask::new(
            "urn:uuid:en2".to_string(),
            enable_spec::Payload::type_uri(),
            serde_json::json!({ "capability": "demo", "version": "0.1" }),
        );
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
    #[test]
    fn writes_are_known_while_the_capability_is_off() {
        let set = set_with("demo");
        assert!(set.is_write("registry/recognition"));
        assert!(!slugs(&set.query_dispatcher()).contains("registry/recognition"));
    }

    #[test]
    fn git_trust_tasks_are_not_on_the_read_only_surface() {
        let repo = Arc::new(crate::storage::adapters::local_storage::LocalStorage::new());
        let base_repo = repo.clone();
        let query_repo = repo.clone();
        let set = CapabilitySet::new(
            vec![git_trust::definition(repo).unwrap()],
            Box::new(MemoryCapabilityStore::default()),
            Box::new(move || crate::trust_tasks::build_dispatcher(base_repo.clone())),
            Box::new(move || crate::trust_tasks::build_query_dispatcher(query_repo.clone())),
        )
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

    fn set_of(
        definition: CapabilityDefinition,
        store: MemoryCapabilityStore,
    ) -> Arc<CapabilitySet> {
        CapabilitySet::new(
            vec![definition],
            Box::new(store),
            empty_base(),
            empty_base(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn enabling_a_state_that_adds_an_unclassified_task_is_refused() {
        for definition in [state_dependent_write("demo"), state_dependent_read("demo")] {
            let set = set_of(definition, MemoryCapabilityStore::default());
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
                .save(&BTreeMap::from([(
                    EnablementKey::new("demo", None),
                    CapabilityState {
                        config: Some(serde_json::json!({ "extra": true })),
                        ..probe_state()
                    },
                )]))
                .unwrap();
            let set = set_of(definition, store);
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
                Box::pin(async move { Ok(doc.respond_with(new_id(), serde_json::json!({}))) })
            })
        });
        let set = set_of(definition, MemoryCapabilityStore::default());
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

    fn refused(definitions: Vec<CapabilityDefinition>) -> String {
        match CapabilitySet::new(
            definitions,
            Box::new(MemoryCapabilityStore::default()),
            empty_base(),
            empty_base(),
        ) {
            Ok(_) => panic!("the set should be refused"),
            Err(e) => e,
        }
    }

    #[test]
    fn a_task_declared_as_both_read_and_write_is_refused() {
        use crate::specs::registry::recognition::v0_1 as recognition;
        let mut definition = test_capability("demo");
        definition.register_reads = Some(Arc::new(|d: RegistryDispatcher, _: &CapabilityState| {
            answers_handled::<recognition::Payload>(d)
        }));
        assert!(refused(vec![definition]).contains("declares registry/recognition as a read"));
    }

    #[test]
    fn a_registry_write_declared_as_a_read_is_refused() {
        use crate::specs::registry::record::put::v0_3 as put;
        let mut definition = test_capability("demo");
        definition.register_reads = Some(Arc::new(|d: RegistryDispatcher, _: &CapabilityState| {
            answers_handled::<put::Payload>(d)
        }));
        assert!(refused(vec![definition]).contains("registry/record/put"));
    }

    #[test]
    fn two_capabilities_registering_one_task_are_refused() {
        assert!(
            refused(vec![test_capability("one"), test_capability("two")]).contains("both register")
        );
    }

    #[test]
    fn a_capability_registering_a_registry_task_is_refused() {
        let error = match CapabilitySet::new(
            vec![test_capability("demo")],
            Box::new(MemoryCapabilityStore::default()),
            empty_base(),
            Box::new(|| {
                answers_handled::<crate::specs::registry::recognition::v0_1::Payload>(
                    Dispatcher::new(),
                )
            }),
        ) {
            Ok(_) => panic!("the set should be refused"),
            Err(e) => e,
        };
        assert!(error.contains("which the registry itself serves"));
    }

    #[tokio::test]
    async fn list_defaults_to_enabled_only() {
        let set = set_with("demo");
        assert!(set.list(false).await.is_empty());
        assert_eq!(set.list(true).await.len(), 1, "available listing");
        set.enable("demo", "0.1", None, None).await.unwrap();
        assert_eq!(set.list(false).await.len(), 1);
    }

    // --- a failed save changes nothing ----------------------------------------

    /// A store whose next save fails, once.
    #[derive(Default)]
    struct FailingOnce {
        inner: MemoryCapabilityStore,
        fail_next: std::sync::atomic::AtomicBool,
    }

    impl CapabilityStateStore for Arc<FailingOnce> {
        fn load(&self) -> Result<CapabilityStates, String> {
            self.inner.load()
        }
        fn save(&self, state: &CapabilityStates) -> Result<(), String> {
            if self
                .fail_next
                .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                return Err("disk full".to_string());
            }
            self.inner.save(state)
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
        assert!(store.load().unwrap().is_empty());
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
        assert!(store.load().unwrap().values().all(|s| s.enabled));
        set.disable("demo", None).await.expect("the retry disables");
        assert!(!dispatch_ok(&set).await);
    }

    // --- version, delegate and manifest ---------------------------------------

    #[tokio::test]
    async fn only_the_manifest_version_is_enabled() {
        let set = set_with("demo");
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

    async fn wire(
        set: &CapabilitySet,
        uri: TypeUri,
        payload: Value,
    ) -> Result<Value, (String, bool)> {
        let d = set.dispatcher().read().await.clone();
        crate::trust_tasks::handle_document(&d, TrustTask::new(new_id(), uri, payload))
            .await
            .map(|out| out.payload)
            .map_err(|err| (err.payload.code.to_string(), err.payload.retryable))
    }

    #[tokio::test]
    async fn enable_and_disable_answer_their_specifications_codes() {
        let set = set_with("demo");
        let enable = enable_spec::Payload::type_uri();
        let refused = |code: &str| Err((code.to_string(), false));
        assert_eq!(
            wire(
                &set,
                enable.clone(),
                serde_json::json!({ "capability": "nope", "version": "0.1" })
            )
            .await,
            refused("governance/capability/enable:unknownCapability")
        );
        assert_eq!(
            wire(
                &set,
                enable.clone(),
                serde_json::json!({ "capability": "demo", "version": "0.2" })
            )
            .await,
            refused("governance/capability/enable:unknownCapability")
        );
        assert_eq!(
            wire(
                &set,
                enable.clone(),
                serde_json::json!({ "capability": "demo", "version": "0.1", "config": { "bad": 1 } })
            )
            .await,
            refused("governance/capability/enable:configInvalid")
        );
        assert_eq!(
            wire(
                &set,
                enable.clone(),
                serde_json::json!({
                    "capability": "demo", "version": "0.1", "delegate": "did:example:companion",
                    "manifest": manifest("demo"),
                })
            )
            .await,
            refused("governance/capability/enable:configInvalid")
        );
        let mut other = serde_json::to_value(manifest("demo")).unwrap();
        other["title"] = serde_json::json!("Not the built-in one");
        assert_eq!(
            wire(
                &set,
                enable.clone(),
                serde_json::json!({ "capability": "demo", "version": "0.1", "manifest": other })
            )
            .await,
            refused("governance/capability/enable:configInvalid")
        );
        wire(
            &set,
            enable.clone(),
            serde_json::json!({ "capability": "demo", "version": "0.1", "manifest": manifest("demo") }),
        )
        .await
        .expect("the host's own manifest is accepted");
        assert_eq!(
            wire(
                &set,
                enable,
                serde_json::json!({ "capability": "demo", "version": "0.1" })
            )
            .await,
            refused("governance/capability/enable:alreadyEnabled")
        );

        let disable = disable_spec::Payload::type_uri();
        wire(
            &set,
            disable.clone(),
            serde_json::json!({ "capability": "demo" }),
        )
        .await
        .expect("disabled");
        assert_eq!(
            wire(&set, disable, serde_json::json!({ "capability": "demo" })).await,
            refused("governance/capability/disable:notEnabled")
        );
    }

    // --- enablement per authority ----------------------------------------------

    fn writer_set() -> Arc<CapabilitySet> {
        let mut definition = test_capability("writer");
        definition.requires_authority = true;
        set_of(definition, MemoryCapabilityStore::default())
    }

    fn for_authority(authority: &str) -> Option<Value> {
        Some(serde_json::json!({ "authority": authority }))
    }

    #[tokio::test]
    async fn each_authority_enables_and_disables_its_own() {
        let set = writer_set();
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
        let set = writer_set();
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
        let set = writer_set();
        for authority in ["did:example:a", "did:example:b"] {
            set.enable("writer", "0.1", for_authority(authority), None)
                .await
                .unwrap();
        }
        let list = |status: Option<&str>| {
            let payload = match status {
                Some(status) => serde_json::json!({ "status": status }),
                None => serde_json::json!({}),
            };
            let set = set.clone();
            async move {
                let q = set.query_dispatcher().read().await.clone();
                crate::trust_tasks::handle_document(
                    &q,
                    TrustTask::new(new_id(), list_spec::Payload::type_uri(), payload),
                )
                .await
                .expect("listed")
                .payload
            }
        };
        let out = list(None).await;
        assert_eq!(out["capabilities"].as_array().unwrap().len(), 2);
        assert_eq!(
            out["ext"][EXT_NAMESPACE]["entries"],
            serde_json::json!([
                { "capability": "writer", "authority": "did:example:a" },
                { "capability": "writer", "authority": "did:example:b" },
            ])
        );
        assert!(
            list(Some("available")).await["capabilities"]
                .as_array()
                .unwrap()
                .is_empty()
        );

        set.disable("writer", Some("did:example:a")).await.unwrap();
        set.disable("writer", Some("did:example:b")).await.unwrap();
        let out = list(Some("all")).await;
        assert_eq!(out["capabilities"].as_array().unwrap().len(), 1, "{out}");
        assert_eq!(out["capabilities"][0]["enabled"], false);
        assert_eq!(
            out["ext"][EXT_NAMESPACE]["entries"],
            serde_json::json!([{ "capability": "writer" }])
        );
    }

    // --- the state file ---------------------------------------------------------

    #[test]
    fn the_single_slot_state_file_is_migrated() {
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
        let states = store.load().expect("the old format loads");
        let keys: Vec<&EnablementKey> = states.keys().collect();
        assert_eq!(
            keys,
            vec![
                &EnablementKey::new("demo", None),
                &EnablementKey::new("git-trust", Some("did:scid:vh:1:abc")),
            ]
        );

        store.save(&states).unwrap();
        let written: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(written["format"], STATE_FORMAT);
        assert_eq!(written["enablements"][1]["authority"], "did:scid:vh:1:abc");
        assert!(written["enablements"][1].get("delegate").is_none());
        let reloaded = store.load().unwrap();
        assert_eq!(reloaded.keys().collect::<Vec<_>>(), keys);
    }

    #[test]
    fn a_state_file_of_an_unknown_format_is_refused() {
        assert!(decode_states(r#"{ "format": 3, "enablements": [] }"#).is_err());
    }
}
