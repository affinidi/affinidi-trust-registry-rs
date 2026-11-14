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
//! state (which are on, with what config), and rebuilds/swaps the live
//! [`RegistryDispatcher`]s the transport bindings dispatch through. Enable
//! and disable follow the Remote-First rule: state is persisted before the
//! new dispatcher is swapped in, so a crash between the two re-converges at
//! next startup rather than losing the transition.

// `TaskOutcome`'s error is a whole `trust-task-error` document, which is large
// by design; boxing it would only move the allocation onto every caller. The
// router allows this lint for the same reason.
#![allow(clippy::result_large_err)]

use std::collections::{BTreeMap, BTreeSet};
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

use crate::trust_tasks::payloads::reserialize;
use crate::trust_tasks::proof::requires_proof;
use crate::trust_tasks::router::{new_id, reject_build_err, respond};
use crate::trust_tasks::{RegistryDispatcher, TaskFuture, TaskOutcome};

pub use enable_spec::CapabilityManifest;

/// The enablement-config member naming the authority a capability acts under.
/// Writes a capability makes are bound to it, so enabling a capability with an
/// authority is itself bound to it.
pub const CONFIG_AUTHORITY: &str = "authority";

/// Validates a per-community `config` document.
pub type ConfigValidator = Arc<dyn Fn(&Value) -> Result<(), String> + Send + Sync>;

/// Contributes a capability's dispatcher registrations, given the
/// community's enablement state.
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
    /// registrations, to the admin surface only. Receives the community's
    /// enablement state (version, config, delegate) so handlers can bind
    /// per-community configuration. It must register the same task types
    /// whatever that state is: the set is read once, when the
    /// [`CapabilitySet`] is built, to decide which tasks are writes. A state
    /// under which it registers anything else is refused at enable, and a
    /// persisted one leaves the capability unserved.
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
    pub register_reads: Option<RegisterFn>,
    /// Validates a per-community `config` document. `None` = no config
    /// accepted beyond an empty object.
    pub validate_config: Option<ConfigValidator>,
    /// Whether the capability writes records, and so must be enabled with an
    /// `authority` its writes are bound to. Enabling one without an authority
    /// is refused, so no such capability can run unbound.
    pub requires_authority: bool,
}

/// A consistent view of one capability: whether it is enabled, the authority
/// it acts under, and the dispatcher that serves it, all read together, so a
/// check against the authority holds for the dispatcher it is used with.
pub struct CapabilitySnapshot {
    pub enabled: bool,
    pub authority: Option<String>,
    pub dispatcher: Arc<RegistryDispatcher>,
}

/// Persisted per-capability enablement state.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityState {
    pub version: String,
    pub enabled: bool,
    #[serde(default)]
    pub config: Option<Value>,
    pub enabled_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegate: Option<String>,
}

/// Durable store for enablement state.
pub trait CapabilityStateStore: Send + Sync {
    fn load(&self) -> Result<BTreeMap<String, CapabilityState>, String>;
    fn save(&self, state: &BTreeMap<String, CapabilityState>) -> Result<(), String>;
}

/// JSON-file-backed store (atomic replace via a temp file rename).
pub struct FileCapabilityStore {
    path: PathBuf,
}

impl FileCapabilityStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl CapabilityStateStore for FileCapabilityStore {
    fn load(&self) -> Result<BTreeMap<String, CapabilityState>, String> {
        match std::fs::read_to_string(&self.path) {
            Ok(text) => serde_json::from_str(&text)
                .map_err(|e| format!("capability state {} is corrupt: {e}", self.path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
            Err(e) => Err(format!(
                "cannot read capability state {}: {e}",
                self.path.display()
            )),
        }
    }

    fn save(&self, state: &BTreeMap<String, CapabilityState>) -> Result<(), String> {
        let json = serde_json::to_string_pretty(state).map_err(|e| e.to_string())?;
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, json).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, &self.path).map_err(|e| e.to_string())
    }
}

/// In-memory store for tests and ephemeral deployments.
#[derive(Default)]
pub struct MemoryCapabilityStore {
    state: std::sync::Mutex<BTreeMap<String, CapabilityState>>,
}

impl CapabilityStateStore for MemoryCapabilityStore {
    fn load(&self) -> Result<BTreeMap<String, CapabilityState>, String> {
        Ok(self.state.lock().unwrap_or_else(|p| p.into_inner()).clone())
    }
    fn save(&self, state: &BTreeMap<String, CapabilityState>) -> Result<(), String> {
        *self.state.lock().unwrap_or_else(|p| p.into_inner()) = state.clone();
        Ok(())
    }
}

/// A live, swappable dispatcher the transport bindings read through.
pub type DispatcherHandle = Arc<RwLock<Arc<RegistryDispatcher>>>;

/// Errors from enable/disable. The governance handlers below answer each as
/// a framework rejection whose message starts with the spec's extension
/// error code (`unknown_capability: ...`).
#[derive(Debug, PartialEq)]
pub enum CapabilityError {
    UnknownCapability,
    AlreadyEnabled,
    NotEnabled,
    ConfigInvalid(String),
    Storage(String),
}

/// Runtime composition of base handlers + enabled capability handlers.
pub struct CapabilitySet {
    available: BTreeMap<String, CapabilityDefinition>,
    state: RwLock<BTreeMap<String, CapabilityState>>,
    store: Box<dyn CapabilityStateStore>,
    /// Builds the always-on base registrations (admin surface).
    base: Box<dyn Fn() -> RegistryDispatcher + Send + Sync>,
    /// Builds the always-on read-only registrations (HTTP surface).
    base_query: Box<dyn Fn() -> RegistryDispatcher + Send + Sync>,
    dispatcher: DispatcherHandle,
    query_dispatcher: DispatcherHandle,
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
        delegate: None,
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
        Ok(Arc::new_cyclic(|weak: &std::sync::Weak<Self>| Self {
            dispatcher: Arc::new(RwLock::new(Arc::new(compose(
                &base,
                &available,
                &classification,
                &state,
                weak.clone(),
                true,
            )))),
            query_dispatcher: Arc::new(RwLock::new(Arc::new(compose(
                &base_query,
                &available,
                &classification,
                &state,
                weak.clone(),
                false,
            )))),
            weak: weak.clone(),
            classification,
            available,
            state: RwLock::new(state),
            store,
            base,
            base_query,
        }))
    }

    /// The full (admin) dispatcher handle for the DIDComm/TSP bindings.
    pub fn dispatcher(&self) -> DispatcherHandle {
        self.dispatcher.clone()
    }

    /// The read-only dispatcher handle for the HTTP binding.
    pub fn query_dispatcher(&self) -> DispatcherHandle {
        self.query_dispatcher.clone()
    }

    /// Enable `capability`: validate, persist state, then swap dispatchers.
    pub async fn enable(
        &self,
        capability: &str,
        version: &str,
        config: Option<Value>,
        delegate: Option<String>,
    ) -> Result<CapabilityState, CapabilityError> {
        let definition = self
            .available
            .get(capability)
            .ok_or(CapabilityError::UnknownCapability)?;
        if let Some(validate) = &definition.validate_config {
            let empty = Value::Object(serde_json::Map::new());
            validate(config.as_ref().unwrap_or(&empty)).map_err(CapabilityError::ConfigInvalid)?;
        }
        if definition.requires_authority
            && !config
                .as_ref()
                .and_then(|c| c.get(CONFIG_AUTHORITY))
                .is_some_and(Value::is_string)
        {
            return Err(CapabilityError::ConfigInvalid(format!(
                "{capability} writes records and must be enabled with an `{CONFIG_AUTHORITY}`"
            )));
        }
        let mut state = self.state.write().await;
        if state.get(capability).is_some_and(|s| s.enabled) {
            return Err(CapabilityError::AlreadyEnabled);
        }
        let entry = CapabilityState {
            version: version.to_string(),
            enabled: true,
            config,
            enabled_at: Utc::now(),
            delegate,
        };
        self.classification
            .check(capability, definition, &entry)
            .map_err(CapabilityError::ConfigInvalid)?;
        state.insert(capability.to_string(), entry.clone());
        // Persist first (Remote-First): a crash after this line re-converges
        // at startup; a crash before it loses nothing.
        self.store.save(&state).map_err(CapabilityError::Storage)?;
        self.rebuild(&state).await;
        Ok(entry)
    }

    /// Disable `capability`. Disable is not delete: state is retained with
    /// `enabled: false` for audit; registry records are untouched.
    pub async fn disable(&self, capability: &str) -> Result<(), CapabilityError> {
        let mut state = self.state.write().await;
        match state.get_mut(capability) {
            Some(entry) if entry.enabled => entry.enabled = false,
            _ => return Err(CapabilityError::NotEnabled),
        }
        self.store.save(&state).map_err(CapabilityError::Storage)?;
        self.rebuild(&state).await;
        Ok(())
    }

    /// List capabilities: `(manifest, Option<state>)`, enabled-only unless
    /// `include_available`.
    pub async fn list(
        &self,
        include_available: bool,
    ) -> Vec<(CapabilityManifest, Option<CapabilityState>)> {
        let state = self.state.read().await;
        self.available
            .values()
            .filter_map(|d| {
                let s = state
                    .get(d.manifest.capability.to_string().as_str())
                    .cloned();
                let enabled = s.as_ref().is_some_and(|s| s.enabled);
                (enabled || include_available).then(|| (d.manifest.clone(), s))
            })
            .collect()
    }

    /// The authority an enabled capability acts under: the `authority` member
    /// of its enablement config. `None` when the capability is not enabled or
    /// its config names no authority.
    pub async fn configured_authority(&self, capability: &str) -> Option<String> {
        self.state
            .read()
            .await
            .get(capability)
            .filter(|state| state.enabled)
            .and_then(|state| state.config.as_ref())
            .and_then(|config| config.get(CONFIG_AUTHORITY))
            .and_then(Value::as_str)
            .map(str::to_string)
    }

    /// Whether and under what authority `capability` is enabled, with the
    /// admin dispatcher that goes with that state. Enable and disable swap the
    /// dispatcher while holding the state lock, so reading both under it
    /// cannot pair one state with another's dispatcher.
    pub async fn snapshot(&self, capability: &str) -> CapabilitySnapshot {
        let state = self.state.read().await;
        let entry = state.get(capability).filter(|s| s.enabled);
        CapabilitySnapshot {
            enabled: entry.is_some(),
            authority: entry
                .and_then(|s| s.config.as_ref())
                .and_then(|c| c.get(CONFIG_AUTHORITY))
                .and_then(Value::as_str)
                .map(str::to_string),
            dispatcher: self.dispatcher.read().await.clone(),
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

    async fn rebuild(&self, state: &BTreeMap<String, CapabilityState>) {
        *self.dispatcher.write().await = Arc::new(compose(
            &self.base,
            &self.available,
            &self.classification,
            state,
            self.weak.clone(),
            true,
        ));
        *self.query_dispatcher.write().await = Arc::new(compose(
            &self.base_query,
            &self.available,
            &self.classification,
            state,
            self.weak.clone(),
            false,
        ));
    }
}

/// Base registrations plus the governance surface plus every enabled
/// capability's registrations. The admin surface gets enable/disable/list and
/// every task of an enabled capability; the read-only (query) surface gets
/// only list and the tasks capabilities declare as reads.
///
/// A capability whose state makes it register tasks other than the ones it
/// was classified with ([`Classification::check`]) is left out of both
/// surfaces, so none of its tasks can run unclassified.
fn compose(
    base: &(impl Fn() -> RegistryDispatcher + ?Sized),
    available: &BTreeMap<String, CapabilityDefinition>,
    classification: &Classification,
    state: &BTreeMap<String, CapabilityState>,
    set: std::sync::Weak<CapabilitySet>,
    admin: bool,
) -> RegistryDispatcher {
    let mut dispatcher = base();
    dispatcher = {
        let list_set = set.clone();
        dispatcher.on::<list_spec::Payload, _>(move |doc| -> TaskFuture {
            let set = list_set.clone();
            Box::pin(handle_list(set, doc))
        })
    };
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
    for (slug, definition) in available {
        if let Some(entry) = state.get(slug).filter(|s| s.enabled) {
            if let Err(e) = classification.check(slug, definition, entry) {
                tracing::error!("capability {slug} is enabled but not served: {e}");
                continue;
            }
            if let Some(register_reads) = &definition.register_reads {
                dispatcher = register_reads(dispatcher, entry);
            }
            if admin {
                dispatcher = (definition.register)(dispatcher, entry);
            }
        }
    }
    dispatcher
}

// --- governance wire handlers -------------------------------------------------

fn upgraded(set: &std::sync::Weak<CapabilitySet>) -> Result<Arc<CapabilitySet>, RejectReason> {
    set.upgrade().ok_or(RejectReason::InternalError {
        reason: "capability set is shutting down".to_string(),
    })
}

fn reject_of(
    doc_reject: impl FnOnce(RejectReason) -> trust_tasks_rs::ErrorResponse,
    e: CapabilityError,
) -> trust_tasks_rs::ErrorResponse {
    let reason = match e {
        CapabilityError::UnknownCapability => RejectReason::TaskFailed {
            reason: "unknown_capability: not built into this host and no manifest supplied"
                .to_string(),
            details: None,
        },
        CapabilityError::AlreadyEnabled => RejectReason::TaskFailed {
            reason: "already_enabled: the capability is already enabled for this community"
                .to_string(),
            details: None,
        },
        CapabilityError::NotEnabled => RejectReason::TaskFailed {
            reason: "not_enabled: the capability is not currently enabled".to_string(),
            details: None,
        },
        CapabilityError::ConfigInvalid(detail) => RejectReason::MalformedRequest {
            reason: format!("config_invalid: {detail}"),
        },
        CapabilityError::Storage(detail) => RejectReason::InternalError { reason: detail },
    };
    doc_reject(reason)
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
        Err(e) => Err(reject_of(|r| doc.reject_with(new_id(), r), e)),
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
    match set.disable(&capability).await {
        Ok(()) => {
            let response: Result<disable_spec::Response, _> = disable_spec::Response::builder()
                .capability(capability)
                .enabled(false)
                .try_into();
            respond(&doc, response.map_err(|e| reject_build_err(&doc, e))?)
        }
        Err(e) => Err(reject_of(|r| doc.reject_with(new_id(), r), e)),
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
        .as_ref()
        .map(|s| format!("{s:?}").to_ascii_lowercase())
        .unwrap_or_else(|| "enabled".to_string());
    let include_available = status != "enabled";
    let mut entries: Vec<list_spec::ResponseCapabilitiesItem> = Vec::new();
    for (manifest, s) in set.list(include_available).await {
        let enabled = s.as_ref().is_some_and(|s| s.enabled);
        if status == "available" && enabled {
            continue;
        }
        // The list spec carries its own copy of the shared manifest type.
        let manifest: list_spec::CapabilityManifest =
            reserialize(&manifest).map_err(|e| reject_build_err(&doc, e))?;
        let enabled_at = s.as_ref().filter(|_| enabled).map(|s| s.enabled_at);
        let delegate = s.and_then(|s| s.delegate);
        let entry: Result<list_spec::ResponseCapabilitiesItem, _> =
            list_spec::ResponseCapabilitiesItem::builder()
                .manifest(manifest)
                .enabled(enabled)
                .enabled_at(enabled_at)
                .delegate(delegate)
                .try_into();
        entries.push(entry.map_err(|e| reject_build_err(&doc, e))?);
    }
    let response: Result<list_spec::Response, _> = list_spec::Response::builder()
        .capabilities(entries)
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
        let snapshot = set.snapshot("writer").await;
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

        set.disable("demo").await.unwrap();
        assert!(!dispatch_ok(&set).await, "disable swaps the handler out");
    }

    #[tokio::test]
    async fn error_taxonomy() {
        let set = set_with("demo");
        assert_eq!(
            set.enable("nope", "0.1", None, None).await.unwrap_err(),
            CapabilityError::UnknownCapability
        );
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
        set.disable("demo").await.unwrap();
        assert_eq!(
            set.disable("demo").await.unwrap_err(),
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
            "git-trust".to_string(),
            CapabilityState {
                enabled: true,
                config: Some(serde_json::json!({ "authority": "did:example:a" })),
                ..probe_state()
            },
        )]);
        let query = compose(
            &*set.base_query,
            &set.available,
            &set.classification,
            &state,
            set.weak.clone(),
            false,
        );
        let admin = compose(
            &*set.base,
            &set.available,
            &set.classification,
            &state,
            set.weak.clone(),
            true,
        );

        let query = slugs_of(&query).unwrap();
        assert!(!query.contains("git-trust/grant"));
        assert!(!query.contains("git-trust/revoke"));
        assert!(slugs_of(&admin).unwrap().contains("git-trust/grant"));
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
            assert!(!set.snapshot("demo").await.enabled);
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
                    "demo".to_string(),
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
}
