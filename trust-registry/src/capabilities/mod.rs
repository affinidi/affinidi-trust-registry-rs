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

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::RwLock;
use trust_tasks_rs::specs::governance::capability::enable::v0_1 as enable_spec;

use crate::trust_tasks::RegistryDispatcher;

pub use enable_spec::CapabilityManifest;

/// A capability the host can serve: its manifest plus the dispatcher
/// registrations it contributes when enabled.
pub struct CapabilityDefinition {
    pub manifest: CapabilityManifest,
    /// Contributes the capability's `.on::<P, _>()` registrations.
    pub register: Arc<dyn Fn(RegistryDispatcher) -> RegistryDispatcher + Send + Sync>,
    /// Validates a per-community `config` document. `None` = no config
    /// accepted beyond an empty object.
    pub validate_config: Option<Arc<dyn Fn(&Value) -> Result<(), String> + Send + Sync>>,
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
        Ok(self
            .state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone())
    }
    fn save(&self, state: &BTreeMap<String, CapabilityState>) -> Result<(), String> {
        *self.state.lock().unwrap_or_else(|p| p.into_inner()) = state.clone();
        Ok(())
    }
}

/// A live, swappable dispatcher the transport bindings read through.
pub type DispatcherHandle = Arc<RwLock<Arc<RegistryDispatcher>>>;

/// Errors from enable/disable, mapped to the spec's extension error codes by
/// the transport handlers.
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
        let set = Self {
            dispatcher: Arc::new(RwLock::new(Arc::new(compose(
                &base, &available, &state,
            )))),
            query_dispatcher: Arc::new(RwLock::new(Arc::new(compose(
                &base_query,
                &available,
                &state,
            )))),
            available,
            state: RwLock::new(state),
            store,
            base,
            base_query,
        };
        Ok(Arc::new(set))
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
        if let (Some(config), Some(validate)) = (&config, &definition.validate_config) {
            validate(config).map_err(CapabilityError::ConfigInvalid)?;
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
        state.insert(capability.to_string(), entry.clone());
        // Persist first (Remote-First): a crash after this line re-converges
        // at startup; a crash before it loses nothing.
        self.store
            .save(&state)
            .map_err(CapabilityError::Storage)?;
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
        self.store
            .save(&state)
            .map_err(CapabilityError::Storage)?;
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
                let s = state.get(&d.manifest.capability.to_string()).cloned();
                let enabled = s.as_ref().is_some_and(|s| s.enabled);
                (enabled || include_available).then(|| (d.manifest.clone(), s))
            })
            .collect()
    }

    async fn rebuild(&self, state: &BTreeMap<String, CapabilityState>) {
        *self.dispatcher.write().await = Arc::new(compose(&self.base, &self.available, state));
        *self.query_dispatcher.write().await =
            Arc::new(compose(&self.base_query, &self.available, state));
    }
}

/// Base registrations plus every enabled capability's registrations.
fn compose(
    base: &(impl Fn() -> RegistryDispatcher + ?Sized),
    available: &BTreeMap<String, CapabilityDefinition>,
    state: &BTreeMap<String, CapabilityState>,
) -> RegistryDispatcher {
    let mut dispatcher = base();
    for (slug, definition) in available {
        if state.get(slug).is_some_and(|s| s.enabled) {
            dispatcher = (definition.register)(dispatcher);
        }
    }
    dispatcher
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

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
        use trust_tasks_rs::specs::registry::recognition::v0_1 as recognition;
        CapabilityDefinition {
            manifest: manifest(slug),
            register: Arc::new(|d: RegistryDispatcher| {
                d.on::<recognition::Payload, _>(|doc| -> crate::trust_tasks::TaskFuture {
                    Box::pin(async move {
                        Ok(doc.respond_with(
                            "urn:uuid:test-reply".to_string(),
                            serde_json::json!({ "handled": true }),
                        ))
                    })
                })
            }),
            validate_config: Some(Arc::new(|config: &Value| {
                if config.get("bad").is_some() {
                    Err("bad key".to_string())
                } else {
                    Ok(())
                }
            })),
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

    fn recognition_doc() -> TrustTask<Value> {
        use trust_tasks_rs::specs::registry::recognition::v0_1 as recognition;
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
    async fn list_defaults_to_enabled_only() {
        let set = set_with("demo");
        assert!(set.list(false).await.is_empty());
        assert_eq!(set.list(true).await.len(), 1, "available listing");
        set.enable("demo", "0.1", None, None).await.unwrap();
        assert_eq!(set.list(false).await.len(), 1);
    }
}
