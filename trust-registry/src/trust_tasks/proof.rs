//! Data Integrity proof verification for the Trust Tasks that need a proof.
//!
//! Which tasks need one is the registry's policy, in
//! [`descriptor`](crate::trust_tasks::descriptor): every write (record put and
//! delete, `registry/did/rotate`, capability enable and disable, and the
//! capabilities' write tasks) and `registry/record/query`. This module
//! performs the cryptographic step — verifying the Data Integrity proof
//! against the issuer's resolved key — so a forged or tampered document is
//! rejected, not merely a proofless one. A document with no proof, or with no
//! in-band `issuer` for the proof to be bound to, is refused outright rather
//! than left to the verifier.
//!
//! Verification is backed by [`trust_tasks_proof`]'s Affinidi verifier over a
//! DID-resolver cache of its own ([`build_verifier`]); `did:key` issuers verify
//! offline, `did:web` / `did:webvh` issuers resolve through the cache.
//!
//! A registry write is an operational message (VTI-KEY-084, VTI-KEY-106): it
//! is signed with the writer's `operational` key, carries the proof purpose
//! `authentication`, and the key must be listed under `authentication` in the
//! writer's DID document. [`AuthenticationKeyResolver`] enforces the last part,
//! so a key the writer lists only under `assertionMethod` cannot sign a write.

use std::sync::Arc;

use affinidi_tdk::data_integrity::{DataIntegrityError, ResolvedKey};
use affinidi_tdk::did_common::Document;
use affinidi_tdk::did_common::verification_method::VerificationRelationship;
use affinidi_tdk::did_resolver::DIDCacheClient;
use async_trait::async_trait;
use serde_json::Value;
use trust_tasks_proof::affinidi::{
    CachedDidResolver, ProofPurpose, ProofPurposeResolver, Verifier,
};
use trust_tasks_rs::{DynProofVerifier, RejectReason, TrustTask, erase_verifier};

use crate::trust_tasks::descriptor::descriptor;

/// The only `proofPurpose` a registry write may carry (VTI-KEY-106).
pub const WRITE_PROOF_PURPOSE: &str = "authentication";

/// Is `vm` one of the methods `doc` lists under `authentication`, by absolute
/// DID URL or relative fragment, referenced or embedded?
pub fn is_authentication_method(doc: &Document, vm: &str) -> bool {
    let fragment = vm.find('#').map(|i| &vm[i..]);
    let refers = |id: &str| id == vm || fragment.is_some_and(|f| id == f);
    doc.authentication
        .iter()
        .any(|relationship| match relationship {
            VerificationRelationship::Reference(id) => refers(id),
            VerificationRelationship::VerificationMethod(method) => refers(method.id.as_str()),
            _ => false,
        })
}

/// Resolves a proof's verification method only when the controlling DID
/// document lists it under `authentication`, whatever `proofPurpose` the proof
/// declares, through [`CachedDidResolver`] (which also requires the method's
/// controller to be the DID that names it).
///
/// A resolution that failed transiently ([`classify_resolver_error`]) is
/// reported as [`RESOLUTION_UNAVAILABLE`], which [`verify_proof`] answers
/// `unavailable` (retryable) rather than `proofInvalid`.
pub struct AuthenticationKeyResolver {
    keys: Arc<dyn ProofPurposeResolver>,
}

impl AuthenticationKeyResolver {
    pub fn new(client: Arc<DIDCacheClient>) -> Self {
        Self::over(Arc::new(CachedDidResolver::new(client)))
    }

    /// Over any resolver that reports its failures as [`CachedDidResolver`]
    /// does.
    fn over(keys: Arc<dyn ProofPurposeResolver>) -> Self {
        Self { keys }
    }
}

#[async_trait]
impl ProofPurposeResolver for AuthenticationKeyResolver {
    async fn resolve_vm_for_purpose(
        &self,
        vm: &str,
        _purpose: ProofPurpose,
    ) -> Result<ResolvedKey, DataIntegrityError> {
        self.keys
            .resolve_vm_for_purpose(vm, ProofPurpose::Authentication)
            .await
            .map_err(|error| match &error {
                DataIntegrityError::Resolver(message)
                    if classify_resolver_error(message) == ResolutionFailure::Transient =>
                {
                    tracing::warn!(
                        "resolving {vm} for a Trust Task proof failed transiently ({message}); \
                         answering unavailable so the sender retries"
                    );
                    DataIntegrityError::Resolver(RESOLUTION_UNAVAILABLE.to_string())
                }
                _ => error,
            })
    }
}

/// What [`AuthenticationKeyResolver`] reports in place of a resolution that
/// failed transiently. [`verify_proof`] answers it `unavailable` (retryable):
/// nothing is known to be wrong with the proof.
///
/// A fixed string, compared exactly, so a resolver message carrying text the
/// sender chose (a DID, a URL) cannot pass for it.
pub const RESOLUTION_UNAVAILABLE: &str =
    "resolving the issuer's DID failed transiently; the proof could not be verified now";

/// Whether a failed DID resolution may succeed if tried again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolutionFailure {
    /// It may pass: a timeout, no response, a connection or DNS failure, an
    /// upstream 5xx / 408 / 429, or the resolver cache itself unavailable.
    Transient,
    /// A definitive answer: the DID is not found or deactivated, its method is
    /// unsupported, it is malformed, its host is refused by the host policy,
    /// the key is not authorised, or anything not known to be transient.
    Definitive,
}

/// What [`CachedDidResolver`] (trust-tasks-proof 0.39) reports when a
/// resolution misses its deadline.
const CACHED_RESOLVER_TIMEOUT: &str =
    "resolving the verificationMethod's DID did not finish in time";
/// The prefix [`CachedDidResolver`] puts before the resolver cache's own
/// error (`DIDCacheError`'s `Display`).
const CACHED_RESOLVER_RESOLVE: &str = "resolve the verificationMethod's DID: ";

/// Classify the message of a [`DataIntegrityError::Resolver`] from
/// [`CachedDidResolver`].
///
/// trust-tasks-proof stringifies the resolver cache's typed `DIDCacheError`
/// (and its own deadline) into that one variant, so this reads the `Display`
/// forms of trust-tasks-proof 0.39 and affinidi-did-resolver-cache-sdk 0.8 /
/// affinidi-did-resolver-traits 0.1. It matches conservatively: only the
/// forms known to be transient are; anything else, including a form a later
/// release introduces, is definitive (`proofInvalid`, as before).
///
/// Known misclassifications, all toward retryable (the sender retries, and
/// the same answer comes back until it gives up):
/// - a `NetworkFetch` with no status covers a failure *after* the host
///   answered as well as no response: a did:web body that cannot be read, or
///   a did:webvh log served with 200 that cannot be decoded, is reported the
///   same way as a DNS failure, so it is transient;
/// - a client in network mode receives every cache-server error, a definitive
///   one included (not found, deactivated), as a `Transport error` string, so
///   it is transient. The registry builds its verifier's client in local mode.
///
/// TODO(#302 follow-up, upstream): ask trust-tasks-proof for a typed
/// resolver error (e.g. a `DataIntegrityError` variant or a source carrying
/// the `DIDCacheError` / `NetworkFetchError`, or an `is_transient()`), so this
/// stops depending on message text. The unit tests below pin each form.
pub fn classify_resolver_error(message: &str) -> ResolutionFailure {
    use ResolutionFailure::{Definitive, Transient};

    if message == CACHED_RESOLVER_TIMEOUT {
        return Transient;
    }
    let Some(cache) = message.strip_prefix(CACHED_RESOLVER_RESOLVE) else {
        // The host policy, the document checks, the key decoding: all about
        // the DID or its document, none about reaching it.
        return Definitive;
    };
    // `DIDCacheError::NetworkTimeout`, `TransportError` (network mode: the
    // cache server unreachable or its connection lost) and `ConfigError` (the
    // resolver cache itself unusable): none says anything about the proof.
    if cache == "Network timeout"
        || cache.starts_with("Transport error: ")
        || cache.starts_with("Config error: ")
    {
        return Transient;
    }
    // `DIDCacheError::NetworkFetch(NetworkFetchError)`.
    if cache.starts_with("DID host ") {
        if cache.ends_with("rate-limited resolution (HTTP 429)") {
            return Transient;
        }
        // "DID host [<url> ]answered HTTP <status>": the last occurrence is
        // the one the error formats, whatever the URL holds.
        return match cache
            .rsplit_once("answered HTTP ")
            .and_then(|(_, status)| status.parse::<u16>().ok())
        {
            Some(status) if status >= 500 || status == 408 || status == 429 => Transient,
            // 404, 410, 403, …: the host answered about the DID.
            _ => Definitive,
        };
    }
    // A fetch that got no response at all: DNS, connect, TLS, reset.
    if cache.starts_with("network fetch failed: ")
        || (cache.starts_with("fetching ") && cache.contains(" failed: "))
    {
        return Transient;
    }
    // `DIDError` (not found, deactivated, malformed, a log that does not
    // verify), `UnsupportedMethod`, `ParsingError`.
    Definitive
}

/// Whether `slug` is one of the registry's own tasks that changes the
/// registry, and so needs a verifiable proof from an admin: the writes in
/// [`descriptor::DESCRIPTORS`](crate::trust_tasks::descriptor::DESCRIPTORS).
///
/// A capability's write tasks are not described there: the
/// [`CapabilitySet`](crate::capabilities::CapabilitySet) classifies them
/// ([`CapabilitySet::is_write`](crate::capabilities::CapabilitySet::is_write)),
/// and the [`TaskHandler`](crate::trust_tasks::TaskHandler) consults both.
pub fn is_write_slug(slug: &str) -> bool {
    descriptor(slug).is_some_and(|d| d.is_write())
}

/// Slugs a caller may only use with a proof bound to its sender, under the
/// same rules as a write: the writes, plus `registry/record/query`, whose
/// answers carry whole records (context included) rather than the yes/no of
/// the public TRQP queries. Derived from
/// [`descriptor::DESCRIPTORS`](crate::trust_tasks::descriptor::DESCRIPTORS).
pub fn requires_proof(slug: &str) -> bool {
    descriptor(slug).is_some_and(|d| d.requires_proof())
}

/// Why a write signed by a non-`did:key` issuer could not be verified while
/// the DID resolver is unavailable. [`verify_proof`] answers it `unavailable`
/// (retryable), not `proofInvalid`: nothing is wrong with the proof.
pub const RESOLVER_UNAVAILABLE: &str =
    "the DID resolver is unavailable, so only did:key issuers can be verified";

/// First delay before rebuilding a DID resolver that could not be built.
const RESOLVER_RETRY_INITIAL: std::time::Duration = std::time::Duration::from_secs(1);
/// Longest delay between attempts to rebuild the DID resolver.
const RESOLVER_RETRY_MAX: std::time::Duration = std::time::Duration::from_secs(60);

/// The registry's write-proof verifier: the DID-resolver-backed one, or, while
/// the resolver cannot be built, a `did:key`-only stand-in that a background
/// task replaces as soon as the resolver builds.
///
/// While degraded, a proof whose verification method is not a `did:key` is
/// refused as [`RESOLVER_UNAVAILABLE`] (answered `unavailable`, so a client
/// retries) rather than reported invalid.
pub struct RegistryVerifier {
    resolving: std::sync::RwLock<Option<Arc<dyn DynProofVerifier>>>,
    did_key: Arc<dyn DynProofVerifier>,
}

impl RegistryVerifier {
    fn degraded() -> Self {
        Self {
            resolving: std::sync::RwLock::new(None),
            did_key: erase_verifier(Verifier::for_did_key()),
        }
    }

    fn resolving(verifier: Arc<dyn DynProofVerifier>) -> Self {
        let this = Self::degraded();
        this.install(verifier);
        this
    }

    fn install(&self, verifier: Arc<dyn DynProofVerifier>) {
        *self
            .resolving
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(verifier);
    }

    fn current(&self) -> Option<Arc<dyn DynProofVerifier>> {
        self.resolving
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Whether only `did:key` issuers can be verified.
    pub fn is_did_key_only(&self) -> bool {
        self.current().is_none()
    }
}

#[async_trait]
impl DynProofVerifier for RegistryVerifier {
    async fn verify_json(
        &self,
        doc: &TrustTask<Value>,
    ) -> Result<(), trust_tasks_rs::VerificationError> {
        if let Some(verifier) = self.current() {
            return verifier.verify_json(doc).await;
        }
        let did_key = doc
            .proof
            .as_ref()
            .is_some_and(|proof| proof.verification_method.starts_with("did:key:"));
        if did_key {
            self.did_key.verify_json(doc).await
        } else {
            Err(trust_tasks_rs::VerificationError::Other(
                RESOLVER_UNAVAILABLE.to_string(),
            ))
        }
    }
}

/// Build the resolver-backed verifier, accepting only keys the signer lists
/// under `authentication`.
async fn resolver_verifier() -> Result<Arc<dyn DynProofVerifier>, String> {
    use affinidi_tdk::did_resolver::config::DIDCacheConfigBuilder;

    let client = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
        .await
        .map_err(|e| e.to_string())?;
    let resolver = Arc::new(AuthenticationKeyResolver::new(Arc::new(client)));
    Ok(erase_verifier(Verifier::with_resolver(resolver)))
}

/// Build the Data Integrity proof verifier, backed by the Affinidi
/// DID-resolver cache and accepting only keys the signer lists under
/// `authentication`.
///
/// If the resolver cannot be built, start with a `did:key`-only verifier
/// (`did:key` resolves offline, and its only key is by construction its
/// authentication key), report it on `health`, and keep rebuilding the
/// resolver in the background with backoff until it builds or `shutdown` is
/// cancelled; the full verifier is swapped in the moment it does.
///
/// This verifier builds its own resolver cache; it does not share the one the
/// DIDComm stack holds.
pub async fn build_verifier(
    health: &Arc<crate::health::RegistryHealth>,
    shutdown: &tokio_util::sync::CancellationToken,
) -> Arc<dyn DynProofVerifier> {
    build_verifier_with(resolver_verifier, health, shutdown).await
}

async fn build_verifier_with<F, Fut>(
    mut build: F,
    health: &Arc<crate::health::RegistryHealth>,
    shutdown: &tokio_util::sync::CancellationToken,
) -> Arc<dyn DynProofVerifier>
where
    F: FnMut() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<Arc<dyn DynProofVerifier>, String>> + Send,
{
    match build().await {
        Ok(verifier) => {
            health.set_verifier_did_key_only(false);
            Arc::new(RegistryVerifier::resolving(verifier))
        }
        Err(e) => {
            tracing::error!(
                "DID resolver cache unavailable ({e}); Trust Task proof verification is \
                 limited to did:key issuers until it can be built (retrying in the background)"
            );
            health.set_verifier_did_key_only(true);
            let verifier = Arc::new(RegistryVerifier::degraded());
            let target = verifier.clone();
            let health = health.clone();
            let shutdown = shutdown.clone();
            tokio::spawn(async move {
                let mut delay = RESOLVER_RETRY_INITIAL;
                loop {
                    tokio::select! {
                        _ = shutdown.cancelled() => return,
                        _ = tokio::time::sleep(delay) => {}
                    }
                    match build().await {
                        Ok(resolving) => {
                            target.install(resolving);
                            health.set_verifier_did_key_only(false);
                            tracing::info!(
                                "DID resolver cache built; Trust Task proof verification \
                                 covers every supported DID method again"
                            );
                            return;
                        }
                        Err(e) => {
                            tracing::warn!(
                                "DID resolver cache still unavailable ({e}); retrying in {delay:?}"
                            );
                            delay = (delay * 2).min(RESOLVER_RETRY_MAX);
                        }
                    }
                }
            });
            verifier
        }
    }
}

/// Cryptographically verify the Data Integrity proof on a document that needs
/// one: a write, or a `registry/record/query` ([`requires_proof`]).
///
/// Public reads pass through unchanged. Such a document must carry a proof
/// ([`RejectReason::ProofRequired`]) and an in-band `issuer` the proof is bound
/// to ([`RejectReason::MalformedRequest`]); both are refused here as well as by
/// [`TaskHandler::authorize_write`](crate::trust_tasks::TaskHandler::authorize_write),
/// so this check is safe to call on its own. A present proof that fails
/// verification is [`RejectReason::ProofInvalid`].
///
/// It is one of the registry's own ([`requires_proof`]) or, given the
/// `capabilities` being served, a capability's write task. Pass the capability
/// set whenever capabilities are served; without it their writes pass through
/// unverified.
pub async fn verify_write_proof(
    verifier: &Arc<dyn DynProofVerifier>,
    capabilities: Option<&crate::capabilities::CapabilitySet>,
    doc: &TrustTask<Value>,
) -> Result<(), RejectReason> {
    let slug = doc.type_uri.slug();
    if !requires_proof(slug) && !capabilities.is_some_and(|c| c.is_write(slug)) {
        return Ok(());
    }
    verify_proof(verifier, doc).await
}

/// [`verify_write_proof`] for a document the caller has already classified as
/// a write, whatever its slug: a capability's write tasks are not in
/// [`is_write_slug`], so this check does not consult it.
pub async fn verify_proof(
    verifier: &Arc<dyn DynProofVerifier>,
    doc: &TrustTask<Value>,
) -> Result<(), RejectReason> {
    if doc.proof.is_none() {
        return Err(RejectReason::ProofRequired);
    }
    if doc.issuer.is_none() {
        return Err(RejectReason::MalformedRequest {
            reason: "a write must name its issuer".to_string(),
        });
    }
    verifier.verify_json(doc).await.map_err(|e| match e {
        trust_tasks_rs::VerificationError::Other(reason) if is_unavailable(&reason) => {
            RejectReason::Unavailable { retry_after: None }
        }
        e => RejectReason::ProofInvalid {
            reason: e.to_string(),
        },
    })
}

/// Whether a verifier's `Other` reason says the proof could not be checked
/// now, rather than that it is wrong: the degraded verifier's
/// [`RESOLVER_UNAVAILABLE`], or [`RESOLUTION_UNAVAILABLE`] as the Affinidi
/// verifier reports it (a `DataIntegrityError::Resolver`, displayed).
fn is_unavailable(reason: &str) -> bool {
    reason == RESOLVER_UNAVAILABLE
        || reason == DataIntegrityError::Resolver(RESOLUTION_UNAVAILABLE.to_string()).to_string()
}

#[cfg(test)]
pub(crate) mod tests {
    // `deprecated`: the superseded 0.1 types name the documents.
    #![allow(clippy::unwrap_used, clippy::expect_used, deprecated)]

    use super::*;
    use crate::trust_tasks::payloads::{RecognitionRequest, RecordPutRequest};
    use affinidi_tdk::did_resolver::errors::{DIDCacheError, NetworkFetchError};
    use trust_tasks_rs::{Payload as _, TypeUri};

    /// A document of `type_uri` carrying a proof that verifies against
    /// nothing. Only the type and the proof are looked at, so the payload is
    /// left empty (raw JSON: neither task's generated type accepts `{}`).
    fn doc_with_dummy_proof(type_uri: TypeUri) -> TrustTask<Value> {
        let mut doc = TrustTask::new("id-1", type_uri, serde_json::json!({}));
        doc.issuer = Some("did:example:admin".to_string());
        // Raw JSON: a proof with a bogus `proofValue`, which is the point.
        doc.proof = Some(
            serde_json::from_value(serde_json::json!({
                "type": "DataIntegrityProof",
                "cryptosuite": "eddsa-jcs-2022",
                "created": "2026-07-09T00:00:00Z",
                "proofPurpose": "assertionMethod",
                "verificationMethod": "did:example:admin#key-1",
                "proofValue": "z0000"
            }))
            .expect("valid proof fixture"),
        );
        doc
    }

    #[tokio::test]
    async fn read_document_skips_verification() {
        let verifier = erase_verifier(Verifier::for_did_key());
        let doc = doc_with_dummy_proof(RecognitionRequest::type_uri());
        assert!(verify_write_proof(&verifier, None, &doc).await.is_ok());
    }

    #[tokio::test]
    async fn write_with_bogus_proof_is_rejected() {
        // A did:key verifier rejects a proof whose verificationMethod is not a
        // resolvable did:key with a valid signature.
        let verifier = erase_verifier(Verifier::for_did_key());
        let doc = doc_with_dummy_proof(RecordPutRequest::type_uri());
        assert!(matches!(
            verify_write_proof(&verifier, None, &doc).await,
            Err(RejectReason::ProofInvalid { .. })
        ));
    }

    #[tokio::test]
    async fn write_without_proof_is_refused() {
        let verifier = erase_verifier(Verifier::for_did_key());
        let mut doc = doc_with_dummy_proof(RecordPutRequest::type_uri());
        doc.proof = None;
        assert!(matches!(
            verify_write_proof(&verifier, None, &doc).await,
            Err(RejectReason::ProofRequired)
        ));
    }

    #[tokio::test]
    async fn write_without_issuer_is_refused() {
        let verifier = erase_verifier(Verifier::for_did_key());
        let mut doc = doc_with_dummy_proof(RecordPutRequest::type_uri());
        doc.issuer = None;
        assert!(matches!(
            verify_write_proof(&verifier, None, &doc).await,
            Err(RejectReason::MalformedRequest { .. })
        ));
    }

    fn document(authentication: Value) -> Document {
        serde_json::from_value(serde_json::json!({
            "id": "did:example:writer",
            "verificationMethod": [{
                "id": "did:example:writer#key-1",
                "type": "Multikey",
                "controller": "did:example:writer",
                "publicKeyMultibase": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
            }],
            "authentication": authentication,
            "assertionMethod": ["did:example:writer#key-1"]
        }))
        .expect("valid DID document")
    }

    #[test]
    fn a_key_listed_under_authentication_is_accepted() {
        let doc = document(serde_json::json!(["#key-1"]));
        assert!(is_authentication_method(&doc, "did:example:writer#key-1"));
    }

    #[test]
    fn a_key_listed_only_under_assertion_method_is_refused() {
        let doc = document(serde_json::json!([]));
        assert!(!is_authentication_method(&doc, "did:example:writer#key-1"));
    }

    /// A resolver that cannot be built at start is not given up on: writes by
    /// non-`did:key` issuers are answered `unavailable` (retryable) while it
    /// is missing, health says so, and the resolver is swapped in once a
    /// background attempt succeeds.
    #[tokio::test(start_paused = true)]
    async fn a_failed_resolver_is_retried_and_swapped_in() {
        use crate::health::RegistryHealth;
        use std::sync::atomic::{AtomicU32, Ordering};

        let health = Arc::new(RegistryHealth::new(false));
        let attempts = Arc::new(AtomicU32::new(0));
        let counted = attempts.clone();
        let verifier = build_verifier_with(
            move || {
                let counted = counted.clone();
                async move {
                    if counted.fetch_add(1, Ordering::SeqCst) < 2 {
                        Err("resolver cache unavailable".to_string())
                    } else {
                        // Stands in for the resolver-backed verifier.
                        Ok(erase_verifier(Verifier::for_did_key()))
                    }
                }
            },
            &health,
            &tokio_util::sync::CancellationToken::new(),
        )
        .await;

        assert_eq!(health.to_json()["verifier"], "didKeyOnly");
        assert_eq!(health.to_json()["status"], "degraded");
        let doc = doc_with_dummy_proof(RecordPutRequest::type_uri());
        assert!(
            matches!(
                verify_write_proof(&verifier, None, &doc).await,
                Err(RejectReason::Unavailable { .. })
            ),
            "a did:example proof is not invalid, only unverifiable for now"
        );

        // The paused clock jumps through the backoff.
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
        assert_eq!(health.to_json()["verifier"], "ok");
        assert!(matches!(
            verify_write_proof(&verifier, None, &doc).await,
            Err(RejectReason::ProofInvalid { .. })
        ));
    }

    /// Stands in for [`CachedDidResolver`]: fails every resolution with
    /// `message`, as it reports a resolver failure.
    struct FailingResolver(String);

    #[async_trait]
    impl ProofPurposeResolver for FailingResolver {
        async fn resolve_vm_for_purpose(
            &self,
            _vm: &str,
            _purpose: ProofPurpose,
        ) -> Result<ResolvedKey, DataIntegrityError> {
            Err(DataIntegrityError::Resolver(self.0.clone()))
        }
    }

    /// The registry's resolver-backed verifier over a resolver that fails
    /// every resolution with `message`.
    pub(crate) fn verifier_failing_with(message: impl Into<String>) -> Arc<dyn DynProofVerifier> {
        let resolver = AuthenticationKeyResolver::over(Arc::new(FailingResolver(message.into())));
        erase_verifier(Verifier::with_resolver(Arc::new(resolver)))
    }

    /// What [`CachedDidResolver`] reports for a resolver cache error `e`: its
    /// `format!("resolve the verificationMethod's DID: {e}")`. The prefix is
    /// copied (it is private to trust-tasks-proof); the cache's part is the
    /// real upstream `Display`, so a rewording there fails these tests.
    pub(crate) fn cache_error(e: DIDCacheError) -> String {
        format!("{CACHED_RESOLVER_RESOLVE}{e}")
    }

    /// A fetch the DID host answered with `status`.
    fn http(status: u16) -> DIDCacheError {
        DIDCacheError::NetworkFetch(
            NetworkFetchError::new(format!("HTTP {status}"))
                .with_url("https://example.com/.well-known/did.jsonl")
                .with_status(status),
        )
    }

    /// trust-tasks-proof 0.39's deadline message. Copied: it is a private
    /// string inside `CachedDidResolver::resolve_for`, with no type behind it
    /// to build it from.
    pub(crate) const TIMEOUT: &str = CACHED_RESOLVER_TIMEOUT;

    /// A DID host answering 404: the DID does not exist.
    pub(crate) fn not_found() -> String {
        cache_error(http(404))
    }

    async fn refusal(message: impl Into<String>) -> Result<(), RejectReason> {
        verify_write_proof(
            &verifier_failing_with(message),
            None,
            &doc_with_dummy_proof(RecordPutRequest::type_uri()),
        )
        .await
    }

    /// #302: trust-tasks-proof's own deadline is not a bad proof.
    #[tokio::test]
    async fn a_resolution_timeout_is_answered_unavailable() {
        assert!(matches!(
            refusal(TIMEOUT).await,
            Err(RejectReason::Unavailable { .. })
        ));
        assert!(matches!(
            refusal(cache_error(DIDCacheError::NetworkTimeout)).await,
            Err(RejectReason::Unavailable { .. })
        ));
    }

    /// #302: a DID host that could not be reached, or answered 5xx, is not a
    /// bad proof.
    #[tokio::test]
    async fn a_network_failure_is_answered_unavailable() {
        for error in [
            // No response at all: DNS, connect, TLS, reset.
            DIDCacheError::NetworkFetch(
                NetworkFetchError::new("dns error: failed to lookup address")
                    .with_url("https://example.com/.well-known/did.json"),
            ),
            DIDCacheError::NetworkFetch(NetworkFetchError::new("connection reset by peer")),
            http(503),
            http(429),
            DIDCacheError::TransportError("not connected".into()),
        ] {
            let message = cache_error(error);
            assert!(
                matches!(
                    refusal(message.clone()).await,
                    Err(RejectReason::Unavailable { .. })
                ),
                "{message}"
            );
        }
    }

    /// A definitive answer about the DID stays `proofInvalid`.
    #[tokio::test]
    async fn a_definitive_resolution_failure_is_answered_proof_invalid() {
        for message in [
            not_found(),
            cache_error(DIDCacheError::DIDError(
                "did:webvh:Qm:example.com is deactivated".into(),
            )),
            cache_error(DIDCacheError::UnsupportedMethod("example".into())),
            cache_error(DIDCacheError::DIDError("Failed to parse DID: bad".into())),
        ] {
            assert!(
                matches!(
                    refusal(message.clone()).await,
                    Err(RejectReason::ProofInvalid { .. })
                ),
                "{message}"
            );
        }
    }

    /// The real resolver, offline: a DID naming a private host (the host
    /// policy) and a DID the cache cannot resolve are definitive.
    #[tokio::test]
    async fn real_definitive_failures_stay_proof_invalid() {
        use affinidi_tdk::did_resolver::config::DIDCacheConfigBuilder;

        let client = Arc::new(
            DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
                .await
                .expect("local resolver cache"),
        );
        let resolver = AuthenticationKeyResolver::new(client);
        for vm in [
            "did:web:localhost#key-1",
            "did:web:10.0.0.1#key-1",
            "did:example:admin#key-1",
        ] {
            let err = resolver
                .resolve_vm_for_purpose(vm, ProofPurpose::Authentication)
                .await
                .expect_err("does not resolve");
            let DataIntegrityError::Resolver(message) = &err else {
                panic!("{err:?}");
            };
            assert_ne!(message, RESOLUTION_UNAVAILABLE, "{vm}");
            assert_eq!(
                classify_resolver_error(message),
                ResolutionFailure::Definitive,
                "{vm}: {message}"
            );
        }
    }

    /// The classification, form by form, including text a sender controls.
    #[test]
    fn resolver_errors_are_classified_conservatively() {
        use ResolutionFailure::{Definitive, Transient};
        for (message, expected) in [
            (CACHED_RESOLVER_TIMEOUT.to_string(), Transient),
            (cache_error(DIDCacheError::NetworkTimeout), Transient),
            (
                cache_error(DIDCacheError::TransportError(
                    "websocket handshake failed".into(),
                )),
                Transient,
            ),
            (
                cache_error(DIDCacheError::ConfigError("no network address".into())),
                Transient,
            ),
            (
                cache_error(DIDCacheError::NetworkFetch(
                    NetworkFetchError::new("HTTP 502").with_status(502),
                )),
                Transient,
            ),
            (cache_error(http(408)), Transient),
            (
                cache_error(DIDCacheError::NetworkFetch(
                    NetworkFetchError::new("HTTP 429").with_status(429),
                )),
                Transient,
            ),
            (
                cache_error(DIDCacheError::NetworkFetch(
                    NetworkFetchError::new("connection refused").with_url("https://h/x"),
                )),
                Transient,
            ),
            (cache_error(http(404)), Definitive),
            (cache_error(http(410)), Definitive),
            // A URL the sender chose cannot turn a 404 into a 503.
            (
                cache_error(DIDCacheError::NetworkFetch(
                    NetworkFetchError::new("HTTP 404")
                        .with_url("https://h/answered HTTP 503")
                        .with_status(404),
                )),
                Definitive,
            ),
            (
                cache_error(DIDCacheError::DIDError("not found".into())),
                Definitive,
            ),
            // A DID error whose text a sender may shape.
            (
                cache_error(DIDCacheError::DIDError("Network timeout".into())),
                Definitive,
            ),
            (
                cache_error(DIDCacheError::ParsingError("bad json".into())),
                Definitive,
            ),
            (
                format!("{CACHED_RESOLVER_RESOLVE}something new"),
                Definitive,
            ),
            ("resolver error: Network timeout".to_string(), Definitive),
        ] {
            assert_eq!(classify_resolver_error(&message), expected, "{message}");
        }
    }

    /// The marker reaches [`verify_proof`] exactly; a sender cannot forge it
    /// from inside a resolver message.
    #[tokio::test]
    async fn the_unavailable_marker_is_matched_exactly() {
        let forged = cache_error(DIDCacheError::DIDError(RESOLUTION_UNAVAILABLE.into()));
        // Not reclassified by the wrapper (a `DID error`), so not unavailable.
        assert!(matches!(
            refusal(forged).await,
            Err(RejectReason::ProofInvalid { .. })
        ));
    }

    /// A resolver that builds at once is used directly, and health says so.
    #[tokio::test]
    async fn a_resolver_that_builds_is_used_at_once() {
        let health = Arc::new(crate::health::RegistryHealth::new(false));
        let verifier = build_verifier_with(
            || async { Ok(erase_verifier(Verifier::for_did_key())) },
            &health,
            &tokio_util::sync::CancellationToken::new(),
        )
        .await;
        assert_eq!(health.to_json()["verifier"], "ok");
        assert!(matches!(
            verify_write_proof(
                &verifier,
                None,
                &doc_with_dummy_proof(RecordPutRequest::type_uri())
            )
            .await,
            Err(RejectReason::ProofInvalid { .. })
        ));
    }
}
