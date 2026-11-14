//! Does the DID document this registry **publishes** match what this binary
//! actually serves?
//!
//! ## Why this exists
//!
//! [`TransportFlags::validate`](super::did_document::TransportFlags::validate)
//! already refuses `ENABLE_TSP=true` on a build without the `tsp` feature. That
//! guard protects the document this process *builds* — the one served at
//! `/.well-known/did.json`. It cannot protect the document peers actually
//! resolve, because the registry does not write that one: a `did:webvh` log is
//! published by the VTA / DID-hosting service at provisioning time and is never
//! revisited. The two can therefore disagree indefinitely, and the flags default
//! to `ENABLE_TSP=false`.
//!
//! That is not hypothetical. A reference deployment published `#tsp` at
//! provisioning, ran with `ENABLE_TSP` unset, and was silently TSP-blind for
//! days. Peers read the document, correctly chose the highest-preference
//! transport it advertised, sent, and waited. The registry dropped every frame
//! with one `WARN` on a log nobody was reading; the VTC saw a 60-second timeout
//! and reported `registry_status=degraded` with no way to tell that the peer was
//! answering on a different protocol. Both ends were behaving exactly as
//! designed, and the deployment was still broken.
//!
//! ## What it does, and what it deliberately does not
//!
//! Resolves this registry's own DID **over the network** — the published view,
//! not the local mirror — and reports each disagreement with what this build and
//! configuration can serve:
//!
//! - advertised but unservable → `ERROR`, naming both remedies. A peer that
//!   picks this transport is silently dropped.
//! - servable but unadvertised → `INFO`. Normal mid-rollout (ship the capable
//!   binary, then add the service entry).
//!
//! It does **not** refuse to boot. Unknown is not the same as bad: resolution
//! fails on a resolver blip or a DID host hiccup, and a registry that stops
//! answering DIDComm because it could not resolve itself is a worse outcome than
//! the mismatch it is trying to report. `vtc-service` makes the same split — its
//! `enforce_at_boot` refuses only on the *local* document it controls, while the
//! resolved view is advisory.
//!
//! Matching is on the service **`type`**, never the `#id` fragment: the fragment
//! is an arbitrary label (`#tsp` here, `#tsp-transport` in the OWF reference
//! implementation, `#vta-didcomm` on a document minted by an older template) and
//! keying on it reads a correctly-advertised transport as absent.

use serde_json::Value;

use super::did_document::{
    DIDCOMM_SERVICE_TYPE, REST_SERVICE_TYPE, TRUST_REGISTRY_SERVICE_TYPE, TSP_SERVICE_TYPE,
    TransportFlags,
};
use crate::configs::DidcommConfig;
use crate::health::TransportState;

/// How long the startup check may spend resolving the registry's own DID.
/// It runs in the background, so this bounds only how long `/health` waits for
/// a `transports` value.
pub const CHECK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Which transports a DID document names, or which a build can serve.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Transports {
    pub tsp: bool,
    pub didcomm: bool,
    pub rest: bool,
}

/// How loudly a [`Finding`] should be reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// A peer choosing this transport is dropped in silence.
    Error,
    /// Worth knowing, not broken.
    Info,
}

/// One disagreement between the published document and this build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub severity: Severity,
    pub message: String,
}

/// Does this service entry's `type` name `wanted`?
///
/// `type` is a string **or an array of strings** in DID Core, and both shapes
/// occur in the wild — the reference mediator publishes
/// `"type": ["DIDCommMessaging"]` while this registry writes a bare string. A
/// reader that handles only one shape silently sees no services at all on the
/// other, which reads identically to "the peer advertises nothing".
fn service_is(entry: &Value, wanted: &str) -> bool {
    match entry.get("type") {
        Some(Value::String(t)) => t == wanted,
        Some(Value::Array(types)) => types.iter().any(|t| t.as_str() == Some(wanted)),
        _ => false,
    }
}

/// Read the transports a resolved DID document advertises. A TRQP surface is
/// advertised by either `TRQPRest` or the ToIP `TrustRegistry` type.
pub fn advertised_in(document: &Value) -> Transports {
    let services = document
        .get("service")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    Transports {
        tsp: services.iter().any(|s| service_is(s, TSP_SERVICE_TYPE)),
        didcomm: services.iter().any(|s| service_is(s, DIDCOMM_SERVICE_TYPE)),
        rest: services.iter().any(|s| {
            service_is(s, REST_SERVICE_TYPE) || service_is(s, TRUST_REGISTRY_SERVICE_TYPE)
        }),
    }
}

/// What this build **and** this configuration can actually answer.
///
/// The `tsp` arm is the whole point: a runtime flag cannot conjure a compiled-out
/// binding, so it is `flags.tsp && cfg!(feature = "tsp")` and not just the flag.
pub fn served(flags: &TransportFlags) -> Transports {
    Transports {
        tsp: flags.tsp && cfg!(feature = "tsp"),
        didcomm: flags.didcomm,
        rest: flags.rest,
    }
}

/// Compare a published document against what this build serves.
///
/// Equivalent to [`findings_for`] with a public REST URL configured.
pub fn findings(advertised: &Transports, served: &Transports) -> Vec<Finding> {
    findings_for(advertised, served, true)
}

/// Compare a published document against what this build serves.
///
/// `rest_public_url` says whether the registry has a public URL to advertise
/// its REST surface at (`TR_PUBLIC_URL`). Without one, REST served but not
/// advertised is the expected state, not a rollout step, so it is not
/// reported.
pub fn findings_for(
    advertised: &Transports,
    served: &Transports,
    rest_public_url: bool,
) -> Vec<Finding> {
    let mut out = Vec::new();

    if advertised.tsp && !served.tsp {
        out.push(Finding {
            severity: Severity::Error,
            message: format!(
                "this registry's published DID document advertises {TSP_SERVICE_TYPE}, but this \
                 build cannot serve it, so every TSP frame a peer sends is dropped unread and \
                 the peer sees only a timeout. Either run a binary built with `--features tsp` \
                 and set ENABLE_TSP=true, or remove the TSP service entry from the published \
                 document."
            ),
        });
    }
    if advertised.didcomm && !served.didcomm {
        out.push(Finding {
            severity: Severity::Error,
            message: format!(
                "this registry's published DID document advertises {DIDCOMM_SERVICE_TYPE}, but \
                 ENABLE_DIDCOMM is not set, so no listener is running and messages queue at the \
                 mediator unread. Either set ENABLE_DIDCOMM=true, or remove the DIDComm service \
                 entry from the published document."
            ),
        });
    }
    if advertised.rest && !served.rest {
        out.push(Finding {
            severity: Severity::Error,
            message: format!(
                "this registry's published DID document advertises {REST_SERVICE_TYPE}, but \
                 ENABLE_REST is not set, so nothing answers on the HTTP surface. Either set \
                 ENABLE_REST=true, or remove the REST service entry from the published document."
            ),
        });
    }

    // The other direction is routine: the capable binary usually ships before
    // the document names the service. Said once, at info, so a rollout can see
    // its own progress without it reading as a fault.
    for (servable, advertised_it, name) in [
        (served.tsp, advertised.tsp, TSP_SERVICE_TYPE),
        (served.didcomm, advertised.didcomm, DIDCOMM_SERVICE_TYPE),
        (
            served.rest && rest_public_url,
            advertised.rest,
            REST_SERVICE_TYPE,
        ),
    ] {
        if servable && !advertised_it {
            out.push(Finding {
                severity: Severity::Info,
                message: format!(
                    "this registry serves {name} but its published DID document does not \
                     advertise it, so no peer will choose it. Normal mid-rollout; add the \
                     service entry to start receiving that traffic."
                ),
            });
        }
    }

    out
}

/// What `config` serves. DIDComm (and TSP, which rides on its socket) counts
/// only when the listener — or the host's receive loop — is enabled, whatever
/// its transport flag says.
pub fn served_by(config: &DidcommConfig) -> Transports {
    let mut flags = config.transport_flags;
    flags.didcomm &= config.is_enabled;
    flags.tsp &= config.is_enabled;
    served(&flags)
}

/// Whether the registry's own local DID document advertises a REST endpoint,
/// which it does only when a public URL is configured.
fn local_document_advertises_rest(config: &DidcommConfig) -> bool {
    serde_json::from_str::<Value>(&config.did_document)
        .map(|doc| advertised_in(&doc).rest)
        .unwrap_or(false)
}

/// Resolve this registry's own DID and log every disagreement with what this
/// build serves. Best-effort: never fails startup.
///
/// Returns [`TransportState::Mismatch`] when an error-severity finding was
/// logged, [`TransportState::Ok`] when there was none, and
/// [`TransportState::Unknown`] when the document could not be resolved.
pub async fn report_at_startup(config: &DidcommConfig) -> TransportState {
    use affinidi_tdk::did_resolver::{DIDCacheClient, config::DIDCacheConfigBuilder};

    let own_did = config.profile_config.did.as_str();
    let resolved = match DIDCacheClient::new(DIDCacheConfigBuilder::default().build()).await {
        Ok(client) => client.resolve(own_did).await,
        Err(e) => {
            tracing::debug!(
                error = %e,
                "no DID resolver available; skipping the advertised-vs-served transport check",
            );
            return TransportState::Unknown;
        }
    };

    let document = match resolved {
        Ok(r) => match serde_json::to_value(&r.doc) {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!(error = %e, "could not read this registry's own DID document");
                return TransportState::Unknown;
            }
        },
        Err(e) => {
            // Unknown is not bad. Logged at debug because a resolver blip during
            // boot is common and this check is advisory.
            tracing::debug!(
                did = own_did,
                error = %e,
                "could not resolve this registry's own DID; skipping the advertised-vs-served \
                 transport check",
            );
            return TransportState::Unknown;
        }
    };

    report_findings(
        &advertised_in(&document),
        &served_by(config),
        local_document_advertises_rest(config),
    )
}

/// Log [`findings_for`] and summarise them for `/health`.
fn report_findings(
    advertised: &Transports,
    served: &Transports,
    rest_public_url: bool,
) -> TransportState {
    let mut state = TransportState::Ok;
    for finding in findings_for(advertised, served, rest_public_url) {
        match finding.severity {
            Severity::Error => {
                tracing::error!("{}", finding.message);
                state = TransportState::Mismatch;
            }
            Severity::Info => tracing::info!("{}", finding.message),
        }
    }
    state
}

/// Run [`report_at_startup`] in the background, bounded by [`CHECK_TIMEOUT`]
/// and by `shutdown`, and record its outcome on `health`.
///
/// Runs for every transport configuration that has a DID of its own: REST-only
/// (when the host configured a DID), host-driven and the registry's own
/// listener alike. A standalone REST-only registry loads no DID, so there is
/// no published document to compare and nothing is recorded.
pub(crate) fn spawn_startup_check(
    config: &DidcommConfig,
    health: std::sync::Arc<crate::health::RegistryHealth>,
    shutdown: tokio_util::sync::CancellationToken,
) -> Option<tokio::task::JoinHandle<()>> {
    if config.profile_config.did.trim().is_empty() {
        tracing::debug!(
            "no registry DID configured; skipping the advertised-vs-served transport check"
        );
        return None;
    }
    let config = config.clone();
    Some(tokio::spawn(async move {
        let state = tokio::select! {
            _ = shutdown.cancelled() => return,
            result = tokio::time::timeout(CHECK_TIMEOUT, report_at_startup(&config)) => {
                result.unwrap_or_else(|_| {
                    tracing::debug!(
                        "resolving this registry's own DID took longer than {CHECK_TIMEOUT:?}; \
                         skipping the advertised-vs-served transport check"
                    );
                    TransportState::Unknown
                })
            }
        };
        health.set_transports(state);
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn doc_with(services: Value) -> Value {
        json!({ "id": "did:webvh:scid:registry.example", "service": services })
    }

    #[test]
    fn a_type_array_is_read_the_same_as_a_bare_string() {
        // The reference mediator publishes `"type": ["DIDCommMessaging"]`. Read
        // only the string form and its services vanish, which is indistinguishable
        // from a peer that advertises nothing.
        let as_string = doc_with(json!([{ "id": "#didcomm", "type": "DIDCommMessaging" }]));
        let as_array = doc_with(json!([{ "id": "#service", "type": ["DIDCommMessaging"] }]));
        assert!(advertised_in(&as_string).didcomm);
        assert!(advertised_in(&as_array).didcomm);
    }

    #[test]
    fn the_id_fragment_is_never_what_matching_keys_on() {
        // `#tsp` here, `#tsp-transport` upstream, `#vta-didcomm` from an older
        // template: all arbitrary labels. The type is the contract.
        let odd_fragments = doc_with(json!([
            { "id": "#tsp-transport", "type": "TSPTransport" },
            { "id": "#vta-didcomm", "type": "DIDCommMessaging" },
        ]));
        let found = advertised_in(&odd_fragments);
        assert!(found.tsp);
        assert!(found.didcomm);

        // ...and a fragment that *looks* right with the wrong type is not a match.
        let liar = doc_with(json!([{ "id": "#tsp", "type": "SomethingElse" }]));
        assert!(!advertised_in(&liar).tsp);
    }

    #[test]
    fn a_document_with_no_services_advertises_nothing() {
        assert_eq!(
            advertised_in(&json!({ "id": "did:example:x" })),
            Transports::default()
        );
        assert_eq!(advertised_in(&doc_with(json!([]))), Transports::default());
    }

    #[test]
    fn advertising_a_transport_this_build_cannot_serve_is_an_error() {
        // The live failure this module exists for: `#tsp` published, ENABLE_TSP
        // unset. Every TSP frame is dropped and the sender sees only silence.
        let advertised = Transports {
            tsp: true,
            didcomm: true,
            rest: false,
        };
        let served = Transports {
            tsp: false,
            didcomm: true,
            rest: false,
        };

        let out = findings(&advertised, &served);
        assert_eq!(out.len(), 1, "exactly the TSP mismatch: {out:?}");
        assert_eq!(out[0].severity, Severity::Error);
        assert!(out[0].message.contains(TSP_SERVICE_TYPE));
        // The message has to carry the fix, not just the fault.
        assert!(out[0].message.contains("--features tsp"));
        assert!(out[0].message.contains("ENABLE_TSP=true"));
    }

    #[test]
    fn serving_a_transport_the_document_omits_is_only_informational() {
        // Ship the capable binary, then publish the service. Not a fault.
        let advertised = Transports {
            tsp: false,
            didcomm: true,
            rest: false,
        };
        let served = Transports {
            tsp: true,
            didcomm: true,
            rest: false,
        };

        let out = findings(&advertised, &served);
        assert_eq!(out.len(), 1, "{out:?}");
        assert_eq!(out[0].severity, Severity::Info);
        assert!(out[0].message.contains(TSP_SERVICE_TYPE));
    }

    #[test]
    fn a_document_that_matches_the_build_reports_nothing() {
        let both = Transports {
            tsp: true,
            didcomm: true,
            rest: true,
        };
        assert!(findings(&both, &both).is_empty());
    }

    #[test]
    fn the_flag_alone_does_not_count_as_serving_tsp() {
        // A runtime flag cannot conjure a compiled-out binding. Without the
        // feature this must read as "not served" however the flag is set, which
        // is what turns a stale advertisement into an error rather than silence.
        let flags = TransportFlags {
            rest: true,
            didcomm: true,
            tsp: true,
        };
        assert_eq!(served(&flags).tsp, cfg!(feature = "tsp"));

        let off = TransportFlags {
            rest: true,
            didcomm: true,
            tsp: false,
        };
        assert!(!served(&off).tsp, "flag off is never served");
    }

    /// The ToIP `TrustRegistry` type names a TRQP surface as much as
    /// `TRQPRest` does.
    #[test]
    fn the_toip_trust_registry_type_counts_as_rest() {
        let doc = doc_with(json!([{ "id": "#trust-registry", "type": "TrustRegistry" }]));
        assert!(advertised_in(&doc).rest);

        let out = findings_for(
            &advertised_in(&doc),
            &Transports {
                tsp: false,
                didcomm: true,
                rest: false,
            },
            false,
        );
        assert!(
            out.iter()
                .any(|f| f.severity == Severity::Error && f.message.contains("ENABLE_REST")),
            "{out:?}"
        );
    }

    /// Without a public URL there is nothing to advertise, so REST served but
    /// not advertised is not a rollout step to report.
    #[test]
    fn rest_without_a_public_url_is_not_reported_as_unadvertised() {
        let advertised = Transports::default();
        let served = Transports {
            tsp: false,
            didcomm: false,
            rest: true,
        };
        assert!(findings_for(&advertised, &served, false).is_empty());
        assert_eq!(findings_for(&advertised, &served, true).len(), 1);
    }

    /// The case the check used to skip: a REST-only registry whose published
    /// document still advertises DIDComm is an error finding and a `/health`
    /// mismatch.
    #[test]
    fn a_rest_only_registry_advertising_didcomm_is_a_mismatch() {
        let config = DidcommConfig::disabled();
        let served = served_by(&config);
        assert_eq!(
            served,
            Transports {
                tsp: false,
                didcomm: false,
                rest: true,
            }
        );
        let advertised = advertised_in(&doc_with(json!([
            { "id": "#didcomm", "type": "DIDCommMessaging" },
        ])));
        let out = findings_for(&advertised, &served, false);
        assert!(
            out.iter()
                .any(|f| f.severity == Severity::Error && f.message.contains("ENABLE_DIDCOMM")),
            "{out:?}"
        );
        assert_eq!(
            report_findings(&advertised, &served, false),
            TransportState::Mismatch
        );
    }

    /// The flag alone does not make DIDComm served: an embedded config can
    /// leave `transport_flags.didcomm` at `true` with the listener disabled.
    #[test]
    fn didcomm_is_served_only_when_enabled() {
        let mut config = DidcommConfig::default();
        config.transport_flags.didcomm = true;
        config.is_enabled = false;
        assert!(!served_by(&config).didcomm);
        config.is_enabled = true;
        assert!(served_by(&config).didcomm);
    }

    /// With no DID of its own (a standalone REST-only registry), there is no
    /// published document to check and nothing is spawned.
    #[tokio::test]
    async fn no_did_means_no_check() {
        let health = std::sync::Arc::new(crate::health::RegistryHealth::new(false));
        let handle = spawn_startup_check(
            &DidcommConfig::disabled(),
            health.clone(),
            tokio_util::sync::CancellationToken::new(),
        );
        assert!(handle.is_none());
        assert!(health.to_json().get("transports").is_none());
    }
}
