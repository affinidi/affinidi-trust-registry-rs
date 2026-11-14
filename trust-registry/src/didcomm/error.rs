use affinidi_tdk::{common::errors::TDKError, messaging::errors::ATMError};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DIDCommError {
    #[error("ATM error: {0}")]
    ATM(#[from] ATMError),

    #[error("Mediator not configured")]
    MissingMediator,

    #[error("Timeout: {0}")]
    ElapsedTimeout(#[from] tokio::time::error::Elapsed),

    #[error("TDK error: {0}")]
    TDK(#[from] TDKError),

    #[error("Missing ATM instance")]
    MissingATM,

    #[error("Messaging error: {0}")]
    Messaging(String),

    /// The `did:web` document could not be fetched; carries the URL tried.
    #[error("Trust Registry DID document is unreachable at {0}")]
    UnreachableDidDocument(String),

    #[error("Invalid DID format")]
    InvalidDid,

    #[error("HTTP request error: {0}")]
    HttpRequest(#[from] reqwest::Error),

    #[error(
        "Failed to set ACL mode ExplicitAllow at the mediator ({0}); not serving DIDComm while \
         the registry may be reachable by anyone"
    )]
    PrivateAclNotApplied(String),
}
