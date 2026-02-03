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

    #[error("Trust Registry DID document is unreachable at /.well-known/did.json")]
    UnreachableDidDocument,

    #[error("Invalid DID format")]
    InvalidDid,

    #[error("HTTP request error: {0}")]
    HttpRequest(#[from] reqwest::Error),
}
