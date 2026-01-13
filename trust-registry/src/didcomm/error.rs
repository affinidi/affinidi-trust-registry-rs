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
}
