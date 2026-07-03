use affinidi_tdk::{
    TDK,
    common::{config::TDKConfig, profiles::TDKProfile},
    messaging::{ATM, profiles::ATMProfile},
    secrets_resolver::secrets::Secret,
};
use std::{sync::Arc, time::Duration};
use tokio::time::timeout;
use tracing::error;

pub mod did_document;
pub mod handlers;
pub mod service;

pub async fn prepare_atm_and_profile(
    alias: &str,
    service_did: &str,
    mediator_did: &str,
    secrets: Vec<Secret>,
    live_stream: bool,
) -> Result<(Arc<ATM>, Arc<ATMProfile>), Box<dyn std::error::Error>> {
    let service_profile = TDKProfile::new(alias, service_did, Some(mediator_did), secrets);

    let tdk = TDK::new(
        TDKConfig::builder()
            .with_load_environment(false)
            .build()
            .map_err(|e| e.to_string())?,
        None,
    )
    .await
    .map_err(|e| e.to_string())?;
    tdk.add_profile(&service_profile).await;

    let atm = tdk
        .atm
        .clone()
        .ok_or_else(|| "Failed to initialize ATM client".to_owned())?;

    let service_profile = match timeout(
        Duration::from_secs(5),
        atm.profile_add(
            &ATMProfile::from_tdk_profile(&atm, &service_profile)
                .await
                .map_err(|e| e.to_string())?,
            live_stream,
        ),
    )
    .await
    {
        Ok(profile) => profile.map_err(|e| e.to_string())?,
        Err(err) => {
            error!("Failed to add profile: {alias:?}, error: {err:#?}");
            return Err(format!("Failed to add profile: {alias:?}, error: {err:#?}").into());
        }
    };

    Ok((Arc::new(atm), service_profile))
}
