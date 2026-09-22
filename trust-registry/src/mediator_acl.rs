//! The trust registry's own access-list mode at its mediator, set through the
//! mediator's `messaging/account/*` Trust Tasks.
//!
//! This replaces the legacy DIDComm `mediator/1.0/account-management` and
//! `acl-management` protocols, which mediators now warn about and can switch
//! off (`security.legacy_admin_protocols`, affinidi-messaging-mediator 0.28.29).

use std::sync::Arc;

use affinidi_tdk::messaging::{ATM, profiles::ATMProfile};
use trust_tasks_rs::specs::messaging::account::update::v0_1::{
    MediatorAcl, MediatorAclAccessListMode,
};

/// Who may send to the registry's DID.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessListMode {
    /// Anyone not on the deny list (public).
    ExplicitDeny,
    /// Only DIDs on the allow list (private).
    ExplicitAllow,
}

impl From<AccessListMode> for MediatorAclAccessListMode {
    fn from(mode: AccessListMode) -> Self {
        match mode {
            AccessListMode::ExplicitDeny => MediatorAclAccessListMode::ExplicitDeny,
            AccessListMode::ExplicitAllow => MediatorAclAccessListMode::ExplicitAllow,
        }
    }
}

/// Set `profile`'s access-list mode at its mediator. Only the mode changes:
/// `account/update` is a partial update, so every other ACL flag is left as it
/// is.
pub async fn set_access_list_mode(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    mode: AccessListMode,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let acl: MediatorAcl = MediatorAcl::builder()
        .access_list_mode(Some(mode.into()))
        .try_into()?;
    atm.trust_tasks()
        .account_update(profile, None, None, Some(acl), None)
        .await?;
    Ok(())
}

/// `profile`'s current access-list mode at its mediator, when it reports one.
pub async fn access_list_mode(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
) -> Result<Option<AccessListMode>, Box<dyn std::error::Error + Send + Sync>> {
    let account = atm.trust_tasks().account_get(profile, None).await?;
    let mode = serde_json::to_value(&account.acl)?
        .get("accessListMode")
        .and_then(|m| m.as_str())
        .map(|m| match m {
            "explicitAllow" => AccessListMode::ExplicitAllow,
            _ => AccessListMode::ExplicitDeny,
        });
    Ok(mode)
}

/// Make the registry public (explicit-deny) if it is currently private.
pub async fn open_if_private(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if access_list_mode(atm, profile).await? == Some(AccessListMode::ExplicitAllow) {
        set_access_list_mode(atm, profile, AccessListMode::ExplicitDeny).await?;
    }
    Ok(())
}
