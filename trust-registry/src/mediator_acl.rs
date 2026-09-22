//! The trust registry's own access-list mode at its mediator, set through the
//! mediator's `messaging/account/*` Trust Tasks.
//!
//! This replaces the legacy DIDComm `mediator/1.0/account-management` and
//! `acl-management` protocols, which mediators now warn about and can switch
//! off (`security.legacy_admin_protocols`, affinidi-messaging-mediator 0.28.29).

use std::sync::Arc;

use affinidi_tdk::messaging::{ATM, profiles::ATMProfile};
use trust_tasks_rs::specs::messaging::account::get::v0_1::MediatorAclAccessListMode as ReportedMode;
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

/// `profile`'s current access-list mode at its mediator, or `None` when the
/// mediator reports none. A mode this registry does not recognise is an error,
/// never read as public: the access-list mode decides who may reach the
/// registry, so an unknown state must not be mistaken for an open one.
pub async fn access_list_mode(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
) -> Result<Option<AccessListMode>, Box<dyn std::error::Error + Send + Sync>> {
    let account = atm.trust_tasks().account_get(profile, None).await?;
    Ok(from_reported(account.acl.access_list_mode)?)
}

/// Map the mediator's reported mode, exactly. Only the two known modes map;
/// anything else (a mode added to the spec later) is refused.
fn from_reported(reported: Option<ReportedMode>) -> Result<Option<AccessListMode>, String> {
    match reported {
        None => Ok(None),
        Some(ReportedMode::ExplicitAllow) => Ok(Some(AccessListMode::ExplicitAllow)),
        Some(ReportedMode::ExplicitDeny) => Ok(Some(AccessListMode::ExplicitDeny)),
        Some(other) => Err(format!(
            "the mediator reported an access-list mode this registry does not know ({other}); \
             refusing to guess whether the registry is public"
        )),
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_known_modes_map_and_none_stays_unknown() {
        assert_eq!(
            from_reported(Some(ReportedMode::ExplicitAllow)).unwrap(),
            Some(AccessListMode::ExplicitAllow)
        );
        assert_eq!(
            from_reported(Some(ReportedMode::ExplicitDeny)).unwrap(),
            Some(AccessListMode::ExplicitDeny)
        );
        assert_eq!(from_reported(None).unwrap(), None);
    }
}
