//! Emergency access, step by step.
//!
//! 1. The grantor invites a contact by email, with a kind (view or takeover) and a wait in days.
//! 2. The contact accepts from their own account.
//! 3. The grantor confirms: their app checks the contact's fingerprint and seals the root key to
//!    the contact's `kx1` key (docs/crypto.md, context `"emergency-access"`), and the server stores
//!    the box.
//! 4. Whenever the contact needs the vault they initiate recovery. The grantor is told and can
//!    refuse until the wait ends; the timer ([`ApproveDue`](super::ApproveDue)) approves when it
//!    has run out, unless the grantor refused.
//! 5. Once approved, the contact fetches the box. A takeover then sets a new password through the
//!    ordinary registration flow; the server's part ends at releasing the box.
//!
//! The server never opens the box. It hands it to the contact only in the `Approved` state.

use super::ports::{EmergencyEvent, EmergencyNotice, EmergencyNotices, EmergencyRepo};
use crate::authenticate::Actor;
use crate::error::AppError;
use crate::platform::{Platform, random_uuid};
use crate::ports::{Event, EventLog, UserRepo};
use kemlock_domain::unlock::{
    EmergencyError, EmergencyGrant, EmergencyKind, EmergencyState, GrantId, MAX_GRANTS_PER_GRANTOR,
};
use kemlock_domain::{Email, User, UserId};

pub(crate) fn grant_error(e: EmergencyError) -> AppError {
    match e {
        EmergencyError::WrongState(_) => AppError::Invalid("the grant can't take that step now"),
        EmergencyError::BadWait => AppError::Invalid("the wait must be 1 to 90 days"),
        EmergencyError::BadSealedKey => AppError::Invalid("the sealed key has the wrong shape"),
        EmergencyError::NotDue => AppError::Invalid("the wait hasn't ended"),
    }
}

/// The contact's public keys, for the grantor's app to check and seal to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContactKeys {
    pub public_bundle: Vec<u8>,
    pub bundle_signature: Vec<u8>,
    pub key_version: u32,
}

/// A grant as its two parties see it. The sealed key is never in a view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantView {
    pub grant: EmergencyGrant,
    /// The grantor's email, on the contact's side.
    pub grantor_email: Option<Email>,
    /// The contact's keys, on the grantor's side while the grant waits for confirmation.
    pub contact_keys: Option<ContactKeys>,
}

/// Both lists of an account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EmergencyOverview {
    /// Grants where the account is the grantor.
    pub trusted_contacts: Vec<GrantView>,
    /// Grants that name the account as the contact.
    pub grantors: Vec<GrantView>,
}

/// What the contact fetches once a grant is approved.
#[derive(Clone, PartialEq, Eq)]
pub struct KeyRelease {
    pub grant: GrantId,
    pub grantor: UserId,
    pub kind: EmergencyKind,
    /// The root key sealed to the contact's `kx1` key. Opaque to the server.
    pub sealed_key: Vec<u8>,
}

impl std::fmt::Debug for KeyRelease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyRelease")
            .field("grant", &self.grant)
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub struct EmergencyAccess<U, R, N, E, V> {
    pub users: U,
    pub grants: R,
    pub notices: N,
    pub env: E,
    pub events: V,
}

impl<U: UserRepo, R: EmergencyRepo, N: EmergencyNotices, E: Platform, V: EventLog>
    EmergencyAccess<U, R, N, E, V>
{
    /// Names a contact. The invitation goes to the email whether or not it has an account yet.
    pub async fn invite(
        &self,
        actor: &Actor,
        email: &str,
        kind: EmergencyKind,
        wait_days: u32,
    ) -> Result<EmergencyGrant, AppError> {
        let contact = Email::parse(email).map_err(|_| AppError::Invalid("not an email address"))?;
        let me = self.account(actor.user).await?;
        if me.email == contact {
            return Err(AppError::Invalid("you can't name yourself"));
        }
        let mine = self.grants.grants_of_grantor(actor.user).await?;
        if mine.len() >= MAX_GRANTS_PER_GRANTOR {
            return Err(AppError::Invalid(
                "that is as many contacts as one account can name",
            ));
        }
        if mine.iter().any(|g| g.grantee_email == contact) {
            return Err(AppError::Duplicate);
        }
        let grant = EmergencyGrant::invite(
            GrantId(random_uuid(&self.env)),
            actor.user,
            contact,
            kind,
            wait_days,
            self.env.now(),
        )
        .map_err(grant_error)?;
        self.grants.insert_grant(&grant).await?;
        self.record("emergency.invite", actor, grant.id).await;
        self.notify(grant.grantee_email.clone(), &grant, EmergencyEvent::Invited)
            .await;
        Ok(grant)
    }

    /// The contact accepts. The signed-in account's email must be the one the grantor named.
    pub async fn accept(&self, actor: &Actor, id: GrantId) -> Result<EmergencyGrant, AppError> {
        let me = self.account(actor.user).await?;
        let mut grant = self.load(id).await?;
        if grant.grantee_email != me.email {
            return Err(AppError::NotFound);
        }
        let from = grant.state;
        grant.accept(me.id, self.env.now()).map_err(grant_error)?;
        self.save(&grant, from).await?;
        self.record("emergency.accept", actor, id).await;
        if let Some(grantor) = self.users.by_id(grant.grantor).await? {
            self.notify(grantor.email, &grant, EmergencyEvent::Accepted)
                .await;
        }
        Ok(grant)
    }

    /// The grantor confirms the contact and stores the root key sealed to them.
    pub async fn confirm(
        &self,
        actor: &Actor,
        id: GrantId,
        sealed_key: Vec<u8>,
    ) -> Result<EmergencyGrant, AppError> {
        self.confirm_at(actor, id, sealed_key, None).await
    }

    /// [`confirm`](EmergencyAccess::confirm) with a box of the root key at `key_version`: refused
    /// (`StaleKeyVersion`) when the grantor has replaced their keys since. A client that doesn't
    /// say passes `None`.
    pub async fn confirm_at(
        &self,
        actor: &Actor,
        id: GrantId,
        sealed_key: Vec<u8>,
        key_version: Option<u32>,
    ) -> Result<EmergencyGrant, AppError> {
        let mut grant = self.owned(actor, id).await?;
        let from = grant.state;
        grant
            .confirm(sealed_key, self.env.now())
            .map_err(grant_error)?;
        self.save_at(&grant, from, key_version).await?;
        self.record("emergency.confirm", actor, id).await;
        self.notify(
            grant.grantee_email.clone(),
            &grant,
            EmergencyEvent::Confirmed,
        )
        .await;
        Ok(grant)
    }

    /// Whether the grantor's account may have grants in force: not disabled by an admin and not
    /// waiting out an erasure. Their grants are inactive meanwhile (a contact can't ask, the timer
    /// doesn't approve, a key isn't released) and are as they were when the account is back.
    async fn grantor_is_active(&self, grantor: UserId) -> Result<bool, AppError> {
        Ok(!self.users.account_disabled(grantor).await?
            && self.users.erasure_pending(grantor).await?.is_none())
    }

    /// The contact asks for access: the wait starts and the grantor is told.
    pub async fn initiate(&self, actor: &Actor, id: GrantId) -> Result<EmergencyGrant, AppError> {
        let mut grant = self.addressed(actor, id).await?;
        if !self.grantor_is_active(grant.grantor).await? {
            return Err(AppError::Forbidden);
        }
        let from = grant.state;
        grant.initiate(self.env.now()).map_err(grant_error)?;
        self.save(&grant, from).await?;
        self.record("emergency.initiate", actor, id).await;
        if let Some(grantor) = self.users.by_id(grant.grantor).await? {
            self.notify(grantor.email, &grant, EmergencyEvent::RecoveryInitiated)
                .await;
        }
        Ok(grant)
    }

    /// The grantor says yes before the wait ends.
    pub async fn approve(&self, actor: &Actor, id: GrantId) -> Result<EmergencyGrant, AppError> {
        let mut grant = self.owned(actor, id).await?;
        let from = grant.state;
        grant.approve_early(self.env.now()).map_err(grant_error)?;
        self.save(&grant, from).await?;
        self.record("emergency.approve", actor, id).await;
        self.notify(
            grant.grantee_email.clone(),
            &grant,
            EmergencyEvent::Approved,
        )
        .await;
        Ok(grant)
    }

    /// The grantor refuses a running request, or takes back an approval.
    pub async fn reject(&self, actor: &Actor, id: GrantId) -> Result<EmergencyGrant, AppError> {
        let mut grant = self.owned(actor, id).await?;
        let from = grant.state;
        grant.reject(self.env.now()).map_err(grant_error)?;
        self.save(&grant, from).await?;
        self.record("emergency.reject", actor, id).await;
        self.notify(
            grant.grantee_email.clone(),
            &grant,
            EmergencyEvent::Rejected,
        )
        .await;
        Ok(grant)
    }

    /// Either party ends the grant: it is deleted, sealed key and all.
    pub async fn revoke(&self, actor: &Actor, id: GrantId) -> Result<(), AppError> {
        let grant = self.load(id).await?;
        if grant.grantor != actor.user && grant.grantee != Some(actor.user) {
            return Err(AppError::NotFound);
        }
        self.grants.remove_grant(id).await?;
        self.record("emergency.revoke", actor, id).await;
        Ok(())
    }

    /// The sealed key, for the contact, once the grant is approved.
    pub async fn release_key(&self, actor: &Actor, id: GrantId) -> Result<KeyRelease, AppError> {
        let grant = self.addressed(actor, id).await?;
        if !self.grantor_is_active(grant.grantor).await? {
            return Err(AppError::Forbidden);
        }
        if !grant.key_released() {
            return Err(AppError::Forbidden);
        }
        let sealed_key = grant.sealed_key.ok_or(AppError::Forbidden)?;
        self.record("emergency.release", actor, id).await;
        Ok(KeyRelease {
            grant: id,
            grantor: grant.grantor,
            kind: grant.kind,
            sealed_key,
        })
    }

    /// Both lists of the signed-in account.
    pub async fn list(&self, actor: &Actor) -> Result<EmergencyOverview, AppError> {
        let me = self.account(actor.user).await?;
        let mut trusted_contacts = Vec::new();
        for mut grant in self.grants.grants_of_grantor(actor.user).await? {
            grant.sealed_key = None;
            let contact_keys = match (grant.state, grant.grantee) {
                (EmergencyState::Accepted, Some(contact)) => {
                    self.users.by_id(contact).await?.map(|u| ContactKeys {
                        public_bundle: u.public_bundle,
                        bundle_signature: u.bundle_signature,
                        key_version: u.key_version,
                    })
                }
                _ => None,
            };
            trusted_contacts.push(GrantView {
                grant,
                grantor_email: None,
                contact_keys,
            });
        }
        let mut grantors = Vec::new();
        for mut grant in self.grants.grants_for_email(&me.email).await? {
            // A grant the account hasn't accepted yet is still shown, so it can be.
            if grant.grantee.is_some_and(|g| g != me.id) {
                continue;
            }
            grant.sealed_key = None;
            let grantor_email = self.users.by_id(grant.grantor).await?.map(|u| u.email);
            grantors.push(GrantView {
                grant,
                grantor_email,
                contact_keys: None,
            });
        }
        Ok(EmergencyOverview {
            trusted_contacts,
            grantors,
        })
    }

    async fn account(&self, id: UserId) -> Result<User, AppError> {
        self.users.by_id(id).await?.ok_or(AppError::Unauthorized)
    }

    async fn load(&self, id: GrantId) -> Result<EmergencyGrant, AppError> {
        self.grants.grant(id).await?.ok_or(AppError::NotFound)
    }

    /// A grant the actor made; anyone else's is `NotFound`.
    async fn owned(&self, actor: &Actor, id: GrantId) -> Result<EmergencyGrant, AppError> {
        let grant = self.load(id).await?;
        if grant.grantor != actor.user {
            return Err(AppError::NotFound);
        }
        Ok(grant)
    }

    /// A grant that names the actor as its contact, accepted by them.
    async fn addressed(&self, actor: &Actor, id: GrantId) -> Result<EmergencyGrant, AppError> {
        let grant = self.load(id).await?;
        if grant.grantee != Some(actor.user) {
            return Err(AppError::NotFound);
        }
        Ok(grant)
    }

    async fn save(&self, grant: &EmergencyGrant, from: EmergencyState) -> Result<(), AppError> {
        if self.grants.save_grant(grant, from).await? {
            Ok(())
        } else {
            Err(AppError::Invalid("the grant changed; look again and retry"))
        }
    }

    async fn save_at(
        &self,
        grant: &EmergencyGrant,
        from: EmergencyState,
        key_version: Option<u32>,
    ) -> Result<(), AppError> {
        if self.grants.save_grant_at(grant, from, None, key_version).await? {
            Ok(())
        } else {
            Err(AppError::Invalid("the grant changed; look again and retry"))
        }
    }

    async fn record(&self, action: &'static str, actor: &Actor, id: GrantId) {
        let event = Event {
            actor: Some(actor.user),
            device: Some(actor.device),
            action,
            target: Some(id.to_string()),
            at: self.env.now(),
        };
        if let Err(e) = self.events.record(event).await {
            tracing::warn!(action, error = %e, "couldn't record an event");
        }
    }

    async fn notify(&self, to: Email, grant: &EmergencyGrant, event: EmergencyEvent) {
        self.notices
            .notify(EmergencyNotice {
                to,
                grant: grant.id,
                event,
                kind: grant.kind,
                wait_days: grant.wait_days,
            })
            .await;
    }
}
