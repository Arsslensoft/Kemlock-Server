//! The profile port over a few maps and the fake store: the accounts a single sign-on identity
//! owns, the pending changes of sign-in address, and the emergency-access grants an address change
//! moves. The two writes that replace an account's records go to the fake store's row, under the
//! same condition the real store's UPDATE has. Included by the app's and the API's tests.

use super::FakeStore;
use kemlock_app::ports::StoreError;
use kemlock_app::profile::ProfileRepo;
use kemlock_domain::unlock::EmergencyGrant;
use kemlock_domain::{EmailChange, User, UserId};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct Inner {
    sso: HashSet<UserId>,
    changes: HashMap<UserId, EmailChange>,
    grants: Vec<EmergencyGrant>,
    /// Another request writes the account just before the next write of this port.
    interfere: bool,
}

#[derive(Clone)]
pub(crate) struct FakeProfile {
    inner: Arc<Mutex<Inner>>,
    store: FakeStore,
}

impl FakeProfile {
    /// The port over `store`, whose accounts its writes change.
    pub(crate) fn over(store: &FakeStore) -> Self {
        FakeProfile {
            inner: Arc::default(),
            store: store.clone(),
        }
    }

    /// Links the account to a single sign-on identity.
    pub(crate) fn link_sso(&self, user: UserId) {
        self.inner.lock().expect("the lock").sso.insert(user);
    }

    /// The account's pending change, whether its link has run out or not.
    pub(crate) fn pending(&self, user: UserId) -> Option<EmailChange> {
        self.inner
            .lock()
            .expect("the lock")
            .changes
            .get(&user)
            .cloned()
    }

    /// Makes another request write the account just before the next write of this port: the write
    /// finds the account changed since it was read, as a request racing it would.
    pub(crate) fn interfere_once(&self) {
        self.inner.lock().expect("the lock").interfere = true;
    }

    /// Adds an emergency-access grant to what an address change moves.
    pub(crate) fn add_grant(&self, grant: EmergencyGrant) {
        self.inner.lock().expect("the lock").grants.push(grant);
    }

    /// The emergency-access grants, as an address change left them.
    pub(crate) fn grants(&self) -> Vec<EmergencyGrant> {
        self.inner.lock().expect("the lock").grants.clone()
    }

    fn race(&self, account: UserId) {
        let mut inner = self.inner.lock().expect("the lock");
        if std::mem::take(&mut inner.interfere) {
            self.store.touch_user(account);
        }
    }
}

impl ProfileRepo for FakeProfile {
    async fn has_sso_identity(&self, user: UserId) -> Result<bool, StoreError> {
        Ok(self.inner.lock().expect("the lock").sso.contains(&user))
    }

    async fn put_email_change(&self, change: &EmailChange) -> Result<(), StoreError> {
        self.inner
            .lock()
            .expect("the lock")
            .changes
            .insert(change.user, change.clone());
        Ok(())
    }

    async fn email_change_of(&self, user: UserId) -> Result<Option<EmailChange>, StoreError> {
        Ok(self.pending(user))
    }

    async fn email_change_by_token(
        &self,
        token_hash: [u8; 32],
    ) -> Result<Option<EmailChange>, StoreError> {
        Ok(self
            .inner
            .lock()
            .expect("the lock")
            .changes
            .values()
            .find(|change| change.token_hash == token_hash)
            .cloned())
    }

    async fn set_name(&self, user: UserId, name: Option<&str>) -> Result<bool, StoreError> {
        self.race(user);
        Ok(self.store.set_user_name(user, name))
    }

    async fn remove_email_change(&self, user: UserId) -> Result<(), StoreError> {
        self.inner.lock().expect("the lock").changes.remove(&user);
        Ok(())
    }

    async fn replace_credentials(&self, before: &User, after: &User) -> Result<bool, StoreError> {
        self.race(before.id);
        if !self.store.update_credentials_if(before, after, false)? {
            return Ok(false);
        }
        self.inner
            .lock()
            .expect("the lock")
            .changes
            .remove(&before.id);
        Ok(true)
    }

    async fn apply_email_change(
        &self,
        change: &EmailChange,
        before: &User,
        after: &User,
    ) -> Result<bool, StoreError> {
        self.race(before.id);
        let pending = self.pending(change.user);
        if pending.map(|p| p.token_hash) != Some(change.token_hash) {
            return Ok(false);
        }
        if !self.store.update_credentials_if(before, after, true)? {
            return Ok(false);
        }
        let mut inner = self.inner.lock().expect("the lock");
        inner.changes.remove(&change.user);
        // The grants the account is the contact of, and the invitations still waiting at the old
        // address, follow the address, unless the grantor has a grant to the new one already.
        let moving: Vec<usize> = inner
            .grants
            .iter()
            .enumerate()
            .filter(|(_, g)| {
                g.grantee == Some(change.user)
                    || (g.grantee.is_none() && g.grantee_email == before.email)
            })
            .map(|(i, _)| i)
            .collect();
        for i in moving {
            let grantor = inner.grants[i].grantor;
            let clash = inner
                .grants
                .iter()
                .any(|g| g.grantor == grantor && g.grantee_email == after.email);
            if !clash {
                inner.grants[i].grantee_email = after.email.clone();
            }
        }
        Ok(true)
    }
}
