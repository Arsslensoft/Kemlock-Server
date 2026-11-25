//! The profile port over two maps: the accounts a single sign-on identity owns, and the pending
//! changes of sign-in address. Included by the app's and the API's tests.

use kemlock_app::ports::StoreError;
use kemlock_app::profile::ProfileRepo;
use kemlock_domain::{EmailChange, UserId};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct Inner {
    sso: HashSet<UserId>,
    changes: HashMap<UserId, EmailChange>,
}

#[derive(Clone, Default)]
pub(crate) struct FakeProfile(Arc<Mutex<Inner>>);

impl FakeProfile {
    /// Links the account to a single sign-on identity.
    pub(crate) fn link_sso(&self, user: UserId) {
        self.0.lock().expect("the lock").sso.insert(user);
    }

    /// The account's pending change, whether its link has run out or not.
    pub(crate) fn pending(&self, user: UserId) -> Option<EmailChange> {
        self.0.lock().expect("the lock").changes.get(&user).cloned()
    }
}

impl ProfileRepo for FakeProfile {
    async fn has_sso_identity(&self, user: UserId) -> Result<bool, StoreError> {
        Ok(self.0.lock().expect("the lock").sso.contains(&user))
    }

    async fn put_email_change(&self, change: &EmailChange) -> Result<(), StoreError> {
        self.0
            .lock()
            .expect("the lock")
            .changes
            .insert(change.user, change.clone());
        Ok(())
    }

    async fn email_change_of(&self, user: UserId) -> Result<Option<EmailChange>, StoreError> {
        Ok(self.pending(user))
    }

    async fn take_email_change(
        &self,
        token_hash: [u8; 32],
    ) -> Result<Option<EmailChange>, StoreError> {
        let mut inner = self.0.lock().expect("the lock");
        let owner = inner
            .changes
            .values()
            .find(|change| change.token_hash == token_hash)
            .map(|change| change.user);
        Ok(owner.and_then(|user| inner.changes.remove(&user)))
    }

    async fn remove_email_change(&self, user: UserId) -> Result<(), StoreError> {
        self.0.lock().expect("the lock").changes.remove(&user);
        Ok(())
    }
}
