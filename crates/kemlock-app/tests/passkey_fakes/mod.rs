//! In-memory fakes of the passkey ports: the repositories, and a scripted WebAuthn relying party
//! whose "authenticator" answers are small JSON documents. Self-contained (it depends on nothing
//! in `fakes/`), so the API tests can include it too with `#[path]`.
//!
//! The scripted relying party checks what a real one checks that matters to the use cases: the
//! answer is for the challenge the state holds, the credential is one the caller gave, and the
//! counter went up. The real ceremonies are tested in `kemlock-identity`.
#![allow(dead_code, unused_imports)]

use kemlock_app::b64url;
use kemlock_app::passkeys::{
    Assertion, ChallengeKind, ChallengeRepo, CredentialKind, NewCredential, PasskeyRepo,
    RegistrationStart, ResponseIds, Started, WebAuthn, WebAuthnError,
};
use kemlock_app::ports::StoreError;
use kemlock_domain::{Passkey, PasskeyId, PrfWrap, UserId};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use time::OffsetDateTime;

#[derive(Default)]
struct Inner {
    passkeys: Vec<Passkey>,
    challenges: HashMap<(UserId, ChallengeKind), (Vec<u8>, OffsetDateTime)>,
}

#[derive(Clone, Default)]
pub(crate) struct FakePasskeys(Arc<Mutex<Inner>>);

impl FakePasskeys {
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.0
            .lock()
            .expect("the passkey store lock isn't poisoned")
    }

    pub(crate) fn all(&self) -> Vec<Passkey> {
        self.lock().passkeys.clone()
    }

    pub(crate) fn of(&self, user: UserId) -> Vec<Passkey> {
        self.lock()
            .passkeys
            .iter()
            .filter(|p| p.user == user)
            .cloned()
            .collect()
    }

    pub(crate) fn has_challenge(&self, user: UserId, kind: ChallengeKind) -> bool {
        self.lock().challenges.contains_key(&(user, kind))
    }

    /// A passkey of `user` made directly, as if another device registered it.
    pub(crate) fn insert_for_test(&self, user: UserId, name: &str, credential_id: &[u8]) {
        self.lock().passkeys.push(Passkey {
            id: PasskeyId::random(),
            user,
            credential_id: credential_id.to_vec(),
            name: name.to_owned(),
            credential: credential_blob(credential_id, 0),
            prf_wrap: None,
            created_at: OffsetDateTime::UNIX_EPOCH,
            last_used_at: None,
        });
    }
}

impl PasskeyRepo for FakePasskeys {
    async fn passkeys_of(&self, user: UserId) -> Result<Vec<Passkey>, StoreError> {
        Ok(self.of(user))
    }

    async fn passkey_by_credential(
        &self,
        credential_id: &[u8],
    ) -> Result<Option<Passkey>, StoreError> {
        Ok(self
            .lock()
            .passkeys
            .iter()
            .find(|p| p.credential_id == credential_id)
            .cloned())
    }

    async fn insert_passkey(&self, passkey: &Passkey) -> Result<(), StoreError> {
        let mut g = self.lock();
        if g.passkeys
            .iter()
            .any(|p| p.credential_id == passkey.credential_id || p.id == passkey.id)
        {
            return Err(StoreError::Duplicate);
        }
        g.passkeys.push(passkey.clone());
        Ok(())
    }

    async fn rename_passkey(
        &self,
        user: UserId,
        id: PasskeyId,
        name: &str,
    ) -> Result<(), StoreError> {
        let mut g = self.lock();
        let found = g
            .passkeys
            .iter_mut()
            .find(|p| p.user == user && p.id == id)
            .ok_or(StoreError::NotFound)?;
        found.name = name.to_owned();
        Ok(())
    }

    async fn delete_passkey(&self, user: UserId, id: PasskeyId) -> Result<(), StoreError> {
        let mut g = self.lock();
        let before = g.passkeys.len();
        g.passkeys.retain(|p| !(p.user == user && p.id == id));
        if g.passkeys.len() == before {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    async fn record_passkey_use(
        &self,
        id: PasskeyId,
        credential: &[u8],
        at: OffsetDateTime,
    ) -> Result<(), StoreError> {
        let mut g = self.lock();
        let found = g
            .passkeys
            .iter_mut()
            .find(|p| p.id == id)
            .ok_or(StoreError::NotFound)?;
        found.credential = credential.to_vec();
        found.last_used_at = Some(at);
        Ok(())
    }

    async fn set_passkey_wrap(
        &self,
        user: UserId,
        id: PasskeyId,
        wrap: Option<&PrfWrap>,
    ) -> Result<(), StoreError> {
        let mut g = self.lock();
        let found = g
            .passkeys
            .iter_mut()
            .find(|p| p.user == user && p.id == id)
            .ok_or(StoreError::NotFound)?;
        found.prf_wrap = wrap.cloned();
        Ok(())
    }
}

impl ChallengeRepo for FakePasskeys {
    async fn put_challenge(
        &self,
        user: UserId,
        kind: ChallengeKind,
        state: &[u8],
        expires_at: OffsetDateTime,
    ) -> Result<(), StoreError> {
        self.lock()
            .challenges
            .insert((user, kind), (state.to_vec(), expires_at));
        Ok(())
    }

    async fn take_challenge(
        &self,
        user: UserId,
        kind: ChallengeKind,
        now: OffsetDateTime,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let taken = self.lock().challenges.remove(&(user, kind));
        Ok(taken.and_then(|(state, expires_at)| (expires_at > now).then_some(state)))
    }

    async fn purge_challenges(&self, before: OffsetDateTime) -> Result<u64, StoreError> {
        let mut g = self.lock();
        let count = g.challenges.len();
        g.challenges
            .retain(|_, (_, expires_at)| *expires_at >= before);
        Ok((count - g.challenges.len()) as u64)
    }
}

// ---------------------------------------------------------------------------------------------
// The scripted relying party.

/// A relying party whose challenges are counters and whose credentials are `{"id", "counter"}`.
#[derive(Clone, Default)]
pub(crate) struct ScriptedWebAuthn(Arc<Mutex<u64>>);

impl ScriptedWebAuthn {
    fn next(&self) -> u64 {
        let mut n = self.0.lock().expect("the counter lock isn't poisoned");
        *n += 1;
        *n
    }
}

/// The credential blob the scripted relying party stores.
pub(crate) fn credential_blob(id: &[u8], counter: u32) -> Vec<u8> {
    json!({"id": b64url::encode(id), "counter": counter})
        .to_string()
        .into_bytes()
}

fn read(blob: &[u8]) -> Option<(Vec<u8>, u32)> {
    let v: Value = serde_json::from_slice(blob).ok()?;
    let id = b64url::decode(v["id"].as_str()?)?;
    let counter = u32::try_from(v["counter"].as_u64()?).ok()?;
    Some((id, counter))
}

fn parse(response: &[u8]) -> Result<Value, WebAuthnError> {
    serde_json::from_slice(response).map_err(|_| WebAuthnError::Malformed("not JSON"))
}

/// What the browser would send after `create`, for the options the server made.
pub(crate) fn registration_answer(options: &Value, credential_id: &[u8]) -> Vec<u8> {
    json!({"id": b64url::encode(credential_id), "challenge": options["challenge"]})
        .to_string()
        .into_bytes()
}

/// What the browser would send after `get`.
pub(crate) fn assertion_answer(
    options: &Value,
    credential_id: &[u8],
    user_handle: Option<&[u8]>,
    counter: u32,
    user_verified: bool,
) -> Vec<u8> {
    json!({
        "id": b64url::encode(credential_id),
        "challenge": options["challenge"],
        "userHandle": user_handle.map(b64url::encode),
        "counter": counter,
        "userVerified": user_verified,
    })
    .to_string()
    .into_bytes()
}

impl WebAuthn for ScriptedWebAuthn {
    fn start_registration(
        &self,
        request: &RegistrationStart<'_>,
    ) -> Result<Started, WebAuthnError> {
        let n = self.next();
        Ok(Started {
            options: json!({
                "challenge": n.to_string(),
                "kind": format!("{:?}", request.kind),
                "user": b64url::encode(request.user_handle),
                "name": request.user_name,
                "exclude": request.exclude.len(),
            }),
            state: n.to_string().into_bytes(),
        })
    }

    fn finish_registration(
        &self,
        _kind: CredentialKind,
        state: &[u8],
        response: &[u8],
    ) -> Result<NewCredential, WebAuthnError> {
        let v = parse(response)?;
        if v["challenge"].as_str().map(str::as_bytes) != Some(state) {
            return Err(WebAuthnError::Refused("wrong challenge".to_owned()));
        }
        let id = v["id"]
            .as_str()
            .and_then(b64url::decode)
            .ok_or(WebAuthnError::Malformed("no credential id"))?;
        Ok(NewCredential {
            credential: credential_blob(&id, 0),
            credential_id: id,
        })
    }

    fn start_authentication(
        &self,
        kind: CredentialKind,
        credentials: &[&[u8]],
    ) -> Result<Started, WebAuthnError> {
        let n = self.next();
        Ok(Started {
            options: json!({
                "challenge": n.to_string(),
                "kind": format!("{kind:?}"),
                "allowCredentials": credentials.len(),
            }),
            state: n.to_string().into_bytes(),
        })
    }

    fn response_ids(&self, response: &[u8]) -> Result<ResponseIds, WebAuthnError> {
        let v = parse(response)?;
        Ok(ResponseIds {
            credential_id: v["id"]
                .as_str()
                .and_then(b64url::decode)
                .ok_or(WebAuthnError::Malformed("no credential id"))?,
            user_handle: v["userHandle"].as_str().and_then(b64url::decode),
        })
    }

    fn finish_authentication(
        &self,
        _kind: CredentialKind,
        state: &[u8],
        response: &[u8],
        credentials: &[&[u8]],
    ) -> Result<Assertion, WebAuthnError> {
        let v = parse(response)?;
        if v["challenge"].as_str().map(str::as_bytes) != Some(state) {
            return Err(WebAuthnError::Refused("wrong challenge".to_owned()));
        }
        let id = v["id"]
            .as_str()
            .and_then(b64url::decode)
            .ok_or(WebAuthnError::Malformed("no credential id"))?;
        let stored = credentials
            .iter()
            .filter_map(|blob| read(blob))
            .find(|(stored_id, _)| *stored_id == id)
            .ok_or_else(|| WebAuthnError::Refused("an unknown credential".to_owned()))?;
        let counter = u32::try_from(v["counter"].as_u64().unwrap_or(0)).unwrap_or(0);
        if counter <= stored.1 {
            return Err(WebAuthnError::Refused("the counter didn't grow".to_owned()));
        }
        Ok(Assertion {
            credential: credential_blob(&id, counter),
            credential_id: id,
            user_verified: v["userVerified"].as_bool().unwrap_or(true),
        })
    }
}
