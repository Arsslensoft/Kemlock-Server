//! Make a Send and change one.
//!
//! Both check the owner's space policies first: "Remove Send" refuses making or changing a Send,
//! and "Always show the sender's email" refuses one that hides it.

use super::ports::{SendPolicies, SendRepo, SendRules, file_send_bytes};
use super::{SendsConfig, SendsError, new_password, own_send, record};
use crate::authenticate::Actor;
use crate::platform::Platform;
use crate::ports::EventLog;
use crate::quota::check;
use kemlock_domain::BlobId;
use kemlock_domain::sends::{NewSend, PasswordChange, SendId, SendOptions, SendRecord};

/// Refuses what the owner's policies forbid.
fn check_rules(rules: SendRules, hide_email: bool) -> Result<(), SendsError> {
    if rules.disabled {
        return Err(SendsError::Policy(
            "a policy of one of your spaces allows you only to delete an existing Send",
        ));
    }
    if rules.force_email && hide_email {
        return Err(SendsError::Policy(
            "a policy of one of your spaces requires Sends to show your email",
        ));
    }
    Ok(())
}

#[derive(Debug)]
pub struct CreateSend<S, Q, V, E> {
    pub sends: S,
    pub policies: Q,
    pub events: V,
    pub env: E,
    pub config: SendsConfig,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateSendInput {
    pub send: NewSend,
    /// The value the client derived from the password, when the Send has one.
    pub password_proof: Option<Vec<u8>>,
}

impl<S: SendRepo, Q: SendPolicies, V: EventLog, E: Platform> CreateSend<S, Q, V, E> {
    /// Makes the Send. A file Send is made without its bytes and stays closed until
    /// [`UploadSendFile`](super::UploadSendFile) lands them. `Duplicate` when the id is taken.
    pub async fn execute(
        &self,
        actor: &Actor,
        input: CreateSendInput,
    ) -> Result<SendRecord, SendsError> {
        check_rules(
            self.policies.send_rules(actor.user).await?,
            input.send.options.hide_email,
        )?;
        let password = input
            .password_proof
            .as_deref()
            .map(|proof| new_password(&self.env, proof))
            .transpose()?;
        if let Some((size, _)) = input.send.file {
            // What the account's file Sends hold already, in the bytes each announced.
            let used = if self.config.quota.is_some() {
                file_send_bytes(&self.sends.sends_of(actor.user).await?)
            } else {
                0
            };
            check(self.config.quota, used, size).map_err(SendsError::Quota)?;
        }
        let now = self.env.now();
        let blob = input
            .send
            .file
            .is_some()
            .then(|| BlobId::from_bytes(self.env.bytes::<16>()));
        let send = SendRecord::create(
            input.send,
            actor.user,
            password,
            blob,
            self.config.limits,
            now,
        )?;
        // The check above refuses early. This one is the one that holds: the sum and the insert
        // are one step, so Sends made together can't all pass it.
        // The sealed key begins with the key version it was made for (docs/crypto.md, "Sends"): the
        // store refuses it under the owner's lock when the account has replaced its keys since.
        let key_version = send
            .sealed_key
            .first_chunk::<4>()
            .map(|prefix| u32::from_be_bytes(*prefix));
        self.sends
            .add_send_within_quota_at(&send, self.config.quota, key_version)
            .await?
            .map_err(SendsError::Quota)?;
        record(&self.events, actor, "send.create", send.id, now).await;
        Ok(send)
    }
}

#[derive(Debug)]
pub struct UpdateSend<S, Q, V, E> {
    pub sends: S,
    pub policies: Q,
    pub events: V,
    pub env: E,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateSendInput {
    pub meta: Vec<u8>,
    /// New content, for a note.
    pub payload: Option<Vec<u8>>,
    pub options: SendOptions,
    /// `None` keeps the password, `Some(None)` removes it, `Some(Some(proof))` sets it.
    pub password_proof: Option<Option<Vec<u8>>>,
}

impl<S: SendRepo, Q: SendPolicies, V: EventLog, E: Platform> UpdateSend<S, Q, V, E> {
    /// Applies the owner's change. The Send's key, file and view count never change.
    pub async fn execute(
        &self,
        actor: &Actor,
        id: SendId,
        input: UpdateSendInput,
    ) -> Result<SendRecord, SendsError> {
        self.execute_at(actor, id, input, None).await
    }

    /// [`execute`](UpdateSend::execute) for a change whose sealed parts the client made for
    /// `key_version`: the store refuses it when the account has replaced its keys since. A client
    /// that doesn't say passes `None`, and nothing is checked.
    pub async fn execute_at(
        &self,
        actor: &Actor,
        id: SendId,
        input: UpdateSendInput,
        key_version: Option<u32>,
    ) -> Result<SendRecord, SendsError> {
        let mut send = own_send(&self.sends, actor, id).await?;
        check_rules(
            self.policies.send_rules(actor.user).await?,
            input.options.hide_email,
        )?;
        let password = match input.password_proof {
            None => PasswordChange::Keep,
            Some(None) => PasswordChange::Remove,
            Some(Some(proof)) => PasswordChange::Set(new_password(&self.env, &proof)?),
        };
        let now = self.env.now();
        send.revise(input.meta, input.payload, input.options, password, now)?;
        self.sends.update_send_at(&send, key_version).await?;
        record(&self.events, actor, "send.update", send.id, now).await;
        Ok(send)
    }
}
