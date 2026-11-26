//! Confirm a member: the one step that puts keys in someone's hands.
//!
//! The confirmer submits the fingerprint they compared with the member's own. The server checks it
//! against the fingerprint of the member's bundle, so a key the server swapped in after the
//! comparison can't ride on it, checks the confirmer's signature over the statement that they
//! compared it (`sig1`, docs/crypto.md "Member confirmation"), and stores the statement and its
//! signature beside the member. The confirmer's client seals the space key and the keys of the
//! collections the member is granted; the server checks that nothing more and nothing less is
//! sealed.

use super::authority;
use super::error::SpacesError;
use super::ports::{BundleFingerprints, ConfirmationFacts, SpaceChanges, SpaceRepo};
use super::support::{SealedCollectionKey, key_changes, load_open, record};
use crate::authenticate::Actor;
use crate::ports::{Clock, EventLog, UserRepo};
use kemlock_domain::spaces::{
    Confirmation, KeyDelta, Member, MemberState, SpaceError, check_confirmation_parts,
    check_sealed_key,
};
use kemlock_domain::{SpaceId, UserId};

#[derive(Debug)]
pub struct ConfirmMember<R, U, F, V, C> {
    pub spaces: R,
    pub users: U,
    pub fingerprints: F,
    pub events: V,
    pub clock: C,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfirmInput {
    /// The 64-byte fingerprint the confirmer compared, as the member's app shows it.
    pub fingerprint: Vec<u8>,
    /// What the confirmer signed: that they compared this fingerprint for this member of this
    /// space, in the layout of docs/crypto.md "Member confirmation". The server checks it and its
    /// signature, and keeps them for clients to verify again.
    pub statement: Vec<u8>,
    /// The confirmer's `sig1` signature over the statement.
    pub signature: Vec<u8>,
    /// The space key, sealed to the member's exchange key.
    pub sealed_space_key: Vec<u8>,
    /// The key of every collection the member is granted, sealed to them.
    pub collection_keys: Vec<SealedCollectionKey>,
}

impl<R: SpaceRepo, U: UserRepo, F: BundleFingerprints, V: EventLog, C: Clock>
    ConfirmMember<R, U, F, V, C>
{
    /// Confirms an accepted member, or a confirmed one again: that replaces the stored confirmation
    /// and seals the keys anew, for a member whose confirmer left or lost their role, whom nobody
    /// confirmed, or whose keys changed. The confirmer's authority is judged as of now, and the
    /// same statement and signature checks apply. Only for a space with no chain (`load_open`).
    /// Refused when the fingerprint isn't the one of the member's
    /// current bundle, when the confirmer's role can't manage the member, when the confirmer is the
    /// member, when the confirmation's signature doesn't verify, or while the space awaits a key
    /// replacement.
    pub async fn execute(
        &self,
        actor: &Actor,
        space: SpaceId,
        member: UserId,
        input: ConfirmInput,
    ) -> Result<Member, SpacesError> {
        check_confirmation_parts(&input.statement, &input.signature)?;
        check_sealed_key(&input.sealed_space_key)?;
        let state = load_open(&self.spaces, space).await?;
        let user = self
            .users
            .by_id(member)
            .await?
            .ok_or(SpacesError::NotFound)?;
        let actual = self
            .fingerprints
            .fingerprint(&user.public_bundle)
            .ok_or(SpaceError::Invalid("the member's key bundle can't be read"))?;
        let target = state.authorize_confirm(actor.user, member, &input.fingerprint, &actual)?;
        authority::ensure_manage(&state, actor.user, member)?;

        // The confirmer signed that they compared this fingerprint for this member of this space,
        // with their own key: the statement is rebuilt from what the server holds, so one that says
        // anything else (another member, another key version) doesn't pass.
        let confirmer = self
            .users
            .by_id(actor.user)
            .await?
            .ok_or(SpacesError::NotFound)?;
        let facts = ConfirmationFacts {
            space,
            member,
            member_key_version: user.key_version,
            fingerprint: &input.fingerprint,
            confirmer: actor.user,
        };
        if !self.fingerprints.verify_confirmation(
            &confirmer.public_bundle,
            &facts,
            &input.statement,
            &input.signature,
        ) {
            return Err(SpaceError::Invalid(
                "the confirmation isn't the confirmer's signature over this member's fingerprint",
            )
            .into());
        }

        // The keys this member needs: every collection they are granted.
        let needed = state
            .collections_of(member)
            .into_iter()
            .map(|collection| (collection, member))
            .collect();
        let delta = KeyDelta {
            needed,
            ..KeyDelta::default()
        };
        let now = self.clock.now();
        let keys = key_changes(&state, &delta, input.collection_keys, now)?;

        let mut confirmed = target.clone();
        confirmed.state = MemberState::Confirmed;
        confirmed.sealed_space_key = Some(input.sealed_space_key);
        confirmed.sealed_by = None;
        confirmed.key_version = Some(state.space.key_version);
        confirmed.confirmation = Some(Confirmation {
            by: actor.user,
            at: now,
            fingerprint: input.fingerprint,
            member_key_version: user.key_version,
            statement: input.statement,
            signature: input.signature,
        });
        self.spaces
            .apply(SpaceChanges {
                members: vec![confirmed.clone()],
                key_copies: keys.key_copies,
                ..SpaceChanges::new(space)
            })
            .await?;
        record(
            &self.events,
            actor,
            "space.member.confirm",
            format!("{space}/{member}"),
            now,
        )
        .await;
        Ok(confirmed)
    }
}
