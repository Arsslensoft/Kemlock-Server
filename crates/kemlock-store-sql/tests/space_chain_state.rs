//! The verified state a store keeps at a chain's head: after every append, and after an append
//! that kept nothing, it equals the state of a full replay of the stored records.

#[path = "../../kemlock-app/tests/chain_kit/mod.rs"]
mod chain_kit;
mod common;

use chain_kit::{Chain, Person, Step};
use common::memory;
use kemlock_app::spaces::{
    AppendOutcome, ChainAppend, ChainHead, SpaceChainRepo, SpaceChanges, StoredRecord,
    chain_confirmed, confirmed_of, replay_state,
};
use kemlock_crypto::space_chain::{KeyRef, Record, Role, State};
use kemlock_domain::{SpaceId, UserId};
use kemlock_store_sql::SqlStore;
use std::collections::BTreeSet;
use std::sync::Arc;
use uuid::Uuid;

const SPACE: [u8; 16] = [7; 16];

fn people() -> (Person, Person, Person) {
    (
        Person::new([1; 16], 1),
        Person::new([2; 16], 2),
        Person::new([3; 16], 3),
    )
}

/// A mix of records: the space is made, two members are invited and confirmed (one is sealed the
/// space key), and one of them is removed, which marks the space key.
fn steps() -> Vec<Step> {
    let (sam, ana, zed) = people();
    let mut chain = Chain::new(SPACE, 0);
    vec![
        chain.create(&sam, [9; 16]),
        chain.invite(&sam, ana.id, Role::Member),
        chain.confirm(&sam, &ana),
        chain.seal_space_key(&sam, &ana),
        chain.invite(&sam, zed.id, Role::Admin),
        chain.confirm(&sam, &zed),
        chain.seal_space_key(&sam, &zed),
        chain.remove(&sam, ana.id, vec![KeyRef::Space]),
    ]
}

/// Appends one step the way the use case does: the state is the one after the record, kept when
/// `keep` says so.
async fn append(
    store: &SqlStore,
    state: &mut State,
    expected: Option<ChainHead>,
    step: &Step,
    keep: bool,
) -> ChainHead {
    let applied = state
        .apply(&SPACE, &step.record)
        .expect("the record verifies");
    *state = applied.state.clone();
    let record = Record::parse(&step.record.entry).expect("a record");
    let space = SpaceId(Uuid::from_bytes(SPACE));
    let outcome = store
        .chain_append(
            space,
            ChainAppend {
                expected,
                records: vec![StoredRecord {
                    seq: record.seq,
                    link: applied.link,
                    epoch: record.epoch,
                    by: UserId(Uuid::from_bytes(record.by)),
                    at: record.at,
                    entry: step.record.entry.clone(),
                    signature: step.record.signature.clone(),
                    cosignature: step.record.cosignature.clone(),
                }],
                seals: Vec::new(),
                names: Vec::new(),
                changes: SpaceChanges::new(space),
                creating: false,
                held: Vec::new(),
                writes: Vec::new(),
                answers: None,
                state: keep.then(|| Arc::new(applied.state)),
            },
        )
        .await
        .expect("the append is stored");
    let AppendOutcome::Appended(head) = outcome else {
        panic!("the append went stale");
    };
    head
}

/// What the store answers is what a replay of the stored records gives, head included.
async fn assert_state_is_the_replay(
    store: &SqlStore,
    expected_confirmed: Option<&BTreeSet<UserId>>,
) {
    let space = SpaceId(Uuid::from_bytes(SPACE));
    let kept = store.chain_state(space).await.expect("a state");
    let replayed = replay_state(store, space).await.expect("a replay");
    let (kept_head, kept_state) = kept.expect("the chain has a state");
    let (replayed_head, replayed_state) = replayed.expect("the chain replays");
    assert_eq!(kept_head, replayed_head);
    assert_eq!(*kept_state, *replayed_state);
    let confirmed = chain_confirmed(store, space)
        .await
        .expect("confirmed")
        .expect("a chain");
    assert_eq!(confirmed, confirmed_of(&replayed_state));
    if let Some(expected) = expected_confirmed {
        assert_eq!(&confirmed, expected);
    }
}

#[tokio::test]
async fn the_kept_state_equals_a_full_replay_after_every_record() {
    let store = memory().await;
    let space = SpaceId(Uuid::from_bytes(SPACE));
    assert_eq!(store.chain_state(space).await.expect("no error"), None);

    let mut state = State::empty();
    let mut head = None;
    for step in steps() {
        head = Some(append(&store, &mut state, head, &step, true).await);
        assert_state_is_the_replay(&store, None).await;
    }
    // Sam and Zed are confirmed; Ana was removed.
    let (sam, _ana, zed) = people();
    let want: BTreeSet<UserId> = [sam.id, zed.id]
        .into_iter()
        .map(|id| UserId(Uuid::from_bytes(id)))
        .collect();
    assert_state_is_the_replay(&store, Some(&want)).await;
}

#[tokio::test]
async fn an_append_that_kept_nothing_is_replayed_and_still_equals_the_replay() {
    let store = memory().await;
    let mut state = State::empty();
    let mut head = None;
    let all = steps();
    // Kept for some records, not for others: the head's link says which kept state is current.
    for (i, step) in all.iter().enumerate() {
        head = Some(append(&store, &mut state, head, step, i % 3 != 1).await);
        assert_state_is_the_replay(&store, None).await;
    }
}
