//! What a spaces use case fails with, and how it reads as the `AppError` the item routes return.

use kemlock_app::AppError;
use kemlock_app::ports::StoreError;
use kemlock_app::spaces::SpacesError;
use kemlock_domain::spaces::SpaceError;
use kemlock_domain::{ItemError, ItemId, Revision};

#[test]
fn store_errors_keep_their_meaning() {
    let item = ItemId::random();
    assert_eq!(
        SpacesError::from(StoreError::Conflict {
            item,
            current: Some(Revision(3))
        }),
        SpacesError::StaleItem {
            item,
            current: Some(Revision(3))
        }
    );
    assert_eq!(
        SpacesError::from(StoreError::Duplicate),
        SpacesError::Duplicate
    );
    assert_eq!(
        SpacesError::from(StoreError::NotFound),
        SpacesError::NotFound
    );
    assert_eq!(
        SpacesError::from(StoreError::Backend("x".to_owned())),
        SpacesError::Store("x".to_owned())
    );
}

#[test]
fn a_stale_item_write_names_the_item() {
    let item = ItemId::random();
    let stale = ItemError::Stale {
        expected: Some(Revision(1)),
        current: Some(Revision(2)),
    };
    assert_eq!(
        SpacesError::from_item(item, stale),
        SpacesError::StaleItem {
            item,
            current: Some(Revision(2))
        }
    );
    assert_eq!(
        SpacesError::from_item(item, ItemError::Immutable),
        SpacesError::Item(ItemError::Immutable)
    );
}

#[test]
fn as_app_errors_a_space_stays_hidden_from_outsiders() {
    assert_eq!(
        AppError::from(SpacesError::Rule(SpaceError::NotAMember)),
        AppError::NotFound
    );
    assert_eq!(AppError::from(SpacesError::NotFound), AppError::NotFound);
    assert_eq!(
        AppError::from(SpacesError::Rule(SpaceError::Forbidden("no"))),
        AppError::Forbidden
    );
    assert_eq!(
        AppError::from(SpacesError::Rule(SpaceError::State("not yet"))),
        AppError::Invalid("not yet")
    );
    for paused in [
        SpaceError::KeysPending,
        SpaceError::StaleKeyVersion { current: 2 },
        SpaceError::FingerprintMismatch,
        SpaceError::LastOwner,
    ] {
        assert!(matches!(
            AppError::from(SpacesError::Rule(paused)),
            AppError::Invalid(_)
        ));
    }
    let item = ItemId::random();
    assert_eq!(
        AppError::from(SpacesError::StaleItem {
            item,
            current: None
        }),
        AppError::Conflict {
            item,
            current: None
        }
    );
    assert_eq!(
        AppError::from(SpacesError::Item(ItemError::Malformed)),
        AppError::Item(ItemError::Malformed)
    );
    assert_eq!(AppError::from(SpacesError::Duplicate), AppError::Duplicate);
}
