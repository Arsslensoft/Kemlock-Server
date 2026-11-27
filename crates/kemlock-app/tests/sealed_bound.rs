//! The fallback of `open_bound` to the bare purpose, and its switch. A test binary of its own, and
//! one test, because the switch is process-wide.

mod fakes;

use fakes::FakeSeal;
use kemlock_app::ports::SecretSeal;
use kemlock_app::sealed::{
    PURPOSE_TOTP, allow_bare_secrets, bare_secrets_allowed, open_bound, seal_bound,
};
use kemlock_domain::UserId;

#[test]
fn the_bare_form_opens_only_while_the_server_allows_it() {
    let seal = FakeSeal::new();
    let user = UserId::random();
    let bare = seal.seal(PURPOSE_TOTP, b"seed");
    let bound = seal_bound(&seal, PURPOSE_TOTP, user, b"seed");

    assert!(bare_secrets_allowed(), "on until the server's pass has run");
    let old = open_bound(&seal, PURPOSE_TOTP, user, &bare).expect("opens the old way");
    assert!(old.legacy);

    allow_bare_secrets(false);
    assert!(open_bound(&seal, PURPOSE_TOTP, user, &bare).is_err());
    let new = open_bound(&seal, PURPOSE_TOTP, user, &bound).expect("opens bound");
    assert!(!new.legacy);
    assert_eq!(new.value.as_slice(), b"seed");
    // Another account's row doesn't open it either way.
    assert!(open_bound(&seal, PURPOSE_TOTP, UserId::random(), &bound).is_err());

    allow_bare_secrets(true);
    assert!(open_bound(&seal, PURPOSE_TOTP, user, &bare).is_ok());
}
