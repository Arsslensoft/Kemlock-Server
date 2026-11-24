//! The Recovery Kit: its pieces, the Shamir split and the root key's wrap.

use kemlock_crypto::keys::RootKey;
use kemlock_crypto::recovery_kit::{
    KIT_KEY_LEN, KitPiece, PieceProblem, WRAPPED_LEN, display_piece, is_kit_id, make_kit, open,
    parse_piece, piece_text, rebuild_key, seal,
};

fn parsed(pieces: &[String]) -> Vec<KitPiece> {
    pieces
        .iter()
        .map(|p| parse_piece(p).expect("a piece"))
        .collect()
}

#[test]
fn any_two_of_three_pieces_rebuild_the_key() {
    let (id, key, pieces) = make_kit(2, 3).expect("a kit");
    assert!(is_kit_id(&id));
    let all = parsed(&pieces);
    for (a, b) in [(0, 1), (0, 2), (1, 2), (2, 0)] {
        let rebuilt = rebuild_key(&[all[a].clone(), all[b].clone()]).expect("a key");
        assert_eq!(*rebuilt, *key, "pieces {a} and {b}");
    }
    let rebuilt = rebuild_key(&all).expect("three pieces");
    assert_eq!(*rebuilt, *key);
}

#[test]
fn one_piece_is_not_enough_and_gives_no_key() {
    let (_, _, pieces) = make_kit(2, 3).expect("a kit");
    let all = parsed(&pieces);
    assert_eq!(rebuild_key(&all[..1]).unwrap_err(), PieceProblem::NotEnough);
    assert_eq!(rebuild_key(&[]).unwrap_err(), PieceProblem::NotEnough);
}

#[test]
fn pieces_of_two_kits_or_the_same_piece_twice_are_refused() {
    let (_, _, one) = make_kit(2, 3).expect("a kit");
    let (_, _, two) = make_kit(2, 3).expect("another kit");
    let (one, two) = (parsed(&one), parsed(&two));
    assert_eq!(
        rebuild_key(&[one[0].clone(), two[1].clone()]).unwrap_err(),
        PieceProblem::OtherKit
    );
    assert_eq!(
        rebuild_key(&[one[0].clone(), one[0].clone()]).unwrap_err(),
        PieceProblem::Duplicate
    );
}

#[test]
fn a_piece_has_the_apps_text_shape() {
    let (id, _, pieces) = make_kit(2, 3).expect("a kit");
    for (n, text) in pieces.iter().enumerate() {
        let parts: Vec<&str> = text.split('-').collect();
        assert_eq!(parts.len(), 5);
        assert_eq!(parts[0], "BMCKIT1");
        assert_eq!(parts[1], id);
        assert_eq!(parts[2], format!("23{}", n + 1));
        assert_eq!(parts[3].len(), 52);
        assert_eq!(parts[4].len(), 4);
    }
}

#[test]
fn a_piece_reads_in_any_case_with_or_without_spaces() {
    let (_, _, pieces) = make_kit(2, 3).expect("a kit");
    let plain = parse_piece(&pieces[0]).expect("a piece");
    assert_eq!(
        parse_piece(&pieces[0].to_lowercase()).expect("lower"),
        plain
    );
    assert_eq!(
        parse_piece(&display_piece(&pieces[0])).expect("grouped"),
        plain
    );
    assert_eq!(piece_text(&plain), pieces[0]);
}

#[test]
fn a_mistyped_piece_fails_its_check() {
    let (_, _, pieces) = make_kit(2, 3).expect("a kit");
    let mut chars: Vec<char> = pieces[0].chars().collect();
    // The first character of the share, after "BMCKIT1-XXXXXXXX-231-".
    let at = 21;
    chars[at] = if chars[at] == 'A' { 'B' } else { 'A' };
    let typo: String = chars.into_iter().collect();
    assert_eq!(parse_piece(&typo).unwrap_err(), PieceProblem::Checksum);
}

#[test]
fn text_that_is_not_a_piece_is_a_format_problem() {
    for text in [
        "",
        "hello",
        "BMCKIT2-AAAAAAAA-231-AAAA-AAAA",
        "BMCKIT1-AAAAAAAA-231-TOOSHORT-AAAA",
        "BMCKIT1-AAAAAAA1-231-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-AAAA",
    ] {
        assert_eq!(
            parse_piece(text).unwrap_err(),
            PieceProblem::Format,
            "{text:?}"
        );
    }
}

#[test]
fn the_kit_limits_are_enforced() {
    assert!(make_kit(0, 3).is_err());
    assert!(make_kit(4, 3).is_err());
    assert!(make_kit(2, 10).is_err());
    let (_, key, pieces) = make_kit(1, 1).expect("one piece is enough");
    assert_eq!(*rebuild_key(&parsed(&pieces)).expect("a key"), *key);
}

#[test]
fn the_root_key_round_trips_through_the_wrap() {
    let (id, key, _) = make_kit(2, 3).expect("a kit");
    let root = RootKey::generate();
    let account = [3u8; 16];
    let wrapped = seal(&key, &id, &root, &account, 2).expect("a wrap");
    assert_eq!(wrapped.len(), WRAPPED_LEN);
    let opened = open(&key, &id, &wrapped, &account, 2).expect("opens");
    assert_eq!(opened.as_bytes(), root.as_bytes());
}

#[test]
fn the_wrap_opens_for_nothing_else() {
    let (id, key, _) = make_kit(2, 3).expect("a kit");
    let root = RootKey::generate();
    let account = [3u8; 16];
    let wrapped = seal(&key, &id, &root, &account, 2).expect("a wrap");
    let other_key = [9u8; KIT_KEY_LEN];
    assert!(
        open(&other_key, &id, &wrapped, &account, 2).is_err(),
        "another key"
    );
    assert!(
        open(&key, "AAAAAAAA", &wrapped, &account, 2).is_err(),
        "another kit"
    );
    assert!(
        open(&key, &id, &wrapped, &[4u8; 16], 2).is_err(),
        "another account"
    );
    assert!(
        open(&key, &id, &wrapped, &account, 3).is_err(),
        "another key version"
    );
    let mut altered = wrapped.clone();
    altered[20] ^= 1;
    assert!(
        open(&key, &id, &altered, &account, 2).is_err(),
        "an altered byte"
    );
    assert!(
        open(&key, &id, &wrapped[1..], &account, 2).is_err(),
        "a short wrap"
    );
}

#[test]
fn a_pieces_share_is_held_in_wiped_memory_and_still_rebuilds_the_key() {
    let (_, key, pieces) = make_kit(2, 3).expect("a kit");
    let all = parsed(&pieces);
    // The share is zeroizing: it is wiped when the piece is dropped.
    let share: &zeroize::Zeroizing<[u8; KIT_KEY_LEN]> = &all[0].y;
    assert_ne!(**share, [0u8; KIT_KEY_LEN]);
    let rebuilt = rebuild_key(&all[1..]).expect("two pieces");
    assert_eq!(*rebuilt, *key);
}
