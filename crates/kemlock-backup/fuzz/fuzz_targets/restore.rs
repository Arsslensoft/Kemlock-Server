//! A restore reads an archive an operator brings: an age file, then zstd, then tar. The first
//! byte picks how far the input is trusted. 0: the whole archive is the input, so the age header
//! is what is fuzzed. 1: a valid age file around any zstd stream. 2: a valid age file around
//! zstd-compressed bytes, so the tar reader and the path checks are reached. Whatever the
//! archive holds, nothing is written outside the restore folder.

#![no_main]

use age::x25519::Identity;
use kemlock_backup::read_archive;
use libfuzzer_sys::fuzz_target;
use std::io::Write;
use std::sync::OnceLock;

fn identity() -> &'static Identity {
    static IDENTITY: OnceLock<Identity> = OnceLock::new();
    IDENTITY.get_or_init(Identity::generate)
}

/// `payload` as an age file for the fuzzer's own identity.
fn seal(payload: &[u8]) -> Vec<u8> {
    let recipient = identity().to_public();
    let encryptor =
        age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
            .expect("one recipient");
    let mut out = Vec::new();
    let mut writer = encryptor.wrap_output(&mut out).expect("the header");
    writer.write_all(payload).expect("the body");
    writer.finish().expect("the last chunk");
    out
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let bytes = match mode % 3 {
        0 => rest.to_vec(),
        1 => seal(rest),
        _ => seal(&zstd::encode_all(rest, 1).expect("zstd compresses")),
    };

    let work = tempfile::tempdir().expect("a temp dir");
    let archive = work.path().join("archive.tar.zst.age");
    std::fs::write(&archive, bytes).expect("the archive is written");
    let restore = work.path().join("restore");
    std::fs::create_dir(&restore).expect("the restore folder");

    let _ = read_archive(&archive, identity(), &restore);

    let mut beside: Vec<_> = std::fs::read_dir(work.path())
        .expect("the work folder")
        .map(|entry| entry.expect("an entry").file_name())
        .collect();
    beside.sort();
    assert_eq!(
        beside,
        ["archive.tar.zst.age", "restore"],
        "a restore wrote outside its folder"
    );
});
