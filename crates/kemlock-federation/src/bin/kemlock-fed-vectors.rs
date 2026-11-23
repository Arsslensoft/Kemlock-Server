//! Regenerates `test-vectors/federation-*.json` from fixed seeds.
//!
//! ```text
//! cargo run -p kemlock-federation --features vectors --bin kemlock-fed-vectors -- --out test-vectors
//! ```
//!
//! The output is byte for byte the same on every run; CI regenerates it and fails on a difference.

use std::{env, path::PathBuf, process::ExitCode};

const USAGE: &str = "usage: kemlock-fed-vectors [--out <dir>]\n\
    Writes every federation test-vector file and federation-SHA256SUMS into <dir> (default: test-vectors).";

fn main() -> ExitCode {
    let mut out = PathBuf::from("test-vectors");
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--out" => match args.next() {
                Some(dir) => out = PathBuf::from(dir),
                None => {
                    eprintln!("--out needs a directory\n{USAGE}");
                    return ExitCode::from(2);
                }
            },
            "--help" | "-h" => {
                println!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("unknown argument {other}\n{USAGE}");
                return ExitCode::from(2);
            }
        }
    }
    match kemlock_federation::vectors::write_all(&out) {
        Ok(()) => {
            println!("wrote the federation test vectors to {}", out.display());
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}
