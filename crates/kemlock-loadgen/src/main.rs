//! kemlock-loadgen: the parts of the performance harness (`perf/`) that k6 can't do.
//!
//! - `seed`: makes the standard load's accounts and items and writes an accounts file;
//! - `signin`: drives OPAQUE sign-ins at a fixed rate and reports the server's time for both
//!   messages (the design's "Rust sign-in driver");
//! - `serve`: holds a signed-in device per account and makes DPoP proofs for k6 over a local
//!   port, so k6's syncs, puts and WebSockets are ordinary authenticated traffic.
//!
//! It talks plain HTTP to the server directly, never through a proxy, as the design's rigs do.

mod accounts;
mod device;
mod proxy;
mod seed;
mod serve;
mod signin;
mod stats;

use clap::{Args, Parser, Subcommand};
use device::Target;
use std::process::ExitCode;

#[derive(Debug, Parser)]
#[command(name = "kemlock-loadgen", version, about)]
struct Cli {
    #[command(flatten)]
    target: TargetArgs,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Args)]
struct TargetArgs {
    /// Where the server listens.
    #[arg(long, global = true, default_value = "http://127.0.0.1:8080")]
    base_url: String,
    /// The server's DOMAIN, which DPoP proofs must name. Defaults to --base-url.
    #[arg(long, global = true)]
    domain: Option<String>,
    /// A header to send a made-up client address in, such as X-Forwarded-For. Set the server's
    /// IP_HEADER to the same name and KEMLOCK_TRUSTED_PROXIES to this machine's address, or the
    /// per-address sign-in and registration limits will refuse the load.
    #[arg(long, global = true)]
    ip_header: Option<String>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Register accounts, write their items and record each sync cursor.
    Seed(seed::Args),
    /// Drive OPAQUE sign-ins at a fixed rate and report latency.
    Signin(signin::Args),
    /// Serve DPoP proofs and tokens for k6 on a local port.
    Serve(serve::Args),
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let target = Target::new(
        &cli.target.base_url,
        cli.target.domain.as_deref(),
        cli.target.ip_header.as_deref(),
    );
    let result = match cli.command {
        Command::Seed(args) => seed::run(target, args).await,
        Command::Signin(args) => signin::run(target, args).await,
        Command::Serve(args) => serve::run(target, args).await,
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("kemlock-loadgen: {e}");
            ExitCode::FAILURE
        }
    }
}
