//! Kemlock Server: configuration, wiring and the HTTP server.
//!
//! `kemlock-server healthcheck` asks the running server's `/alive` and exits 0 or 1: the image's
//! `HEALTHCHECK`, so the image needs no second binary. Any other argument is refused.

use kemlock_server::healthcheck::healthy;
use kemlock_server::{Config, logging, run};
use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let healthcheck = match args.as_slice() {
        [] => false,
        [one] if one == "healthcheck" => true,
        _ => {
            eprintln!("kemlock-server: usage: kemlock-server [healthcheck]");
            return ExitCode::from(2);
        }
    };
    let config = match Config::load() {
        Ok(config) => config,
        Err(e) => {
            eprintln!("kemlock-server: {e}");
            return ExitCode::from(2);
        }
    };
    if healthcheck {
        return if healthy(config.port) {
            ExitCode::SUCCESS
        } else {
            eprintln!(
                "kemlock-server: nothing answered /alive on port {}",
                config.port
            );
            ExitCode::FAILURE
        };
    }
    logging::init(&config);
    match run(config).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "kemlock-server stopped");
            eprintln!("kemlock-server: {e}");
            ExitCode::FAILURE
        }
    }
}
