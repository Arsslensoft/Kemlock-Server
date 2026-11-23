//! `signin`: the OPAQUE sign-in driver. It starts sign-ins at a fixed rate (the standard load's
//! 10% is 2 a second of 20), each from a new device with a new DPoP key, and reports the time
//! the server took for both messages. The client's OPAQUE work runs between the two requests,
//! outside both clocks; the real client's Argon2id never runs here at all.

use crate::accounts::AccountsFile;
use crate::device::{Device, Result, Target};
use crate::stats::{Summary, summarize};
use serde::Serialize;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio::time::{Instant, MissedTickBehavior, interval};

#[derive(clap::Args, Debug)]
pub(crate) struct Args {
    /// The accounts file `seed` wrote.
    #[arg(long, default_value = "loadgen-accounts.json")]
    pub(crate) accounts: PathBuf,
    /// Sign-ins started per second.
    #[arg(long, default_value_t = 2.0)]
    pub(crate) rate: f64,
    /// How long to keep starting them, in seconds.
    #[arg(long, default_value_t = 600)]
    pub(crate) duration_secs: u64,
    /// Write the summary here as JSON, as well as printing it.
    #[arg(long)]
    pub(crate) out: Option<PathBuf>,
    /// Exit with an error when the p95 is over this many milliseconds.
    #[arg(long)]
    pub(crate) max_p95_ms: Option<f64>,
}

#[derive(Debug)]
enum Outcome {
    Took(Duration),
    Limited,
    Failed(String),
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Report {
    sign_in: Summary,
}

pub(crate) async fn run(target: Target, args: Args) -> Result<()> {
    if !(args.rate.is_finite() && args.rate > 0.0) {
        return Err("--rate must be a positive number".into());
    }
    let file = AccountsFile::load(&args.accounts)?;
    if file.accounts.is_empty() {
        return Err("the accounts file has no accounts".into());
    }
    let emails: Arc<Vec<String>> =
        Arc::new(file.accounts.iter().map(|a| a.email.clone()).collect());
    let http = reqwest::Client::new();
    let (sender, mut receiver) = mpsc::unbounded_channel::<Outcome>();

    let mut ticker = interval(Duration::from_secs_f64(1.0 / args.rate));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Burst);
    let end = Instant::now() + Duration::from_secs(args.duration_secs);
    let mut tasks = JoinSet::new();
    let mut started: usize = 0;
    while Instant::now() < end {
        ticker.tick().await;
        let email = emails[started % emails.len()].clone();
        // A new address for each attempt, so the per-address limit sees each as a new client.
        let seed = u32::try_from(1_000_000 + started).unwrap_or(u32::MAX);
        let device = Device::new(http.clone(), target.clone(), seed);
        let sender = sender.clone();
        tasks.spawn(async move {
            let outcome = match device.sign_in(&email).await {
                Ok((_tokens, took)) => Outcome::Took(took),
                Err(e) if e.to_string().contains("HTTP 429") => Outcome::Limited,
                Err(e) => Outcome::Failed(e.to_string()),
            };
            // The receiver outlives every task, so a send only fails on shutdown.
            let _ = sender.send(outcome);
        });
        started += 1;
    }
    drop(sender);
    while tasks.join_next().await.is_some() {}

    let (mut samples, mut errors, mut limited) = (Vec::new(), 0u64, 0u64);
    let mut first_errors: Vec<String> = Vec::new();
    while let Some(outcome) = receiver.recv().await {
        match outcome {
            Outcome::Took(took) => samples.push(took),
            Outcome::Limited => limited += 1,
            Outcome::Failed(message) => {
                errors += 1;
                if first_errors.len() < 3 && !first_errors.contains(&message) {
                    first_errors.push(message);
                }
            }
        }
    }
    let sign_in = summarize(samples, errors, limited);
    for message in &first_errors {
        eprintln!("sign-in failed: {message}");
    }
    let json = serde_json::to_string_pretty(&Report {
        sign_in: sign_in.clone(),
    })?;
    println!("{json}");
    if let Some(path) = &args.out {
        std::fs::write(path, &json).map_err(|e| format!("can't write {}: {e}", path.display()))?;
    }
    if sign_in.count == 0 {
        return Err("no sign-in succeeded".into());
    }
    if let Some(limit) = args.max_p95_ms
        && sign_in.p95_ms > limit
    {
        return Err(format!("sign-in p95 {:.1} ms is over {limit} ms", sign_in.p95_ms).into());
    }
    Ok(())
}
