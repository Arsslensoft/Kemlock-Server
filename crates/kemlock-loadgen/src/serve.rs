//! `serve`: a small local service that holds one signed-in device per seeded account and makes
//! the DPoP proofs k6 can't. k6 asks `POST /proof` for each request it sends to the server and
//! puts the two headers it gets back on that request; the server sees ordinary DPoP traffic, and
//! only the request to the server is timed.
//!
//! Each account is signed in again when this starts, with a new device and key, so a rerun
//! needs no state from the last one but the accounts file. Access tokens live 10 minutes by
//! default; a background task refreshes each at 60% of its life, so runs can be any length.

use crate::accounts::AccountsFile;
use crate::device::{Device, Result, Target, Tokens, remember_nonce};
use crate::proxy::{ProxyState, router as proxy_router};
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{RwLock, Semaphore};
use tokio::task::JoinSet;
use tokio::time::Instant;

#[derive(clap::Args, Debug)]
pub(crate) struct Args {
    /// The accounts file `seed` wrote.
    #[arg(long, default_value = "loadgen-accounts.json")]
    pub(crate) accounts: PathBuf,
    /// Where to listen. Keep it on loopback: it hands out working tokens.
    #[arg(long, default_value = "127.0.0.1:9099")]
    pub(crate) listen: String,
    /// Sign-ins in flight at start.
    #[arg(long, default_value_t = 8)]
    pub(crate) concurrency: usize,
    /// Also listen here as a signing reverse proxy for oha, which can't make DPoP proofs. Every
    /// request goes to the server as one account, with a new proof.
    #[arg(long)]
    pub(crate) proxy_listen: Option<String>,
    /// The account the proxy acts as.
    #[arg(long, default_value_t = 0)]
    pub(crate) proxy_account: usize,
}

#[derive(Debug)]
pub(crate) struct Session {
    pub(crate) tokens: Tokens,
    pub(crate) obtained: Instant,
}

impl Session {
    /// Whether 60% of the access token's life has passed.
    fn due(&self) -> bool {
        self.obtained.elapsed() >= Duration::from_secs(self.tokens.expires_in * 6 / 10)
    }
}

#[derive(Debug)]
pub(crate) struct Served {
    pub(crate) devices: Vec<Device>,
    pub(crate) sessions: Vec<RwLock<Session>>,
}

#[derive(Debug, Deserialize)]
struct ProofRequest {
    /// The account's index in the accounts file.
    account: usize,
    method: String,
    /// The request path without its query.
    path: String,
    /// The `DPoP-Nonce` k6 last saw, if it has one newer than ours.
    #[serde(default)]
    nonce: Option<String>,
}

#[derive(Debug, Serialize)]
struct ProofReply {
    /// The value for the `Authorization` header.
    authorization: String,
    /// The value for the `DPoP` header.
    dpop: String,
}

async fn proof(
    State(served): State<Arc<Served>>,
    Json(request): Json<ProofRequest>,
) -> std::result::Result<Json<ProofReply>, (StatusCode, String)> {
    let (Some(session), Some(device)) = (
        served.sessions.get(request.account),
        served.devices.get(request.account),
    ) else {
        return Err((StatusCode::NOT_FOUND, "no such account".to_owned()));
    };
    let token = session.read().await.tokens.access_token.clone();
    if let Some(nonce) = &request.nonce {
        remember_nonce(nonce);
    }
    Ok(Json(ProofReply {
        authorization: format!("DPoP {token}"),
        dpop: device.proof(&request.method, &request.path, Some(&token)),
    }))
}

/// Refreshes every session that is past 60% of its life, forever.
async fn keep_fresh(served: Arc<Served>) {
    loop {
        tokio::time::sleep(Duration::from_secs(10)).await;
        for (device, slot) in served.devices.iter().zip(&served.sessions) {
            let refresh_token = {
                let session = slot.read().await;
                if !session.due() {
                    continue;
                }
                session.tokens.refresh_token.clone()
            };
            match device.refresh(&refresh_token).await {
                Ok(tokens) => {
                    *slot.write().await = Session {
                        tokens,
                        obtained: Instant::now(),
                    };
                }
                Err(e) => eprintln!("refresh failed: {e}"),
            }
        }
    }
}

pub(crate) async fn run(target: Target, args: Args) -> Result<()> {
    let file = AccountsFile::load(&args.accounts)?;
    if file.accounts.is_empty() || args.concurrency == 0 {
        return Err("need at least one account and --concurrency 1".into());
    }
    let http = reqwest::Client::new();
    let semaphore = Arc::new(Semaphore::new(args.concurrency));
    let mut tasks = JoinSet::new();
    for account in &file.accounts {
        let permit = Arc::clone(&semaphore).acquire_owned().await?;
        let device = Device::new(
            http.clone(),
            target.clone(),
            u32::try_from(account.index).unwrap_or(u32::MAX),
        );
        let (index, email) = (account.index, account.email.clone());
        tasks.spawn(async move {
            let signed_in = device.sign_in(&email).await;
            drop(permit);
            signed_in.map(|(tokens, _took)| (index, device, tokens))
        });
    }
    let mut ready = Vec::with_capacity(file.accounts.len());
    while let Some(joined) = tasks.join_next().await {
        ready.push(joined??);
    }
    ready.sort_by_key(|(index, _, _)| *index);
    if ready
        .iter()
        .enumerate()
        .any(|(slot, (index, _, _))| slot != *index)
    {
        return Err("the accounts file's indexes must be 0, 1, 2, ... in order".into());
    }
    let (mut devices, mut sessions) = (Vec::new(), Vec::new());
    for (_index, device, tokens) in ready {
        devices.push(device);
        sessions.push(RwLock::new(Session {
            tokens,
            obtained: Instant::now(),
        }));
    }
    let served = Arc::new(Served { devices, sessions });
    tokio::spawn(keep_fresh(Arc::clone(&served)));
    if let Some(listen) = &args.proxy_listen {
        if args.proxy_account >= served.devices.len() {
            return Err("--proxy-account is not in the accounts file".into());
        }
        let state = Arc::new(ProxyState {
            served: Arc::clone(&served),
            account: args.proxy_account,
            http: http.clone(),
            base_url: target.base_url.clone(),
        });
        let proxy_listener = tokio::net::TcpListener::bind(listen).await?;
        println!(
            "kemlock-loadgen: signing proxy for account {} on http://{}",
            args.proxy_account,
            proxy_listener.local_addr()?
        );
        tokio::spawn(async move {
            if let Err(e) = axum::serve(proxy_listener, proxy_router(state)).await {
                eprintln!("proxy stopped: {e}");
            }
        });
    }

    let app = Router::new()
        .route("/proof", post(proof))
        .route("/health", get(|| async { "ok" }))
        .with_state(Arc::clone(&served));
    let listener = tokio::net::TcpListener::bind(&args.listen).await?;
    println!(
        "kemlock-loadgen: {} accounts signed in; proofs on http://{}/proof",
        served.devices.len(),
        listener.local_addr()?
    );
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(expires_in: u64, age: Duration) -> Session {
        Session {
            tokens: Tokens {
                access_token: "a".to_owned(),
                refresh_token: "r".to_owned(),
                user_id: "u".to_owned(),
                expires_in,
            },
            obtained: Instant::now() - age,
        }
    }

    #[test]
    fn a_session_is_due_at_sixty_percent_of_its_life() {
        assert!(!session(600, Duration::from_secs(300)).due());
        assert!(session(600, Duration::from_secs(361)).due());
    }
}
