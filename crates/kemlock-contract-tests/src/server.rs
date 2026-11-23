//! The server under test: `kemlock-server` started in this process, or any server at
//! `KEMLOCK_CONTRACT_URL`.

use kemlock_server::Config;
use std::net::SocketAddr;
use std::sync::OnceLock;
use std::sync::mpsc::{Sender, channel};
use std::time::Duration;

/// Where the tests send their requests.
#[derive(Debug, Clone)]
pub struct Target {
    /// The address, without a trailing slash: `http://localhost:41234`. The server's `DOMAIN` is
    /// the same address, which the attachment URLs and the security-key origin rely on.
    pub base: String,
    /// Whether this process started the server.
    pub in_process: bool,
    /// Whether the server is a real Vaultwarden (`KEMLOCK_CONTRACT_VAULTWARDEN=1`).
    pub vaultwarden: bool,
}

/// The server under test, started on first use and kept for the life of the test process.
pub fn target() -> &'static Target {
    static TARGET: OnceLock<Target> = OnceLock::new();
    TARGET.get_or_init(start)
}

fn flag(name: &str) -> bool {
    matches!(
        std::env::var(name).ok().as_deref().map(str::trim),
        Some("1" | "true" | "yes" | "on")
    )
}

fn start() -> Target {
    let vaultwarden = flag("KEMLOCK_CONTRACT_VAULTWARDEN");
    match std::env::var("KEMLOCK_CONTRACT_URL") {
        Ok(url) if !url.trim().is_empty() => Target {
            base: url.trim().trim_end_matches('/').to_owned(),
            in_process: false,
            vaultwarden,
        },
        _ => Target {
            base: boot_in_process(),
            in_process: true,
            vaultwarden,
        },
    }
}

/// Starts the server on a thread of its own, with a runtime of its own: a test's runtime ends with
/// the test, and the server must outlive every test of the file. Returns its address once it
/// answers.
fn boot_in_process() -> String {
    let (sender, receiver) = channel::<Result<String, String>>();
    std::thread::Builder::new()
        .name("kemlock-contract-server".to_owned())
        .spawn(move || {
            let runtime = match tokio::runtime::Runtime::new() {
                Ok(runtime) => runtime,
                Err(e) => {
                    let _ = sender.send(Err(format!("no runtime: {e}")));
                    return;
                }
            };
            if let Err(e) = runtime.block_on(serve(&sender)) {
                // A failure after the address was sent is not read by anyone
                let _ = sender.send(Err(e));
            }
        })
        .expect("a thread for the server");
    match receiver.recv_timeout(Duration::from_secs(180)) {
        Ok(Ok(base)) => base,
        Ok(Err(e)) => panic!("the server under test did not start: {e}"),
        Err(e) => panic!("the server under test did not start in time: {e}"),
    }
}

fn fresh_data_folder() -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let path =
        std::env::temp_dir().join(format!("kemlock-contract-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&path).expect("a temp dir");
    path
}

/// Binds an ephemeral port, builds the server the way `kemlock-server` does for real (its keys made
/// in a temporary data folder, a SQLite file migrated), says where it is, and serves until the
/// process ends.
async fn serve(started: &Sender<Result<String, String>>) -> Result<(), String> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("can't bind: {e}"))?;
    let port = listener
        .local_addr()
        .map_err(|e| format!("no local address: {e}"))?
        .port();
    // `localhost`, not the address: a security key's relying party id must be a domain name
    let base = format!("http://localhost:{port}");
    let data = fresh_data_folder().display().to_string();
    let port_text = port.to_string();
    let config = Config::from_sources(
        &|name| match name {
            "DATA_FOLDER" => Some(data.clone()),
            "DOMAIN" => Some(base.clone()),
            "ROCKET_ADDRESS" => Some("127.0.0.1".to_owned()),
            "ROCKET_PORT" => Some(port_text.clone()),
            "SIGNUPS_ALLOWED" => Some("true".to_owned()),
            "SIGNUPS_VERIFY" => Some("false".to_owned()),
            "KEMLOCK_BITWARDEN_COMPAT" => Some("true".to_owned()),
            "LOG_LEVEL" => Some("warn".to_owned()),
            // Vaultwarden's own names for the login limits: the suite signs in far more often
            // than a person does
            "LOGIN_RATELIMIT_SECONDS" | "UNAUTHENTICATED_RATELIMIT_SECONDS" => Some("1".to_owned()),
            "LOGIN_RATELIMIT_MAX_BURST" | "UNAUTHENTICATED_RATELIMIT_MAX_BURST" => {
                Some("100000".to_owned())
            }
            _ => None,
        },
        None,
    )
    .map_err(|e| format!("configuration: {e}"))?;
    let built = kemlock_server::build(&config)
        .await
        .map_err(|e| format!("building the server: {e}"))?;
    let router = built.router.clone();
    let _ = started.send(Ok(base.clone()));
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .map_err(|e| format!("serving: {e}"))
}
