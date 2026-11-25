//! Where each of an account's vaults lives: the answer behind the web vault's failover banner and
//! its "Where your vault is stored" page.
//!
//! It is built from the federation view (the servers of each vault, the home first) for the
//! account's own vault and the spaces it is a confirmed member of, and from its devices (the apps
//! that use this server). A server that doesn't federate any of them has nothing to say, and the
//! answer is `None`.
//!
//! A peer's status is what this server's probes of it found (`federation_view::PeerStatus`:
//! `unknown` until the first probe), and this server itself is `online`, since it is answering. What
//! this server cannot know it does not say: a server's name is the host of its address and its
//! place is not in its descriptor. A space has no name the server can read, so it is named by its
//! short id.

use crate::error::AppError;
use crate::federation_view::{FederationView, PeerHealthView, PeerStatus, ServerRole};
use crate::ports::DeviceRepo;
use crate::spaces::SpaceRepo;
use kemlock_domain::{DeviceKind, Owner, ServerId, UserId};

/// One server a vault is held on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlacementServer {
    pub id: String,
    /// The host of its address.
    pub name: String,
    pub role: ServerRole,
    /// The apps of this vault are on it right now: it is the server answering.
    pub in_use: bool,
    /// Whether it answers, as the probes found; this server is `online`.
    pub health: PeerHealthView,
    /// A cancel is in force: this vault's waiting changes are being withheld from this server.
    pub withheld: bool,
}

/// One vault and the servers that hold it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlacementVault {
    /// `me` for the account's own vault, else the space's id.
    pub id: String,
    pub name: String,
    /// The home first, then the replicas in order.
    pub servers: Vec<PlacementServer>,
    /// Changes of this vault that haven't reached one of the other servers.
    pub pending: Option<PlacementPending>,
}

/// Changes of a vault that wait for one server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlacementPending {
    /// The server they wait for; also the id the cancel route takes.
    pub peer: ServerId,
    pub peer_name: String,
    pub changes: u64,
    /// The count stopped at a limit.
    pub at_least: bool,
    /// When the oldest was written, Unix seconds.
    pub oldest_at: Option<u64>,
}

/// An app of the account, and the server it uses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlacementApp {
    pub name: String,
    /// The server it uses now, by name: the one answering.
    pub server: String,
    /// A Bitwarden-compatible app, which stays on its address and works from its local copy.
    pub local_copy: bool,
    /// The address it stays on, when `local_copy`.
    pub address: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Placement {
    pub vaults: Vec<PlacementVault>,
    pub apps: Vec<PlacementApp>,
}

/// The host of a server address such as `https://vps.example.net:8443/`: `vps.example.net`.
pub fn host_of(address: &str) -> String {
    let rest = address.split_once("://").map_or(address, |(_, rest)| rest);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    let host = if let Some(stripped) = authority.strip_prefix('[') {
        // An IPv6 literal keeps its brackets.
        stripped
            .split_once(']')
            .map_or(authority.to_owned(), |(h, _)| format!("[{h}]"))
    } else {
        authority.split(':').next().unwrap_or(authority).to_owned()
    };
    host.to_ascii_lowercase()
}

/// Two addresses name the same server: same scheme-less authority, ignoring case and a trailing
/// slash.
fn same_address(a: &str, b: &str) -> bool {
    let norm = |s: &str| {
        s.split_once("://")
            .map_or(s, |(_, rest)| rest)
            .trim_end_matches('/')
            .to_ascii_lowercase()
    };
    norm(a) == norm(b)
}

/// Reads the placement of one account.
#[derive(Debug)]
pub struct ReadPlacement<D, Q> {
    pub devices: D,
    pub spaces: Q,
}

impl<D: DeviceRepo, Q: SpaceRepo> ReadPlacement<D, Q> {
    /// `own_address` is this server's `DOMAIN`. `None` when none of the account's vaults is
    /// federated here.
    pub async fn execute(
        &self,
        user: UserId,
        view: &dyn FederationView,
        own_address: &str,
    ) -> Result<Option<Placement>, AppError> {
        let mut owners = vec![("me".to_owned(), "My vault".to_owned(), Owner::User(user))];
        for member in self.spaces.memberships(user).await? {
            if member.is_confirmed() {
                let id = member.space.to_string();
                let short: String = id.chars().take(8).collect();
                owners.push((id, format!("Space {short}"), Owner::Space(member.space)));
            }
        }
        let mut vaults = Vec::new();
        for (id, name, owner) in owners {
            let Some(held) = view.vault_servers(owner).await? else {
                continue;
            };
            let withheld = view.withheld_from(owner).await?;
            let mut servers = Vec::new();
            for s in &held.servers {
                let in_use = same_address(&s.address, own_address);
                let health = if in_use {
                    // This server is answering: no probe is needed to know it is up.
                    PeerHealthView {
                        status: PeerStatus::Online,
                        ..PeerHealthView::unknown()
                    }
                } else {
                    view.peer_health(s.server).await?
                };
                servers.push(PlacementServer {
                    id: s.server.to_string(),
                    name: host_of(&s.address),
                    role: s.role,
                    in_use,
                    health,
                    withheld: withheld.contains(&s.server),
                });
            }
            // Changes waiting for a server that is down come first: they are the ones a person
            // may cancel. One is reported per vault; cancelling it shows the next.
            let waiting = view.waiting_changes(owner).await?;
            let offline = |peer: &ServerId| {
                servers
                    .iter()
                    .any(|s| s.id == peer.to_string() && s.health.status == PeerStatus::Offline)
            };
            let pending = waiting
                .iter()
                .find(|w| offline(&w.peer))
                .or_else(|| waiting.first())
                .map(|w| {
                    let peer = w.peer.to_string();
                    PlacementPending {
                        peer: w.peer,
                        peer_name: servers
                            .iter()
                            .find(|s| s.id == peer)
                            .map_or(peer, |s| s.name.clone()),
                        changes: w.changes,
                        at_least: w.at_least,
                        oldest_at: w.oldest_at,
                    }
                });
            vaults.push(PlacementVault {
                id,
                name,
                servers,
                pending,
            });
        }
        if vaults.is_empty() {
            return Ok(None);
        }
        let own_name = host_of(own_address);
        let apps = self
            .devices
            .list(user)
            .await?
            .into_iter()
            .map(|device| {
                let local_copy = device.kind == DeviceKind::Bitwarden;
                PlacementApp {
                    name: device.name,
                    server: own_name.clone(),
                    local_copy,
                    address: local_copy.then(|| own_address.trim_end_matches('/').to_owned()),
                }
            })
            .collect();
        Ok(Some(Placement { vaults, apps }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_of_drops_scheme_port_path_and_userinfo() {
        assert_eq!(
            host_of("https://VPS.example.net:8443/x?y"),
            "vps.example.net"
        );
        assert_eq!(host_of("http://u:p@home.lan"), "home.lan");
        assert_eq!(host_of("vault.example.org"), "vault.example.org");
        assert_eq!(host_of("https://[::1]:8080/"), "[::1]");
    }

    #[test]
    fn addresses_match_ignoring_case_and_a_trailing_slash() {
        assert!(same_address(
            "https://Vault.example.org/",
            "https://vault.example.org"
        ));
        assert!(!same_address(
            "https://a.example.org",
            "https://b.example.org"
        ));
    }
}
