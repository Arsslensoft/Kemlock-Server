//! The address of the client whose request is being served, so every event the request writes
//! carries it without each use case passing it down.
//!
//! The server's request layer wraps each request in [`with_request_ip`]; `SqlStore`'s `EventLog`
//! reads [`request_ip`] when it writes an event and stores the address through the privacy port,
//! which cuts it to its /24 or /48 (and keeps the whole one only while the admin's retention
//! settings keep full addresses). Work that outlives the request, or runs on a task of its own, has
//! no address: its events are written without one.

use std::future::Future;
use std::net::IpAddr;

tokio::task_local! {
    static REQUEST_IP: Option<IpAddr>;
}

/// Runs `work` with `ip` as the address of the request it serves.
pub async fn with_request_ip<F: Future>(ip: Option<IpAddr>, work: F) -> F::Output {
    REQUEST_IP.scope(ip, work).await
}

/// The address of the request being served, if the work runs inside [`with_request_ip`] and the
/// request came with one.
pub fn request_ip() -> Option<IpAddr> {
    REQUEST_IP.try_with(|ip| *ip).ok().flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_address_is_there_inside_the_scope_and_gone_outside_it() {
        let ip: IpAddr = "203.0.113.9".parse().expect("an address");
        assert_eq!(request_ip(), None);
        let inside = with_request_ip(Some(ip), async { request_ip() }).await;
        assert_eq!(inside, Some(ip));
        assert_eq!(request_ip(), None);
    }

    #[tokio::test]
    async fn a_request_without_an_address_has_none() {
        assert_eq!(with_request_ip(None, async { request_ip() }).await, None);
    }

    #[tokio::test]
    async fn a_task_of_its_own_does_not_inherit_the_address() {
        let ip: IpAddr = "203.0.113.9".parse().expect("an address");
        let spawned = with_request_ip(Some(ip), async {
            tokio::spawn(async { request_ip() }).await.expect("joined")
        })
        .await;
        assert_eq!(spawned, None);
    }
}
