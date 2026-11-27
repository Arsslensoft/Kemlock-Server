//! Where this server may connect to: the addresses of its peers.
//!
//! A peer's addresses come from its descriptor, which its own key signs, so a peer (or anyone who
//! holds its key, or the operator of a server it was paired with) chooses where this server sends
//! requests: a probe every minute, a visit, the peer's page in the console, key records and
//! WebSocket upgrades. Without a check that is a blind request to anything this server can reach,
//! such as the cloud metadata address or another service on its own network.
//!
//! So an address has a [`Trust`]:
//!
//! - [`Trust::Admin`]: the admin of this server typed it when pairing, or it was in the peer's
//!   descriptor when the admin confirmed the pairing, or the admin approved it later. It may be
//!   `http` and may name a private network (a home lab, a LAN).
//! - [`Trust::Descriptor`]: it came in a descriptor refreshed since. It must be `https`, and its
//!   name must resolve to public addresses only ([`is_public_ip`]); the connection then goes to
//!   exactly the addresses that were checked, so a second lookup can't answer differently.
//!
//! A **name** the admin typed is looked up again at every dial, and whoever runs its DNS can change
//! the answer after the admin looked: so a name never resolves to an address no network of the
//! admin's could use (the unspecified address, multicast, broadcast, link-local, which holds the
//! cloud metadata address), whatever its trust. A private network, loopback and the like stay the
//! admin's to allow, and an IP address typed as such is the admin's own word.
//!
//! Either way an address is a plain base URL: no user name or password, no query, no fragment. The
//! path of a request is joined to it as a path ([`join`]), never appended to a string, so no
//! address can reach a different URL than the one the code asked for.

use crate::error::{FedError, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use url::{Host, Url};

/// How long a name lookup may take.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

/// How far an address is trusted. See the module notes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trust {
    /// The admin chose it: any scheme, any network.
    Admin,
    /// A descriptor said so: `https` and the public internet only.
    Descriptor,
}

/// Whether `ip` is an address on the public internet. Private, loopback, link-local, shared
/// (carrier-grade NAT), documentation, multicast, unspecified and reserved ranges are not, and
/// neither is an IPv6 address that carries such an IPv4 one.
///
/// The same list as `kemlock-notify`'s UnifiedPush guard; that crate can't be a dependency here
/// (it depends on the store, which depends on this crate), so it is written out in both places.
pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => public_v4(v4),
        IpAddr::V6(v6) => public_v6(v6),
    }
}

fn public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_documentation()
        // 0.0.0.0/8 ("this network").
        || a == 0
        // 100.64.0.0/10, shared address space (carrier-grade NAT).
        || (a == 100 && (64..=127).contains(&b))
        // 192.0.0.0/24, IETF protocol assignments.
        || (a == 192 && b == 0 && c == 0)
        // 192.88.99.0/24, the retired 6to4 relay anycast.
        || (a == 192 && b == 88 && c == 99)
        // 198.18.0.0/15, benchmarking.
        || (a == 198 && (b == 18 || b == 19))
        // 240.0.0.0/4, reserved.
        || a >= 240)
}

fn public_v6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return public_v4(v4);
    }
    let s = ip.segments();
    // ::/96 (IPv4-compatible) and 64:ff9b::/96 (NAT64) carry an IPv4 address in the last 32 bits.
    let embedded = Ipv4Addr::new(
        (s[6] >> 8) as u8,
        (s[6] & 0xff) as u8,
        (s[7] >> 8) as u8,
        (s[7] & 0xff) as u8,
    );
    if s[..6] == [0; 6] || s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        return public_v4(embedded);
    }
    // 64:ff9b:1::/48 (local-use NAT64) carries one in the last 32 bits too.
    if s[..3] == [0x64, 0xff9b, 1] {
        return public_v4(embedded);
    }
    // 2002::/16 (6to4) carries one in bits 16 to 48.
    if s[0] == 0x2002 {
        return public_v4(Ipv4Addr::new(
            (s[1] >> 8) as u8,
            (s[1] & 0xff) as u8,
            (s[2] >> 8) as u8,
            (s[2] & 0xff) as u8,
        ));
    }
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        // fc00::/7, unique local.
        || (s[0] & 0xfe00) == 0xfc00
        // fe80::/10 link-local and fec0::/10 site-local.
        || (s[0] & 0xffc0) == 0xfe80
        || (s[0] & 0xffc0) == 0xfec0
        // 2001:db8::/32, documentation.
        || (s[0] == 0x2001 && s[1] == 0x0db8)
        // ::ffff:0:0:0/96, IPv4-translated (deprecated).
        || s[..6] == [0, 0, 0, 0, 0xffff, 0]
        // 100::/64, discard-only.
        || s[..4] == [0x100, 0, 0, 0]
        // 2001:2::/48, benchmarking.
        || (s[0] == 0x2001 && s[1] == 2 && s[2] == 0)
        // 2001:10::/28, ORCHID (never routed).
        || (s[0] == 0x2001 && (s[1] & 0xfff0) == 0x10))
}

/// Whether `ip` is one no peer is ever at, so a name the admin typed may not resolve to it: the
/// unspecified address, multicast, broadcast and link-local ranges (169.254.0.0/16 holds the cloud
/// metadata address), also inside an IPv6 address that carries an IPv4 one.
pub fn is_never_dialled(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_unspecified() || v4.is_multicast() || v4.is_broadcast() || v4.is_link_local()
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_never_dialled(IpAddr::V4(v4));
            }
            let s = v6.segments();
            v6.is_unspecified() || v6.is_multicast() || (s[0] & 0xffc0) == 0xfe80
        }
    }
}

/// `address` in the form two addresses are compared in: no blanks, no trailing slash, lower case.
pub fn normal(address: &str) -> String {
    address.trim().trim_end_matches('/').to_ascii_lowercase()
}

/// Whether two addresses name the same place.
pub fn same_address(a: &str, b: &str) -> bool {
    normal(a) == normal(b)
}

/// The IP address a URL names directly, if its host is one and not a name.
fn literal(url: &Url) -> Option<IpAddr> {
    match url.host()? {
        Host::Ipv4(ip) => Some(IpAddr::V4(ip)),
        Host::Ipv6(ip) => Some(IpAddr::V6(ip)),
        Host::Domain(_) => None,
    }
}

/// Parses `address` as the base URL of a peer and checks it is fit to dial at this `trust`: `http`
/// or `https` (only `https` for a descriptor's address), a host, no user name, password, query or
/// fragment, and, for a descriptor's address, no IP address that is not public.
pub fn base_url(address: &str, trust: Trust) -> Result<Url> {
    let url =
        Url::parse(address.trim()).map_err(|_| FedError::Invalid("an address is not a URL"))?;
    match (url.scheme(), trust) {
        ("https", _) | ("http", Trust::Admin) => {}
        ("http", Trust::Descriptor) => {
            return Err(FedError::Refused(
                "a peer's address must be https unless the admin typed it",
            ));
        }
        _ => return Err(FedError::Invalid("an address must be an http or https URL")),
    }
    if url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(FedError::Invalid(
            "an address is a plain base URL: a host, with no user, query or fragment",
        ));
    }
    if trust == Trust::Descriptor && literal(&url).is_some_and(|ip| !is_public_ip(ip)) {
        return Err(FedError::Refused(
            "a peer's address names a private or local network; only an address the admin typed may",
        ));
    }
    Ok(url)
}

/// `path` (with its query, if it has one) below the base URL: `https://a.example.org/x` and
/// `/fed/v1/descriptor` give `https://a.example.org/x/fed/v1/descriptor`.
pub fn join(base: &Url, path: &str) -> Url {
    let (path, query) = match path.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (path, None),
    };
    let mut url = base.clone();
    let prefix = base.path().trim_end_matches('/');
    url.set_path(&format!("{prefix}{path}"));
    url.set_query(query);
    url
}

/// The addresses to connect to for `url`, checked at this `trust`: the IP it names, or what its
/// name resolves to. For a descriptor's address one that isn't public refuses the whole name (the
/// client could be handed it). The connection must go to exactly these addresses.
pub async fn resolve(url: &Url, trust: Trust) -> Result<Vec<SocketAddr>> {
    let port = url
        .port_or_known_default()
        .ok_or(FedError::Invalid("an address has no port"))?;
    let named = matches!(url.host(), Some(Host::Domain(_)));
    let found: Vec<SocketAddr> = match url.host() {
        None => return Err(FedError::Invalid("an address has no host")),
        Some(Host::Ipv4(ip)) => vec![SocketAddr::new(IpAddr::V4(ip), port)],
        Some(Host::Ipv6(ip)) => vec![SocketAddr::new(IpAddr::V6(ip), port)],
        Some(Host::Domain(name)) => {
            let looked_up =
                tokio::time::timeout(LOOKUP_TIMEOUT, tokio::net::lookup_host((name, port)))
                    .await
                    .map_err(|_| {
                        FedError::Remote(
                            "the peer's name could not be looked up in time".to_owned(),
                        )
                    })?
                    .map_err(|_| {
                        FedError::Remote("the peer's name could not be looked up".to_owned())
                    })?;
            looked_up.collect()
        }
    };
    if found.is_empty() {
        return Err(FedError::Remote(
            "the peer's name has no address".to_owned(),
        ));
    }
    // Checked at every lookup, whoever typed the name: the answer is not the one the admin saw.
    if named && found.iter().any(|a| is_never_dialled(a.ip())) {
        return Err(FedError::Refused(
            "a peer's name resolves to an address no peer is at (link-local, multicast or unspecified)",
        ));
    }
    if trust == Trust::Descriptor && found.iter().any(|a| !is_public_ip(a.ip())) {
        return Err(FedError::Refused(
            "a peer's name resolves to a private or local network; only an address the admin typed may",
        ));
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("an address")
    }

    #[test]
    fn private_and_special_addresses_are_not_public() {
        for text in [
            "127.0.0.1",
            "10.0.0.5",
            "172.16.0.1",
            "192.168.1.10",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "192.0.2.1",
            "198.18.0.1",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "::1",
            "::",
            "fe80::1",
            "fc00::1",
            "fd12:3456::1",
            "ff02::1",
            "2001:db8::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "64:ff9b::7f00:1",
            "2002:7f00:1::1",
            "::7f00:1",
        ] {
            assert!(!is_public_ip(ip(text)), "{text}");
        }
    }

    #[test]
    fn public_addresses_are_public() {
        for text in [
            "8.8.8.8",
            "1.1.1.1",
            "93.184.216.34",
            "172.15.0.1",
            "172.32.0.1",
            "100.63.255.255",
            "100.128.0.1",
            "2606:4700:4700::1111",
            "::ffff:8.8.8.8",
        ] {
            assert!(is_public_ip(ip(text)), "{text}");
        }
    }

    #[test]
    fn an_address_is_a_plain_base_url() {
        for good in [
            "https://a.example.org",
            "https://a.example.org/",
            "https://a.example.org:8443/kemlock",
        ] {
            assert!(base_url(good, Trust::Descriptor).is_ok(), "{good}");
        }
        for bad in [
            "https://a.example.org?x=",
            "https://a.example.org/?",
            "https://a.example.org#",
            "https://a.example.org/#frag",
            "https://user@a.example.org",
            "https://user:pass@a.example.org",
            "ftp://a.example.org",
            "not a url",
            "https://",
        ] {
            assert!(base_url(bad, Trust::Admin).is_err(), "{bad}");
            assert!(base_url(bad, Trust::Descriptor).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_descriptors_address_is_https_and_public_but_one_the_admin_typed_may_be_neither() {
        for private in [
            "http://a.example.org",
            "https://127.0.0.1",
            "https://10.0.0.5:8443",
            "https://169.254.169.254",
            "https://[::1]",
            "https://[fd00::1]",
        ] {
            assert!(
                matches!(
                    base_url(private, Trust::Descriptor),
                    Err(FedError::Refused(_))
                ),
                "{private}"
            );
            assert!(base_url(private, Trust::Admin).is_ok(), "{private}");
        }
        assert!(base_url("https://8.8.8.8", Trust::Descriptor).is_ok());
    }

    #[test]
    fn a_path_is_joined_as_a_path_never_appended_to_the_text() {
        let base = base_url("https://a.example.org/", Trust::Admin).expect("a base");
        assert_eq!(
            join(&base, "/fed/v1/descriptor").as_str(),
            "https://a.example.org/fed/v1/descriptor"
        );
        let prefixed = base_url("https://a.example.org/kemlock/", Trust::Admin).expect("a base");
        assert_eq!(
            join(&prefixed, "/fed/v1/pair/finish?initiator=x").as_str(),
            "https://a.example.org/kemlock/fed/v1/pair/finish?initiator=x"
        );
        // An address that ended in `?x=` or `#` would have swallowed the path; it is refused
        // before it gets here, and a join always keeps the path and the host.
        let url = join(&base, "/fed/v1/keys");
        assert_eq!(url.host_str(), Some("a.example.org"));
        assert_eq!(url.path(), "/fed/v1/keys");
        assert_eq!(url.query(), None);
        assert_eq!(url.fragment(), None);
    }

    #[test]
    fn addresses_compare_without_case_or_a_trailing_slash() {
        assert!(same_address(
            "https://A.example.org/",
            "https://a.example.org"
        ));
        assert!(!same_address(
            "https://a.example.org",
            "https://b.example.org"
        ));
    }

    #[tokio::test]
    async fn a_name_that_is_an_ip_literal_is_checked_without_a_lookup() {
        let private = base_url("https://10.0.0.5:8443", Trust::Admin).expect("a base");
        assert_eq!(
            resolve(&private, Trust::Admin).await.expect("allowed"),
            vec![SocketAddr::new(ip("10.0.0.5"), 8443)]
        );
        assert!(matches!(
            resolve(&private, Trust::Descriptor).await,
            Err(FedError::Refused(_))
        ));
        let public = base_url("https://8.8.8.8", Trust::Descriptor).expect("a base");
        assert_eq!(
            resolve(&public, Trust::Descriptor).await.expect("public"),
            vec![SocketAddr::new(ip("8.8.8.8"), 443)]
        );
    }

    #[test]
    fn some_addresses_are_never_dialled_by_name() {
        for text in [
            "169.254.169.254",
            "169.254.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "fe80::1",
            "ff02::1",
            "::",
            "::ffff:169.254.169.254",
        ] {
            assert!(is_never_dialled(ip(text)), "{text}");
        }
        // A home lab is still the admin's to allow.
        for text in [
            "10.0.0.5",
            "192.168.1.10",
            "127.0.0.1",
            "::1",
            "fd00::1",
            "8.8.8.8",
        ] {
            assert!(!is_never_dialled(ip(text)), "{text}");
        }
    }

    #[tokio::test]
    async fn localhost_is_private_for_a_descriptor_and_fine_when_the_admin_typed_it() {
        let url = base_url("https://localhost:9", Trust::Admin).expect("a base");
        assert!(matches!(
            resolve(&url, Trust::Descriptor).await,
            Err(FedError::Refused(_))
        ));
        assert!(resolve(&url, Trust::Admin).await.is_ok());
    }
}
