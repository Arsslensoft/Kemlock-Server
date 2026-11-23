//! `kemlock-server healthcheck`: the image's `HEALTHCHECK`, with no shell and no curl.
//!
//! One `GET /alive` to the server's own port over loopback. It lives in the server binary so the
//! image carries one executable; `kemlock-cli healthcheck` calls the same code.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::time::Duration;

/// `GET /alive` over a plain TCP connection; returns the HTTP status. No HTTP client is needed
/// for one request to ourselves, and the image has no curl.
fn alive_status(address: SocketAddr, timeout: Duration) -> std::io::Result<u16> {
    let mut stream = TcpStream::connect_timeout(&address, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    stream.write_all(b"GET /alive HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
    let mut head = [0u8; 512];
    let read = stream.read(&mut head)?;
    parse_status(&head[..read])
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "not an HTTP response"))
}

/// The status code of an HTTP/1.x response's first line.
fn parse_status(head: &[u8]) -> Option<u16> {
    let line = head.split(|b| *b == b'\r' || *b == b'\n').next()?;
    let line = std::str::from_utf8(line).ok()?;
    let mut parts = line.split(' ');
    if !parts.next()?.starts_with("HTTP/1.") {
        return None;
    }
    parts.next()?.parse().ok()
}

/// Whether the server on loopback answers `/alive` with 200, over IPv4 or IPv6.
pub fn healthy(port: u16) -> bool {
    let timeout = Duration::from_secs(3);
    [
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ]
    .into_iter()
    .any(|ip| alive_status(SocketAddr::new(ip, port), timeout).is_ok_and(|status| status == 200))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn status_lines_parse() {
        assert_eq!(parse_status(b"HTTP/1.1 200 OK\r\nx: y\r\n\r\n"), Some(200));
        assert_eq!(
            parse_status(b"HTTP/1.0 503 Service Unavailable\r\n"),
            Some(503)
        );
        assert_eq!(parse_status(b"SMTP 220 hello\r\n"), None);
        assert_eq!(parse_status(b""), None);
        assert_eq!(parse_status(b"HTTP/1.1 abc\r\n"), None);
    }

    /// Serves one canned response on an ephemeral loopback port.
    fn serve_once(response: &'static str) -> u16 {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("a free port");
        let port = listener.local_addr().expect("an address").port();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buffer = [0u8; 512];
                let _ = stream.read(&mut buffer);
                let _ = stream.write_all(response.as_bytes());
            }
        });
        port
    }

    #[test]
    fn a_server_answering_200_is_healthy() {
        let port = serve_once("HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok");
        assert!(healthy(port));
    }

    #[test]
    fn a_server_answering_503_or_nothing_is_not() {
        let port = serve_once("HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\n\r\n");
        assert!(!healthy(port));
        // A port nobody listens on.
        let closed = {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("a free port");
            listener.local_addr().expect("an address").port()
        };
        assert!(!healthy(closed));
    }
}
