//! DNS TXT lookups for the domain proof, over `hickory-resolver`.
//!
//! The admin publishes `kemlock-verification=<token>` as a TXT record at the domain; the server's
//! use case (`kemlock_app::sso::DomainProofs`) asks this resolver for the domain's TXT records and
//! compares. The resolver reads the host's DNS settings (`/etc/resolv.conf` on Unix, the adapters
//! on Windows) the first time it is used, not at start, so a server without DNS still boots.

use hickory_resolver::TokioResolver;
use hickory_resolver::proto::rr::{RData, RecordType};
use kemlock_app::sso::{SsoError, TxtLookup};
use tokio::sync::OnceCell;

/// A TXT lookup over the system's DNS settings.
#[derive(Default)]
pub struct DnsTxtResolver {
    resolver: OnceCell<TokioResolver>,
}

impl std::fmt::Debug for DnsTxtResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DnsTxtResolver").finish_non_exhaustive()
    }
}

impl DnsTxtResolver {
    pub fn new() -> Self {
        DnsTxtResolver::default()
    }

    async fn resolver(&self) -> Result<&TokioResolver, SsoError> {
        self.resolver
            .get_or_try_init(|| async {
                TokioResolver::builder_tokio()
                    .and_then(|builder| builder.build())
                    .map_err(|e| SsoError::Provider(format!("can't set up the DNS resolver: {e}")))
            })
            .await
    }
}

/// One TXT record's character-strings joined into one string, as RFC 7208 (section 3.3) reads
/// a record split in 255-byte pieces. Bytes that aren't UTF-8 are replaced.
pub fn join_txt(pieces: &[Box<[u8]>]) -> String {
    let mut joined = Vec::new();
    for piece in pieces {
        joined.extend_from_slice(piece);
    }
    String::from_utf8_lossy(&joined).into_owned()
}

impl TxtLookup for DnsTxtResolver {
    async fn txt_records(&self, name: &str) -> Result<Vec<String>, SsoError> {
        let resolver = self.resolver().await?;
        // A trailing dot makes the name absolute, so the search list isn't tried.
        let fqdn = format!("{}.", name.trim_end_matches('.'));
        match resolver.lookup(fqdn, RecordType::TXT).await {
            Ok(lookup) => Ok(lookup
                .answers()
                .iter()
                .filter_map(|record| match &record.data {
                    RData::TXT(txt) => Some(join_txt(&txt.txt_data)),
                    _ => None,
                })
                .collect()),
            // No such name, or no TXT records at it: nothing is published.
            Err(e) if e.is_no_records_found() => Ok(Vec::new()),
            Err(e) => Err(SsoError::Provider(format!("the DNS lookup failed: {e}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pieces(parts: &[&[u8]]) -> Vec<Box<[u8]>> {
        parts
            .iter()
            .map(|p| (*p).to_vec().into_boxed_slice())
            .collect()
    }

    #[test]
    fn pieces_of_one_record_are_joined() {
        assert_eq!(
            join_txt(&pieces(&[b"kemlock-verification=", b"abc123"])),
            "kemlock-verification=abc123"
        );
        assert_eq!(join_txt(&pieces(&[b"one piece"])), "one piece");
        assert_eq!(join_txt(&[]), "");
    }

    #[test]
    fn bytes_that_are_not_text_are_replaced_not_fatal() {
        assert_eq!(join_txt(&pieces(&[&[0x61, 0xff, 0x62]])), "a\u{fffd}b");
    }

    #[test]
    fn building_the_resolver_is_lazy_and_never_panics() {
        // No lookup is made: this only checks the type is cheap to make and to print.
        let resolver = DnsTxtResolver::new();
        assert!(format!("{resolver:?}").contains("DnsTxtResolver"));
    }
}
