//! This server's own federation identity, and the directory of its peers' identity keys.

use crate::crypto;
use crate::descriptor::{Descriptor, SignedDescriptor, kem_key_id, suite_names};
use crate::error::Result;
use crate::suite::Suite;
use kemlock_crypto::{kx1, sig1};
use kemlock_domain::ServerId;
use std::collections::HashMap;

/// A KEM key pair.
#[derive(Clone, Debug)]
pub struct KemPair {
    pub private: kx1::PrivateKey,
    pub public: kx1::PublicKey,
}

impl KemPair {
    pub fn generate() -> Result<KemPair> {
        let (private, public) = crypto::kem_generate()?;
        Ok(KemPair { private, public })
    }

    /// The pair for a stored private key.
    pub fn from_private(private: kx1::PrivateKey) -> Result<KemPair> {
        let public = crypto::kem_public(&private)?;
        Ok(KemPair { private, public })
    }

    pub fn id(&self) -> [u8; 32] {
        kem_key_id(&self.public)
    }
}

/// What a descriptor is built from, apart from the keys.
#[derive(Clone, Debug)]
pub struct DescriptorParams {
    pub suites: Vec<Suite>,
    pub addresses: Vec<String>,
    pub operator: String,
    /// Unix seconds.
    pub not_before: u64,
    /// Unix seconds.
    pub not_after: u64,
}

/// This server's identity key, its KEM keys and the descriptor that publishes them.
///
/// `kems[0]` is the current KEM key, the one in the descriptor. During a rotation the previous
/// key stays in the list for the week of overlap, so a hello addressed to it still opens.
#[derive(Clone, Debug)]
pub struct LocalIdentity {
    pub server: ServerId,
    pub signing: sig1::SigningKey,
    pub public: sig1::PublicKey,
    pub kems: Vec<KemPair>,
    pub descriptor: SignedDescriptor,
}

impl LocalIdentity {
    /// Builds the identity and signs its descriptor. `kems` must not be empty.
    pub fn new(
        server: ServerId,
        signing: sig1::SigningKey,
        kems: Vec<KemPair>,
        params: DescriptorParams,
    ) -> Result<LocalIdentity> {
        LocalIdentity::new_advertising(server, signing, kems, params, &[])
    }

    /// As [`new`](Self::new), listing `extras` after the suites in the descriptor: names of what
    /// this server does beyond version 1's requests (see `sendsync::SENDS_CAPABILITY`). The
    /// handshake skips names it doesn't know, so they change no negotiation.
    pub fn new_advertising(
        server: ServerId,
        signing: sig1::SigningKey,
        kems: Vec<KemPair>,
        params: DescriptorParams,
        extras: &[&str],
    ) -> Result<LocalIdentity> {
        let public = crypto::sign_public(&signing)?;
        let current = kems.first().ok_or(crate::error::FedError::Invalid(
            "an identity needs a KEM key",
        ))?;
        let descriptor = SignedDescriptor::sign(
            Descriptor {
                server,
                identity_key: public.clone(),
                kem_key: current.public.clone(),
                suites: {
                    let mut names = suite_names(&params.suites);
                    names.extend(extras.iter().map(|e| (*e).to_owned()));
                    names
                },
                addresses: params.addresses,
                operator: params.operator,
                not_before: params.not_before,
                not_after: params.not_after,
            },
            &signing,
        )?;
        Ok(LocalIdentity {
            server,
            signing,
            public,
            kems,
            descriptor,
        })
    }

    /// The KEM key pair with this id, current or previous.
    pub fn kem(&self, id: &[u8; 32]) -> Option<&KemPair> {
        self.kems.iter().find(|k| &k.id() == id)
    }

    /// The suites this server accepts, in its order.
    pub fn suites(&self) -> Vec<Suite> {
        self.descriptor.descriptor.known_suites()
    }
}

/// Where a verifier finds the identity key of a server it has paired with.
pub trait KeyDirectory {
    fn identity_key(&self, server: ServerId) -> Option<sig1::PublicKey>;
}

impl KeyDirectory for HashMap<ServerId, sig1::PublicKey> {
    fn identity_key(&self, server: ServerId) -> Option<sig1::PublicKey> {
        self.get(&server).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn params(now: u64) -> DescriptorParams {
        DescriptorParams {
            suites: Suite::IMPLEMENTED.to_vec(),
            addresses: vec!["https://a.example.org".to_owned()],
            operator: "Example".to_owned(),
            not_before: now,
            not_after: now + crate::descriptor::VALIDITY_SECS,
        }
    }

    #[test]
    fn an_identity_publishes_a_verifiable_descriptor() {
        let now = 1_800_000_000;
        let kem = KemPair::generate().expect("kem");
        let id = LocalIdentity::new(
            ServerId::random(),
            sig1::SigningKey::from_bytes(&[6; 64]),
            vec![kem.clone()],
            params(now),
        )
        .expect("identity");
        id.descriptor.verify(now, Some(&id.public)).expect("verify");
        assert_eq!(id.descriptor.descriptor.kem_key, kem.public);
        assert_eq!(id.suites(), Suite::IMPLEMENTED.to_vec());
        assert!(id.kem(&kem.id()).is_some());
        assert!(id.kem(&[0; 32]).is_none());
    }

    #[test]
    fn a_server_lists_what_it_answers_beyond_version_1_and_only_then() {
        let now = 1_800_000_000;
        let kem = KemPair::generate().expect("kem");
        let plain = LocalIdentity::new(
            ServerId::random(),
            sig1::SigningKey::from_bytes(&[6; 64]),
            vec![kem.clone()],
            params(now),
        )
        .expect("identity");
        let newer = LocalIdentity::new_advertising(
            ServerId::random(),
            sig1::SigningKey::from_bytes(&[6; 64]),
            vec![kem],
            params(now),
            &[crate::sendsync::SENDS_CAPABILITY],
        )
        .expect("identity");
        let as_peer = |id: &LocalIdentity| crate::ports::Peer {
            id: id.server,
            operator: String::new(),
            identity_key: id.public.as_bytes().to_vec(),
            addresses: Vec::new(),
            suites: id.descriptor.descriptor.suites.clone(),
            state: crate::ports::PeerState::Paired,
            paired_at: now,
            last_seen: None,
        };
        // An older server's descriptor doesn't list it, so no `Sends` request is sent to it...
        assert!(!as_peer(&plain).advertises(crate::sendsync::SENDS_CAPABILITY));
        assert!(as_peer(&newer).advertises(crate::sendsync::SENDS_CAPABILITY));
        // ...and listing it changes neither the suites a server accepts nor the descriptor's check.
        assert_eq!(newer.suites(), plain.suites());
        newer.descriptor.verify(now, Some(&newer.public)).expect("verify");
        assert_eq!(
            newer.descriptor.descriptor.negotiate(&Suite::IMPLEMENTED).ok(),
            plain.descriptor.descriptor.negotiate(&Suite::IMPLEMENTED).ok()
        );
    }

    #[test]
    fn an_identity_without_a_kem_key_is_refused() {
        assert!(
            LocalIdentity::new(
                ServerId::random(),
                sig1::SigningKey::from_bytes(&[6; 64]),
                vec![],
                params(1),
            )
            .is_err()
        );
    }

    #[test]
    fn a_map_is_a_directory() {
        let id = ServerId::random();
        let key = crypto::sign_public(&sig1::SigningKey::from_bytes(&[1; 64])).expect("key");
        let dir: HashMap<ServerId, sig1::PublicKey> = [(id, key.clone())].into_iter().collect();
        assert_eq!(dir.identity_key(id), Some(key));
        assert_eq!(dir.identity_key(ServerId::random()), None);
    }
}
