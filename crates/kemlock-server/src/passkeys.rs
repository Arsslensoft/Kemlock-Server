//! Passkeys and WebAuthn security keys, wired: the relying party for the server's own `DOMAIN`, and
//! the runtime the `/kem/v1` passkey routes run on.
//!
//! One relying party serves both APIs: the Kemlock API's passkey sign-in and security-key second
//! step, and the Bitwarden API's provider 7. Its id is the host of `DOMAIN` and its only origin the
//! origin of `DOMAIN`, so a passkey made at one address does not work at another.
//!
//! "Require SSO" reads space membership from the store, the same facts every other way in reads, so
//! a space that requires single sign-on closes passkey sign-in to its members here as it does the
//! password.

use crate::adapters::ServerCrypto;
use kemlock_api_kem::PasskeyRuntime;
use kemlock_app::admin::{PasskeyStepUp, PasskeyStepper};
use kemlock_identity::WebAuthnRp;
use kemlock_store_sql::SqlStore;
use std::sync::Arc;

/// The ports of the passkey routes for this server.
pub type Runtime = PasskeyRuntime<SqlStore, Arc<WebAuthnRp>, SqlStore>;

/// The relying party for `domain` (`DOMAIN`); an error names why it can't be one.
pub fn relying_party(domain: &str) -> Result<Arc<WebAuthnRp>, String> {
    WebAuthnRp::new(domain)
        .map(Arc::new)
        .map_err(|e| e.to_string())
}

/// The runtime the passkey routes use.
pub fn runtime(store: SqlStore, relying_party: Arc<WebAuthnRp>) -> Runtime {
    PasskeyRuntime::new(store.clone(), relying_party, store)
}

/// The passkey step-up of the admin console: an admin proves it is them with a fresh assertion
/// from one of their own passkeys (user verification required), through the same relying party.
pub fn step_up(
    store: SqlStore,
    relying_party: Arc<WebAuthnRp>,
    crypto: ServerCrypto,
) -> Arc<dyn PasskeyStepper> {
    Arc::new(PasskeyStepUp {
        passkeys: store,
        webauthn: relying_party,
        seal: crypto.clone(),
        env: crypto,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_relying_party_follows_the_domain() {
        let rp = relying_party("https://vault.example.org:8443").expect("a relying party");
        assert_eq!(rp.rp_id(), "vault.example.org");
        assert!(relying_party("not a url").is_err());
    }

    #[test]
    #[allow(
        clippy::type_complexity,
        reason = "the full type is what the test pins"
    )]
    fn the_runtime_reads_the_stores_membership_facts_not_an_empty_stand_in() {
        // Naming the type is the check: a runtime over `NoSpaces` would not coerce to this.
        let _: fn(
            SqlStore,
            Arc<WebAuthnRp>,
        ) -> PasskeyRuntime<SqlStore, Arc<WebAuthnRp>, SqlStore> = runtime;
    }
}
