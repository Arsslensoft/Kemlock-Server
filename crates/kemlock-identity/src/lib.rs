//! Kemlock Server's identity adapters: the OpenID Connect relying party and the DNS lookup behind
//! the domain proof.
//!
//! - [`OidcClient`] implements `kemlock_app::sso::OidcProvider` over the `openidconnect` crate:
//!   discovery, the authorization code flow with PKCE and a nonce, ID token validation (and
//!   `amr`, `groups` and `sid` read from the verified token) and back-channel logout tokens.
//! - [`DnsTxtResolver`] implements `kemlock_app::sso::TxtLookup` over `hickory-resolver`, for the
//!   `kemlock-verification=<token>` TXT record an admin publishes to prove an email domain.
//! - [`WebAuthnRp`] implements `kemlock_app::passkeys::WebAuthn` over `webauthn-rs-core`: passkey and
//!   security-key registration and sign-in for this server's own domain, and
//!   [`authenticator::SoftwareAuthenticator`] plays the authenticator in tests.
//! - [`YubicoClient`] and [`DuoClient`] implement `kemlock_app::two_step::{Yubico, Duo}`: Yubico's
//!   OTP validation service and Duo's Universal Prompt, the second steps Vaultwarden has beyond an
//!   authenticator app and a security key.
//! - [`testing`] has [`FakeProvider`](testing::FakeProvider), an in-process OpenID Connect
//!   provider for tests, and an ES256 signer.
//!
//! SSO decides who may sign in; nothing here touches a vault key. SAML providers connect through
//! an OpenID Connect broker such as Keycloak or Authentik.

pub mod authenticator;
pub mod dns;
pub mod duo;
pub mod logout;
pub mod oidc;
pub mod testing;
pub mod token;
pub mod webauthn;
pub mod yubico;

pub use dns::DnsTxtResolver;
pub use duo::DuoClient;
pub use oidc::OidcClient;
pub use webauthn::WebAuthnRp;
pub use yubico::YubicoClient;

/// The HTTP client crate the relying party uses (`reqwest` 0.12, as `openidconnect` re-exports it),
/// for tests that play a browser against a real provider.
pub use openidconnect::reqwest;
