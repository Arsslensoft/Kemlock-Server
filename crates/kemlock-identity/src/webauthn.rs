//! The WebAuthn relying party: [`WebAuthnRp`] implements `kemlock_app::passkeys::WebAuthn` over
//! `webauthn-rs-core`.
//!
//! The relying party is this server at its `DOMAIN`: the relying party id is the domain's host and
//! the one allowed origin is its scheme, host and port. The core is used directly rather than
//! through the `webauthn-rs` wrapper, because the two kinds of credential need different policies
//! and the wrapper fixes one:
//!
//! | | passkey | security key (Bitwarden's type 7) |
//! |---|---|---|
//! | user verification | required | discouraged, as Vaultwarden asks |
//! | discoverable credential | required | no |
//! | `appid` extension | no | `<DOMAIN>/app-id.json` |
//! | attestation | none | none |
//!
//! Every ceremony is stateless here: the registration and authentication state the core makes
//! goes out as JSON bytes, and the caller keeps it (the stored challenge, or a sealed value) until
//! the answer comes. A stored credential is the core's `Credential` as JSON: the public key, the
//! signature counter and the backup flags.
//!
//! Answers arrive as `PublicKeyCredential.toJSON()` or in the spelling Bitwarden's clients use
//! (`AttestationObject`, `clientDataJson`); both are read.

use kemlock_app::passkeys::{
    Assertion, CredentialKind, NewCredential, RegistrationStart, ResponseIds, Started, WebAuthn,
    WebAuthnError,
};
use serde_json::{Map, Value};
use std::time::Duration;
use url::Url;
use webauthn_rs_core::WebauthnCore;
use webauthn_rs_core::proto::{
    AttestationConveyancePreference, AuthenticationState, COSEAlgorithm, Credential,
    PublicKeyCredential, RegisterPublicKeyCredential, RegistrationState,
    RequestAuthenticationExtensions, RequestRegistrationExtensions, UserVerificationPolicy,
};

/// How long a browser is asked to wait for the authenticator, as Vaultwarden asks.
const TIMEOUT: Duration = Duration::from_secs(60);

/// The name the relying party gives itself, which an authenticator may show.
const RP_NAME: &str = "Kemlock";

/// The members of `response` whose spelling the Bitwarden clients vary, as the core reads them.
const RESPONSE_MEMBERS: [&str; 6] = [
    "attestationObject",
    "clientDataJSON",
    "authenticatorData",
    "signature",
    "userHandle",
    "transports",
];

/// This server as a WebAuthn relying party.
#[derive(Clone, Debug)]
pub struct WebAuthnRp {
    core: WebauthnCore,
    rp_id: String,
    app_id: String,
}

impl WebAuthnRp {
    /// The relying party for the server at `domain` (`DOMAIN`, such as `https://vault.example.org`):
    /// its host is the relying party id, and its origin the only one answers may come from.
    pub fn new(domain: &str) -> Result<Self, WebAuthnError> {
        let url = Url::parse(domain.trim())
            .map_err(|_| WebAuthnError::Failed("DOMAIN isn't a URL".to_owned()))?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(WebAuthnError::Failed(
                "DOMAIN must be an http or https address".to_owned(),
            ));
        }
        let rp_id = url
            .host_str()
            .filter(|host| !host.is_empty())
            .ok_or_else(|| WebAuthnError::Failed("DOMAIN has no host".to_owned()))?
            .to_owned();
        let origin = Url::parse(&url.origin().ascii_serialization())
            .map_err(|_| WebAuthnError::Failed("DOMAIN has no origin".to_owned()))?;
        let app_id = format!("{}/app-id.json", domain.trim().trim_end_matches('/'));
        Ok(WebAuthnRp {
            core: WebauthnCore::new_unsafe_experts_only(
                RP_NAME,
                &rp_id,
                vec![origin],
                TIMEOUT,
                Some(false),
                Some(false),
            ),
            rp_id,
            app_id,
        })
    }

    /// The relying party id: the host of the server's domain.
    pub fn rp_id(&self) -> &str {
        &self.rp_id
    }

    /// The address Bitwarden's `appid` extension names: `<DOMAIN>/app-id.json`.
    pub fn app_id(&self) -> &str {
        &self.app_id
    }
}

fn failed(e: impl std::fmt::Display) -> WebAuthnError {
    WebAuthnError::Failed(e.to_string())
}

fn refused(e: impl std::fmt::Display) -> WebAuthnError {
    WebAuthnError::Refused(e.to_string())
}

/// The response as the core's serde types read it: the members of `response` under their
/// standard names whatever the client's case, `rawId` filled from `id`, and one spelling of the
/// extension results.
fn normalised(response: &[u8], assertion: bool) -> Result<Value, WebAuthnError> {
    let mut value: Value = serde_json::from_slice(response)
        .map_err(|_| WebAuthnError::Malformed("the response isn't JSON"))?;
    let top = value
        .as_object_mut()
        .ok_or(WebAuthnError::Malformed("the response isn't a JSON object"))?;
    if !top.contains_key("rawId")
        && let Some(id) = top.get("id").cloned()
    {
        top.insert("rawId".to_owned(), id);
    }
    if top.contains_key("extensions") {
        top.remove("clientExtensionResults");
    }
    let inner = top
        .get_mut("response")
        .and_then(Value::as_object_mut)
        .ok_or(WebAuthnError::Malformed(
            "the response has no response member",
        ))?;
    rename_members(inner);
    if assertion {
        inner.entry("userHandle".to_owned()).or_insert(Value::Null);
    }
    Ok(value)
}

fn rename_members(inner: &mut Map<String, Value>) {
    let keys: Vec<String> = inner.keys().cloned().collect();
    for key in keys {
        let Some(canonical) = RESPONSE_MEMBERS
            .iter()
            .find(|member| member.eq_ignore_ascii_case(&key))
        else {
            continue;
        };
        if *canonical == key {
            continue;
        }
        if let Some(moved) = inner.remove(&key) {
            inner.entry((*canonical).to_owned()).or_insert(moved);
        }
    }
}

fn registration_response(response: &[u8]) -> Result<RegisterPublicKeyCredential, WebAuthnError> {
    serde_json::from_value(normalised(response, false)?)
        .map_err(|_| WebAuthnError::Malformed("the registration response isn't valid"))
}

fn assertion_response(response: &[u8]) -> Result<PublicKeyCredential, WebAuthnError> {
    serde_json::from_value(normalised(response, true)?)
        .map_err(|_| WebAuthnError::Malformed("the sign-in response isn't valid"))
}

fn credential_of(blob: &[u8]) -> Result<Credential, WebAuthnError> {
    serde_json::from_slice(blob)
        .map_err(|_| WebAuthnError::Malformed("a stored credential isn't valid"))
}

impl WebAuthn for WebAuthnRp {
    fn start_registration(
        &self,
        request: &RegistrationStart<'_>,
    ) -> Result<Started, WebAuthnError> {
        let (policy, resident) = match request.kind {
            CredentialKind::Passkey => (UserVerificationPolicy::Required, true),
            CredentialKind::SecurityKey => (UserVerificationPolicy::Discouraged_DO_NOT_USE, false),
        };
        let exclude: Vec<Vec<u8>> = request.exclude.to_vec();
        let builder = self
            .core
            .new_challenge_register_builder(
                request.user_handle,
                request.user_name,
                request.display_name,
            )
            .map_err(failed)?
            .attestation(AttestationConveyancePreference::None)
            .credential_algorithms(COSEAlgorithm::secure_algs())
            .require_resident_key(resident)
            .authenticator_attachment(None)
            .user_verification_policy(policy)
            .reject_synchronised_authenticators(false)
            .exclude_credentials((!exclude.is_empty()).then_some(exclude))
            .hints(None)
            .extensions(Some(RequestRegistrationExtensions {
                cred_protect: None,
                uvm: None,
                cred_props: Some(true),
                min_pin_length: None,
                hmac_create_secret: None,
            }));
        let (challenge, state) = self
            .core
            .generate_challenge_register(builder)
            .map_err(failed)?;
        Ok(Started {
            options: serde_json::to_value(&challenge.public_key).map_err(failed)?,
            state: serde_json::to_vec(&state).map_err(failed)?,
        })
    }

    fn finish_registration(
        &self,
        _kind: CredentialKind,
        state: &[u8],
        response: &[u8],
    ) -> Result<NewCredential, WebAuthnError> {
        let state: RegistrationState = serde_json::from_slice(state)
            .map_err(|_| WebAuthnError::Malformed("the registration state isn't valid"))?;
        let response = registration_response(response)?;
        let credential = self
            .core
            .register_credential(&response, &state, None)
            .map_err(refused)?;
        Ok(NewCredential {
            credential: serde_json::to_vec(&credential).map_err(failed)?,
            credential_id: credential.cred_id,
        })
    }

    fn start_authentication(
        &self,
        kind: CredentialKind,
        credentials: &[&[u8]],
    ) -> Result<Started, WebAuthnError> {
        let credentials = credentials
            .iter()
            .map(|blob| credential_of(blob))
            .collect::<Result<Vec<Credential>, WebAuthnError>>()?;
        let (policy, extensions) = match kind {
            CredentialKind::Passkey => (UserVerificationPolicy::Required, None),
            CredentialKind::SecurityKey => (
                UserVerificationPolicy::Discouraged_DO_NOT_USE,
                Some(RequestAuthenticationExtensions {
                    appid: Some(self.app_id.clone()),
                    uvm: None,
                    hmac_get_secret: None,
                }),
            ),
        };
        let builder = self
            .core
            .new_challenge_authenticate_builder(credentials, Some(policy))
            .map_err(failed)?
            .extensions(extensions)
            .allow_backup_eligible_upgrade(true)
            .hints(None);
        let (challenge, state) = self
            .core
            .generate_challenge_authenticate(builder)
            .map_err(failed)?;
        Ok(Started {
            options: serde_json::to_value(&challenge.public_key).map_err(failed)?,
            state: serde_json::to_vec(&state).map_err(failed)?,
        })
    }

    fn response_ids(&self, response: &[u8]) -> Result<ResponseIds, WebAuthnError> {
        let response = assertion_response(response)?;
        Ok(ResponseIds {
            credential_id: response.raw_id,
            user_handle: response.response.user_handle,
        })
    }

    fn finish_authentication(
        &self,
        _kind: CredentialKind,
        state: &[u8],
        response: &[u8],
        credentials: &[&[u8]],
    ) -> Result<Assertion, WebAuthnError> {
        let state: AuthenticationState = serde_json::from_slice(state)
            .map_err(|_| WebAuthnError::Malformed("the sign-in state isn't valid"))?;
        let response = assertion_response(response)?;
        let mut credential = credentials
            .iter()
            .map(|blob| credential_of(blob))
            .collect::<Result<Vec<Credential>, WebAuthnError>>()?
            .into_iter()
            .find(|c| c.cred_id == response.raw_id)
            .ok_or_else(|| WebAuthnError::Refused("an unknown credential".to_owned()))?;
        let result = self
            .core
            .authenticate_single_credential(&response, &state, &credential)
            .map_err(refused)?;
        // What a sign-in teaches about the authenticator: its counter, and a credential that
        // became backed up or backup eligible.
        if result.counter() > credential.counter {
            credential.counter = result.counter();
        }
        credential.backup_state = result.backup_state();
        if result.backup_eligible() && !credential.backup_eligible {
            credential.backup_eligible = true;
        }
        Ok(Assertion {
            credential: serde_json::to_vec(&credential).map_err(failed)?,
            credential_id: credential.cred_id,
            user_verified: result.user_verified(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_relying_party_is_the_host_and_the_origin_drops_the_path() {
        let rp = WebAuthnRp::new("https://vault.example.org:8443/bw/").expect("a relying party");
        assert_eq!(rp.rp_id(), "vault.example.org");
        assert_eq!(rp.app_id(), "https://vault.example.org:8443/bw/app-id.json");
        let local = WebAuthnRp::new("http://localhost:41234").expect("localhost");
        assert_eq!(local.rp_id(), "localhost");
        assert_eq!(local.app_id(), "http://localhost:41234/app-id.json");
    }

    #[test]
    fn a_domain_that_isnt_a_web_address_is_refused() {
        for bad in [
            "",
            "vault.example.org",
            "ftp://vault.example.org",
            "file:///x",
        ] {
            assert!(WebAuthnRp::new(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn response_members_are_read_in_any_case() {
        let value = normalised(
            json!({
                "id": "abc",
                "type": "public-key",
                "extensions": {},
                "clientExtensionResults": {},
                "response": {"AttestationObject": "x", "clientDataJson": "y", "signature": "s"}
            })
            .to_string()
            .as_bytes(),
            true,
        )
        .expect("normalises");
        assert_eq!(value["rawId"], "abc");
        assert!(value.get("clientExtensionResults").is_none());
        assert_eq!(value["response"]["attestationObject"], "x");
        assert_eq!(value["response"]["clientDataJSON"], "y");
        assert_eq!(value["response"]["signature"], "s");
        assert!(value["response"]["userHandle"].is_null());
        assert!(value["response"].get("AttestationObject").is_none());
    }

    #[test]
    fn a_standard_spelling_wins_over_a_variant() {
        let value = normalised(
            json!({"id": "a", "response": {"clientDataJSON": "std", "clientDataJson": "alt"}})
                .to_string()
                .as_bytes(),
            false,
        )
        .expect("normalises");
        assert_eq!(value["response"]["clientDataJSON"], "std");
    }

    #[test]
    fn answers_that_are_not_answers_are_malformed() {
        for bad in ["", "[]", "{}", r#"{"response": 3}"#, "not json"] {
            assert!(
                matches!(
                    normalised(bad.as_bytes(), false),
                    Err(WebAuthnError::Malformed(_))
                ),
                "{bad:?}"
            );
        }
    }
}
