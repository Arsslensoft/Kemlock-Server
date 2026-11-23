//! The WebAuthn relying party against a software authenticator: real registrations and sign-ins,
//! with real attestation and signature checks.

use kemlock_app::b64url;
use kemlock_app::passkeys::{
    CredentialKind, NewCredential, RegistrationStart, Started, WebAuthn, WebAuthnError,
};
use kemlock_identity::WebAuthnRp;
use kemlock_identity::authenticator::{
    SoftwareAuthenticator, bitwarden_assertion, bitwarden_registration,
};
use serde_json::{Value, json};

const DOMAIN: &str = "https://kemlock.test";
const HANDLE: [u8; 16] = [7; 16];

fn rp() -> WebAuthnRp {
    WebAuthnRp::new(DOMAIN).expect("a relying party")
}

fn authenticator() -> SoftwareAuthenticator {
    SoftwareAuthenticator::new("kemlock.test", DOMAIN)
}

fn start(rp: &WebAuthnRp, kind: CredentialKind, exclude: &[Vec<u8>]) -> Started {
    rp.start_registration(&RegistrationStart {
        kind,
        user_handle: &HANDLE,
        user_name: "sam@example.org",
        display_name: "Sam",
        exclude,
    })
    .expect("creation options")
}

fn bytes(answer: &Value) -> Vec<u8> {
    answer.to_string().into_bytes()
}

fn register(
    rp: &WebAuthnRp,
    kind: CredentialKind,
    authenticator: &mut SoftwareAuthenticator,
) -> NewCredential {
    let started = start(rp, kind, &[]);
    let answer = authenticator.create(&started.options);
    rp.finish_registration(kind, &started.state, &bytes(&answer))
        .expect("the registration is accepted")
}

fn is_refused<T>(result: Result<T, WebAuthnError>) -> bool {
    matches!(result, Err(WebAuthnError::Refused(_)))
}

fn sorted_keys(value: &Value) -> Vec<&str> {
    let mut keys: Vec<&str> = value
        .as_object()
        .expect("an object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    keys
}

// ---------------------------------------------------------------------------------------------
// Passkeys.

#[test]
fn a_passkey_registration_asks_for_a_discoverable_credential_with_user_verification() {
    let rp = rp();
    let started = start(&rp, CredentialKind::Passkey, &[]);
    let options = &started.options;
    assert_eq!(options["rp"]["id"], "kemlock.test");
    assert_eq!(options["user"]["id"], b64url::encode(&HANDLE));
    assert_eq!(options["user"]["name"], "sam@example.org");
    assert_eq!(options["user"]["displayName"], "Sam");
    assert_eq!(options["attestation"], "none");
    assert_eq!(options["authenticatorSelection"]["residentKey"], "required");
    assert_eq!(
        options["authenticatorSelection"]["userVerification"],
        "required"
    );
    assert_eq!(options["pubKeyCredParams"][0]["alg"], -7);
    assert_eq!(options["challenge"].as_str().map(str::len), Some(43));
    assert_eq!(options["timeout"], 60_000);
}

#[test]
fn a_passkey_registers_and_signs_in_with_the_counter_kept() {
    let rp = rp();
    let mut authenticator = authenticator();
    let made = register(&rp, CredentialKind::Passkey, &mut authenticator);
    assert_eq!(made.credential_id, authenticator.credential_id());

    let started = rp
        .start_authentication(CredentialKind::Passkey, &[])
        .expect("request options");
    assert_eq!(started.options["allowCredentials"], json!([]));
    assert_eq!(started.options["userVerification"], "required");
    assert_eq!(started.options["rpId"], "kemlock.test");
    assert!(started.options.get("extensions").is_none());

    let answer = bytes(&authenticator.get(&started.options));
    let ids = rp.response_ids(&answer).expect("the ids");
    assert_eq!(ids.credential_id, made.credential_id);
    assert_eq!(ids.user_handle, Some(HANDLE.to_vec()));

    let assertion = rp
        .finish_authentication(
            CredentialKind::Passkey,
            &started.state,
            &answer,
            &[made.credential.as_slice()],
        )
        .expect("the sign-in is accepted");
    assert!(assertion.user_verified);
    assert_eq!(assertion.credential_id, made.credential_id);
    let stored: Value = serde_json::from_slice(&assertion.credential).expect("a credential");
    assert_eq!(stored["counter"], 1);
}

#[test]
fn a_counter_that_did_not_grow_and_a_replayed_answer_are_refused() {
    let rp = rp();
    let mut authenticator = authenticator();
    let made = register(&rp, CredentialKind::Passkey, &mut authenticator);
    let first = rp
        .start_authentication(CredentialKind::Passkey, &[])
        .expect("options");
    let answer = bytes(&authenticator.get(&first.options));
    let signed = rp
        .finish_authentication(
            CredentialKind::Passkey,
            &first.state,
            &answer,
            &[made.credential.as_slice()],
        )
        .expect("the first sign-in");

    // The same answer to a new challenge.
    let second = rp
        .start_authentication(CredentialKind::Passkey, &[])
        .expect("options");
    assert!(is_refused(rp.finish_authentication(
        CredentialKind::Passkey,
        &second.state,
        &answer,
        &[signed.credential.as_slice()],
    )));

    // A cloned authenticator that starts again from 0 makes counter 1, which is not above 1.
    authenticator.set_counter(0);
    let cloned = bytes(&authenticator.get(&second.options));
    assert!(is_refused(rp.finish_authentication(
        CredentialKind::Passkey,
        &second.state,
        &cloned,
        &[signed.credential.as_slice()],
    )));

    authenticator.set_counter(9);
    let moved_on = bytes(&authenticator.get(&second.options));
    let stored = rp
        .finish_authentication(
            CredentialKind::Passkey,
            &second.state,
            &moved_on,
            &[signed.credential.as_slice()],
        )
        .expect("a counter that grew");
    let stored: Value = serde_json::from_slice(&stored.credential).expect("a credential");
    assert_eq!(stored["counter"], 10);
}

#[test]
fn registrations_from_another_origin_or_relying_party_or_challenge_are_refused() {
    let rp = rp();
    let started = start(&rp, CredentialKind::Passkey, &[]);

    let mut elsewhere = authenticator();
    elsewhere.set_origin("https://evil.test");
    let answer = bytes(&elsewhere.create(&started.options));
    assert!(is_refused(rp.finish_registration(
        CredentialKind::Passkey,
        &started.state,
        &answer
    )));

    let mut another_port = authenticator();
    another_port.set_origin("https://kemlock.test:9999");
    let answer = bytes(&another_port.create(&started.options));
    assert!(is_refused(rp.finish_registration(
        CredentialKind::Passkey,
        &started.state,
        &answer
    )));

    let mut another_rp = SoftwareAuthenticator::new("evil.test", DOMAIN);
    let answer = bytes(&another_rp.create(&started.options));
    assert!(is_refused(rp.finish_registration(
        CredentialKind::Passkey,
        &started.state,
        &answer
    )));

    // An answer to another challenge.
    let other = start(&rp, CredentialKind::Passkey, &[]);
    let mut honest = authenticator();
    let answer = bytes(&honest.create(&other.options));
    assert!(is_refused(rp.finish_registration(
        CredentialKind::Passkey,
        &started.state,
        &answer
    )));
}

#[test]
fn sign_ins_from_another_origin_or_for_another_challenge_or_credential_are_refused() {
    let rp = rp();
    let mut authenticator = authenticator();
    let made = register(&rp, CredentialKind::Passkey, &mut authenticator);
    let started = rp
        .start_authentication(CredentialKind::Passkey, &[])
        .expect("options");
    let stored = [made.credential.as_slice()];

    authenticator.set_origin("https://evil.test");
    let answer = bytes(&authenticator.get(&started.options));
    assert!(is_refused(rp.finish_authentication(
        CredentialKind::Passkey,
        &started.state,
        &answer,
        &stored
    )));

    authenticator.set_origin(DOMAIN);
    let other = rp
        .start_authentication(CredentialKind::Passkey, &[])
        .expect("options");
    let answer = bytes(&authenticator.get(&other.options));
    assert!(is_refused(rp.finish_authentication(
        CredentialKind::Passkey,
        &started.state,
        &answer,
        &stored
    )));

    // A credential the caller didn't list.
    let answer = bytes(&authenticator.get(&started.options));
    assert!(is_refused(rp.finish_authentication(
        CredentialKind::Passkey,
        &started.state,
        &answer,
        &[]
    )));

    // A signature by another key under the same credential id.
    let mut forger = SoftwareAuthenticator::new("kemlock.test", DOMAIN);
    forger.create(&start(&rp, CredentialKind::Passkey, &[]).options);
    let mut forged = forger.get(&started.options);
    forged["id"] = json!(b64url::encode(&made.credential_id));
    forged["rawId"] = forged["id"].clone();
    assert!(is_refused(rp.finish_authentication(
        CredentialKind::Passkey,
        &started.state,
        &bytes(&forged),
        &stored
    )));
}

#[test]
fn a_passkey_needs_user_verification_at_registration_and_at_sign_in() {
    let rp = rp();
    let started = start(&rp, CredentialKind::Passkey, &[]);
    let mut careless = authenticator();
    careless.set_user_verified(false);
    let answer = bytes(&careless.create(&started.options));
    assert!(is_refused(rp.finish_registration(
        CredentialKind::Passkey,
        &started.state,
        &answer
    )));

    let mut authenticator = authenticator();
    let made = register(&rp, CredentialKind::Passkey, &mut authenticator);
    authenticator.set_user_verified(false);
    let started = rp
        .start_authentication(CredentialKind::Passkey, &[])
        .expect("options");
    let answer = bytes(&authenticator.get(&started.options));
    assert!(is_refused(rp.finish_authentication(
        CredentialKind::Passkey,
        &started.state,
        &answer,
        &[made.credential.as_slice()]
    )));
}

#[test]
fn credentials_already_registered_are_excluded() {
    let rp = rp();
    let mut authenticator = authenticator();
    let made = register(&rp, CredentialKind::Passkey, &mut authenticator);
    let started = start(
        &rp,
        CredentialKind::Passkey,
        std::slice::from_ref(&made.credential_id),
    );
    assert_eq!(
        started.options["excludeCredentials"][0]["id"],
        b64url::encode(&made.credential_id)
    );
    // The same authenticator answering anyway is refused.
    let answer = bytes(&authenticator.create(&started.options));
    assert!(is_refused(rp.finish_registration(
        CredentialKind::Passkey,
        &started.state,
        &answer
    )));
}

// ---------------------------------------------------------------------------------------------
// Security keys.

#[test]
fn a_security_keys_challenge_has_the_shape_vaultwarden_sends() {
    let rp = rp();
    let mut authenticator = authenticator();
    authenticator.set_user_verified(false);
    let made = register(&rp, CredentialKind::SecurityKey, &mut authenticator);

    let started = rp
        .start_authentication(CredentialKind::SecurityKey, &[made.credential.as_slice()])
        .expect("options");
    let options = &started.options;
    // fixtures/webauthn/providers2-7.json, key for key.
    assert_eq!(
        sorted_keys(options),
        [
            "allowCredentials",
            "challenge",
            "extensions",
            "rpId",
            "timeout",
            "userVerification"
        ]
    );
    assert_eq!(
        options["extensions"],
        json!({"appid": "https://kemlock.test/app-id.json"})
    );
    assert_eq!(options["rpId"], "kemlock.test");
    assert_eq!(options["timeout"], 60_000);
    assert_eq!(options["userVerification"], "discouraged");
    assert_eq!(options["challenge"].as_str().map(str::len), Some(43));
    let allowed = &options["allowCredentials"][0];
    assert_eq!(sorted_keys(allowed), ["id", "type"]);
    assert_eq!(allowed["id"], b64url::encode(&made.credential_id));
    assert_eq!(allowed["type"], "public-key");
}

#[test]
fn a_security_key_registers_without_user_verification_and_signs_in() {
    let rp = rp();
    let mut authenticator = authenticator();
    authenticator.set_user_verified(false);
    let started = start(&rp, CredentialKind::SecurityKey, &[]);
    assert_eq!(
        started.options["authenticatorSelection"]["userVerification"],
        "discouraged"
    );
    assert_eq!(
        started.options["authenticatorSelection"]["residentKey"],
        "discouraged"
    );
    let made = rp
        .finish_registration(
            CredentialKind::SecurityKey,
            &started.state,
            &bytes(&authenticator.create(&started.options)),
        )
        .expect("no user verification is asked of a security key");

    let started = rp
        .start_authentication(CredentialKind::SecurityKey, &[made.credential.as_slice()])
        .expect("options");
    let assertion = rp
        .finish_authentication(
            CredentialKind::SecurityKey,
            &started.state,
            &bytes(&authenticator.get(&started.options)),
            &[made.credential.as_slice()],
        )
        .expect("the key's answer");
    assert!(!assertion.user_verified);
    let stored: Value = serde_json::from_slice(&assertion.credential).expect("a credential");
    assert_eq!(stored["counter"], 1);

    // A counter that did not grow is refused.
    let again = rp
        .start_authentication(
            CredentialKind::SecurityKey,
            &[assertion.credential.as_slice()],
        )
        .expect("options");
    authenticator.set_counter(0);
    assert!(is_refused(rp.finish_authentication(
        CredentialKind::SecurityKey,
        &again.state,
        &bytes(&authenticator.get(&again.options)),
        &[assertion.credential.as_slice()],
    )));
}

#[test]
fn bitwardens_spelling_of_an_answer_is_read() {
    let rp = rp();
    let mut authenticator = authenticator();
    authenticator.set_user_verified(false);
    let started = start(&rp, CredentialKind::SecurityKey, &[]);
    let standard = authenticator.create(&started.options);
    let made = rp
        .finish_registration(
            CredentialKind::SecurityKey,
            &started.state,
            &bytes(&bitwarden_registration(&standard)),
        )
        .expect("deviceResponse as Bitwarden's client sends it");

    let started = rp
        .start_authentication(CredentialKind::SecurityKey, &[made.credential.as_slice()])
        .expect("options");
    let token = bitwarden_assertion(&authenticator.get(&started.options));
    assert!(token.contains("clientDataJson"));
    assert!(!token.contains("userHandle"));
    rp.finish_authentication(
        CredentialKind::SecurityKey,
        &started.state,
        token.as_bytes(),
        &[made.credential.as_slice()],
    )
    .expect("twoFactorToken as Bitwarden's client sends it");
}

#[test]
fn a_registration_state_and_a_stored_credential_are_plain_json_bytes() {
    let rp = rp();
    let mut authenticator = authenticator();
    let made = register(&rp, CredentialKind::Passkey, &mut authenticator);
    let credential: Value = serde_json::from_slice(&made.credential).expect("JSON");
    assert_eq!(credential["counter"], 0);
    assert_eq!(credential["cred_id"], b64url::encode(&made.credential_id));
    let started = start(&rp, CredentialKind::Passkey, &[]);
    assert!(serde_json::from_slice::<Value>(&started.state).is_ok());
}

// ---------------------------------------------------------------------------------------------
// Input that isn't WebAuthn.

#[test]
fn garbage_is_malformed_not_a_panic() {
    let rp = rp();
    let started = start(&rp, CredentialKind::Passkey, &[]);
    let malformed = |e: Result<_, WebAuthnError>| matches!(e, Err(WebAuthnError::Malformed(_)));

    assert!(malformed(
        rp.finish_registration(CredentialKind::Passkey, b"not a state", b"{}")
            .map(|_| ())
    ));
    assert!(malformed(
        rp.finish_registration(CredentialKind::Passkey, &started.state, b"not json")
            .map(|_| ())
    ));
    assert!(malformed(
        rp.finish_registration(CredentialKind::Passkey, &started.state, b"{\"id\":\"a\"}")
            .map(|_| ())
    ));
    assert!(malformed(rp.response_ids(b"[1, 2]").map(|_| ())));
    assert!(malformed(
        rp.start_authentication(CredentialKind::Passkey, &[b"not a credential".as_slice()])
            .map(|_| ())
    ));
    assert!(malformed(
        rp.finish_authentication(CredentialKind::Passkey, b"state", b"{}", &[])
            .map(|_| ())
    ));
}
