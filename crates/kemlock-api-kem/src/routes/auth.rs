//! Accounts and sign-in: prelogin, registration, OPAQUE login, the second step, refresh, TOTP.

use super::attempts;
use super::guard;
use super::new_device::announce;
use crate::dto::{
    EmailRequest, KdfDto, MethodsResponse, OpaqueFinishRequest, OpaqueStartRequest,
    OpaqueStartResponse, PreloginResponse, RecoveryCodeRequest, RecoveryCodeResponse,
    RefreshRequest, RegisterFinishRequest, RegisterFinishResponse, RegisterStartRequest,
    RegisterStartResponse, SignInResponse, SsoOffer, TokenResponse, TotpConfirmRequest,
    TotpEnrolResponse, TwoFactorRequest, decode,
};
use crate::extract::{Authed, Body, ClientIp, Proof, RefreshProof, SecureConnection};
use crate::problem::{Problem, rate_limited};
use crate::ratelimit::ip_key;
use crate::replay::Full;
use crate::signlog::{signed_in_ids, token_ids};
use crate::state::{Api, Crypto, Store};
use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use kemlock_app::ports::{TokenSigner, TwoFactorMethod};
use kemlock_app::sign_in::credential_id;
use kemlock_app::{
    AppError, OpaqueFinishInput, OpaqueStartInput, RegisterInput, RegisterStartInput,
    SecondStepInput, SignedIn, TokenPair, b64url,
};
use kemlock_crypto::hash;
use kemlock_domain::{Email, SetupError, UserId};

/// Registering with a setup grant makes the first admin, so it needs the same secure connection
/// the setup code did (HTTPS, or a browser on this machine). Ordinary sign-ups are not held to it.
fn require_secure_for_setup(setup_grant: Option<&str>, secure: bool) -> Result<(), Problem> {
    if setup_grant.is_some() && !secure {
        return Err(AppError::Setup(SetupError::InsecureContext).into());
    }
    Ok(())
}

/// Refuses an email longer than any address can be, before anything is keyed or stored by it.
fn check_email_len(email: &str) -> Result<(), Problem> {
    if email.len() > Email::MAX_LEN {
        return Err(Problem::bad_request("the email is too long"));
    }
    Ok(())
}

fn method_name(method: TwoFactorMethod) -> &'static str {
    method.as_str()
}

pub(super) fn token_response(tokens: &TokenPair, now: i64) -> TokenResponse {
    TokenResponse {
        token_type: "DPoP".to_owned(),
        access_token: tokens.access_token.clone(),
        expires_in: (tokens.access_expires_at.unix_timestamp() - now).max(0),
        refresh_token: tokens.refresh_token.clone(),
        refresh_expires_in: (tokens.refresh_expires_at.unix_timestamp() - now).max(0),
        user_id: tokens.user.0,
        device_id: tokens.device.0,
        admin: tokens.admin,
    }
}

impl<S: Store, P: Crypto, K: TokenSigner + Clone + 'static> Api<S, P, K> {
    /// `POST /kem/v1/auth/prelogin`: the KDF settings and salt for an email.
    pub(crate) async fn handle_prelogin(
        State(api): State<Self>,
        body: Body,
    ) -> Result<Json<PreloginResponse>, Problem> {
        let request: EmailRequest = body.json()?;
        let kdf = api.prelogin().execute(&request.email).await?;
        Ok(Json(PreloginResponse {
            kdf: KdfDto::from_params(&kdf),
        }))
    }

    /// `POST /kem/v1/auth/methods`: the ways in for an email: the password, and `"sso"` when a
    /// provider is set up for the email's domain. The answer never depends on whether the account
    /// exists.
    pub(crate) async fn handle_methods(
        State(api): State<Self>,
        body: Body,
    ) -> Result<Json<MethodsResponse>, Problem> {
        let request: EmailRequest = body.json()?;
        let mut methods = vec!["password".to_owned()];
        let sso = api
            .sign_in_methods()
            .sso_provider(&request.email)
            .await?
            .map(|provider_name| SsoOffer { provider_name });
        if sso.is_some() {
            methods.push("sso".to_owned());
        }
        Ok(Json(MethodsResponse { methods, sso }))
    }

    /// `POST /kem/v1/accounts/register/start`: OPAQUE registration, first message.
    pub(crate) async fn handle_register_start(
        State(api): State<Self>,
        ClientIp(ip): ClientIp,
        SecureConnection(secure): SecureConnection,
        body: Body,
    ) -> Result<Json<RegisterStartResponse>, Problem> {
        guard(&api.limits.register, &ip_key(ip), api.now())?;
        let request: RegisterStartRequest = body.json()?;
        require_secure_for_setup(request.setup_grant.as_deref(), secure)?;
        let invitation = api
            .accept_invitation(&request.email, request.invite_token.as_deref())
            .await?;
        let response = api
            .register_for(&request.email, invitation.is_some())
            .start(RegisterStartInput {
                email: request.email,
                request: decode("request", &request.request)?,
                setup_grant: request.setup_grant,
            })
            .await?;
        Ok(Json(RegisterStartResponse {
            response: b64url::encode(&response),
        }))
    }

    /// `POST /kem/v1/accounts/register/finish`: stores the account. Rate limited per IP like the
    /// start, under a key of its own so a registration costs one try of each.
    pub(crate) async fn handle_register_finish(
        State(api): State<Self>,
        ClientIp(ip): ClientIp,
        SecureConnection(secure): SecureConnection,
        body: Body,
    ) -> Result<(StatusCode, Json<RegisterFinishResponse>), Problem> {
        guard(
            &api.limits.register,
            &format!("finish:{}", ip_key(ip)),
            api.now(),
        )?;
        let request: RegisterFinishRequest = body.json()?;
        require_secure_for_setup(request.setup_grant.as_deref(), secure)?;
        let invitation = api
            .accept_invitation(&request.email, request.invite_token.as_deref())
            .await?;
        let registered = api
            .register_for(&request.email, invitation.is_some())
            .finish(RegisterInput {
                user: UserId(request.user_id),
                email: request.email,
                name: request.name,
                upload: decode("upload", &request.upload)?,
                kdf: request.kdf.to_params()?,
                public_bundle: decode("publicBundle", &request.public_bundle)?,
                bundle_signature: decode("bundleSignature", &request.bundle_signature)?,
                sealed_private_keys: decode("sealedPrivateKeys", &request.sealed_private_keys)?,
                wrapped_root_key: decode("wrappedRootKey", &request.wrapped_root_key)?,
                setup_grant: request.setup_grant,
            })
            .await?;
        // The account exists: the invitation is spent. A failure here leaves it pending, which
        // can't let anyone register again (the address is taken), so it is only logged.
        if let Some(invitation) = invitation {
            invitation.consume().await;
        }
        Ok((
            StatusCode::CREATED,
            Json(RegisterFinishResponse {
                user_id: registered.user.0,
                admin: registered.admin,
            }),
        ))
    }

    /// `POST /kem/v1/auth/opaque/start`: OPAQUE login, first message. Rate limited per IP: every
    /// password guess needs one of these. Not per account: anyone can start a login for any
    /// email, so counting starts against the account would let anyone lock it out. The account is
    /// limited by its failed finishes instead.
    pub(crate) async fn handle_opaque_start(
        State(api): State<Self>,
        proof: Proof,
        body: Body,
    ) -> Result<Json<OpaqueStartResponse>, Problem> {
        let request: OpaqueStartRequest = body.json()?;
        check_email_len(&request.email)?;
        guard(&api.limits.sign_in, &ip_key(proof.ip), api.now())?;
        // The login state is bound to the DPoP key that asks for it.
        let started = api
            .sign_in()
            .start(OpaqueStartInput {
                email: request.email,
                request: decode("request", &request.request)?,
                jkt: proof.jkt,
            })
            .await?;
        Ok(Json(OpaqueStartResponse {
            response: b64url::encode(&started.response),
            login_state: b64url::encode(&started.login_state),
        }))
    }

    /// `POST /kem/v1/auth/opaque/finish`: OPAQUE login, last message, with a DPoP proof whose key
    /// the device and its tokens are bound to. A wrong password counts against the account as seen
    /// from the address that sent it (10 in 15 minutes, then doubling delays, reserved before the
    /// password is looked at), so a stranger sending wrong passwords for someone's email only
    /// locks themselves out; what all addresses add up to only slows the account by a few
    /// seconds, and a right password always gets in from an address that hasn't run out. A right
    /// one clears the counts.
    pub(crate) async fn handle_opaque_finish(
        State(api): State<Self>,
        proof: Proof,
        body: Body,
    ) -> Result<Json<SignInResponse>, Problem> {
        let request: OpaqueFinishRequest = body.json()?;
        check_email_len(&request.email)?;
        let login_state = decode("loginState", &request.login_state)?;
        // Only a genuine, fresh login state gets as far as being counted or remembered, so
        // made-up ones spend nobody's attempts and take no room.
        api.sign_in().check_login_state(&login_state)?;
        // Wrong passwords count per account and source address, reserved before the password is
        // looked at: the name comes from the request, so a count on the name alone would let
        // anyone lock the owner out.
        let attempt = attempts::begin_password_attempt(
            &api,
            "acct",
            &credential_id(&request.email),
            proof.ip,
        )
        .await?;
        let device = request.device.into_info()?;
        // A login state finishes once, whether the password was right or not.
        match api.spend_open_state(proof.ip, &login_state, api.now()) {
            Ok(true) => {}
            Ok(false) => {
                return Err(Problem::bad_request("the login state was already used"));
            }
            Err(Full) => return Err(Problem::overloaded()),
        }
        let finished = api
            .sign_in()
            .finish(OpaqueFinishInput {
                email: request.email,
                login_state,
                finalization: decode("finalization", &request.finalization)?,
                device,
                jkt: proof.jkt,
            })
            .await;
        attempts::end_password_attempt(&api, &attempt, &finished);
        api.log_attempt(api.attempt("password", None, &finished, proof.ip, signed_in_ids))
            .await;
        let signed_in = finished?;
        if let SignedIn::SecondStep(step) = &signed_in {
            // A challenge is sealed, not stored, so nothing counts the open ones: an account is
            // given only so many in a while, or whoever holds the password could pile them up
            // to guess codes on.
            let user = api.sign_in().challenge_user(&step.challenge)?;
            api.limits
                .challenges
                .check(&format!("challenges:{user}"), api.now())
                .map_err(rate_limited)?;
        }
        if let SignedIn::Tokens(tokens) = &signed_in {
            announce(&api, tokens, proof.ip).await;
        }
        Ok(Json(match signed_in {
            SignedIn::Tokens(tokens) => SignInResponse {
                status: "signed_in".to_owned(),
                tokens: Some(token_response(&tokens, api.now())),
                challenge: None,
                methods: None,
            },
            SignedIn::SecondStep(step) => SignInResponse {
                status: "two_factor_required".to_owned(),
                tokens: None,
                challenge: Some(b64url::encode(&step.challenge)),
                methods: Some(
                    step.methods
                        .into_iter()
                        .map(|m| method_name(m).to_owned())
                        .collect(),
                ),
            },
        }))
    }

    /// `POST /kem/v1/auth/two-factor`: the second step, with the same DPoP key as the first.
    /// Limited per IP, per challenge and per account: a wrong code counts against the account
    /// (5 in 15 minutes, then doubling delays) however many challenges or addresses it uses.
    pub(crate) async fn handle_two_factor(
        State(api): State<Self>,
        proof: Proof,
        body: Body,
    ) -> Result<Json<TokenResponse>, Problem> {
        let request: TwoFactorRequest = body.json()?;
        let challenge = decode("challenge", &request.challenge)?;
        let now = api.now();
        guard(&api.limits.sign_in, &ip_key(proof.ip), now)?;
        let digest = hash::sha256(&challenge);
        guard(
            &api.limits.sign_in,
            &format!("challenge:{}", b64url::encode(&digest[..12])),
            now,
        )?;
        let method = match request.method.as_str() {
            "totp" => TwoFactorMethod::Totp,
            _ => return Err(Problem::bad_request("method must be \"totp\"")),
        };
        // A genuine, fresh challenge names the account its codes count against. The attempt is
        // reserved before the code is looked at, so parallel guesses can't all get past the limit.
        let user = api.sign_in().challenge_user(&challenge)?;
        attempts::reserve_second_step(&api, user, now).await?;
        let finished = api
            .sign_in()
            .second_step(SecondStepInput {
                challenge,
                method,
                code: request.code,
                jkt: proof.jkt,
            })
            .await;
        attempts::settle_second_step(&api, user, &finished).await;
        api.log_attempt(api.attempt("two-factor", Some(user), &finished, proof.ip, token_ids))
            .await;
        let tokens = finished?;
        announce(&api, &tokens, proof.ip).await;
        Ok(Json(token_response(&tokens, now)))
    }

    /// `POST /kem/v1/auth/token`: refresh. The refresh token rotates at every use. The proof is
    /// remembered only once the refresh token has worked, so proofs that lead nowhere take no
    /// room in the replay sets and can't be used to fill them.
    pub(crate) async fn handle_token(
        State(api): State<Self>,
        proof: RefreshProof,
        body: Body,
    ) -> Result<Json<TokenResponse>, Problem> {
        let request: RefreshRequest = body.json()?;
        if request.grant_type != "refresh_token" {
            return Err(Problem::bad_request("grantType must be \"refresh_token\""));
        }
        let refreshed = api
            .refresh()
            .execute(&request.refresh_token, &proof.jkt)
            .await;
        if refreshed.is_ok() {
            // A proof raced to the same end is refused here, and the refresh token's rotation
            // already decides which of two refreshes with one token wins.
            let _ = api.dpop.record(&proof.pending, api.now());
        }
        api.log_attempt(api.attempt("refresh", None, &refreshed, proof.ip, token_ids))
            .await;
        let tokens = refreshed?;
        Ok(Json(token_response(&tokens, api.now())))
    }

    /// `POST /kem/v1/account/two-factor/totp`: starts a TOTP enrolment.
    pub(crate) async fn handle_totp_enrol(
        State(api): State<Self>,
        authed: Authed,
    ) -> Result<Json<TotpEnrolResponse>, Problem> {
        let enrolment = api.enrol_totp().execute(authed.actor.user).await?;
        Ok(Json(TotpEnrolResponse {
            secret: enrolment.secret,
            uri: enrolment.uri,
        }))
    }

    /// `POST /kem/v1/account/two-factor/totp/confirm`: enables it with a code from the app.
    pub(crate) async fn handle_totp_confirm(
        State(api): State<Self>,
        authed: Authed,
        body: Body,
    ) -> Result<StatusCode, Problem> {
        let request: TotpConfirmRequest = body.json()?;
        let now = api.now();
        guard(&api.limits.sign_in, &ip_key(authed.ip), now)?;
        guard(
            &api.limits.sign_in,
            &format!("totp:{}", authed.actor.user),
            now,
        )?;
        // Beside another second step that is on, the recovery code proves it is the owner.
        super::two_step::require_proof_to_add_via_api(
            &api,
            authed.actor.user,
            Some(kemlock_app::ports::TwoFactorMethod::Totp),
            request.proof.as_ref(),
        )
        .await?;
        api.confirm_totp()
            .execute(authed.actor.user, &request.code)
            .await?;
        // The first second step an account turns on gives it a recovery code, as in Vaultwarden.
        api.recovery_codes().ensure(authed.actor.user).await?;
        Ok(StatusCode::NO_CONTENT)
    }

    /// `POST /kem/v1/account/two-factor/recovery-code`: the account's recovery code, for a signed-in
    /// device that proves it is the owner with a fresh proof that is not the recovery code (it
    /// proves removals and additions, so a session alone must not be able to read it). The
    /// Bitwarden API shows the same code for the master password.
    pub(crate) async fn handle_recovery_code(
        State(api): State<Self>,
        authed: Authed,
        body: Body,
    ) -> Result<Json<RecoveryCodeResponse>, Problem> {
        let request: RecoveryCodeRequest = if body.0.is_empty() {
            RecoveryCodeRequest::default()
        } else {
            body.json()?
        };
        let now = api.now();
        guard(&api.limits.sign_in, &ip_key(authed.ip), now)?;
        guard(
            &api.limits.sign_in,
            &format!("recovery-code:{}", authed.actor.user),
            now,
        )?;
        let code = api.recovery_codes().show(authed.actor.user).await?;
        // Nothing to give away without a code.
        if code.is_some() {
            super::two_step::require_proof_for_recovery_code(
                &api,
                authed.actor.user,
                request.proof.as_ref(),
            )
            .await?;
        }
        Ok(Json(RecoveryCodeResponse { code }))
    }
}
