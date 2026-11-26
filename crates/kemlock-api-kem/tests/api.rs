//! Router tests: every route in-process against the fakes, with real OPAQUE and DPoP.

mod common;

use axum::http::StatusCode;
use common::*;
use kemlock_domain::ItemId;
use serde_json::json;
use time::Duration;

// ---------------------------------------------------------------------------------------------
// Server, problems and limits

#[tokio::test]
async fn config_describes_the_server_and_setup() {
    let app = App::new(false);
    app.api.start_setup().await.expect("setup starts");
    let reply = app.client().get("/kem/v1/config").await;
    assert_eq!(reply.status, StatusCode::OK);
    let json = reply.json();
    assert_eq!(json["server"], "kemlock-server");
    assert_eq!(json["apiVersions"], json!(["v1"]));
    assert_eq!(json["version"], "0.0.0-test");
    assert_eq!(json["domain"], DOMAIN);
    assert_eq!(json["setup"], "needs-admin");
    assert_eq!(json["signupsAllowed"], false);
    assert_eq!(json["serverId"], app.store.server().to_string());
    assert!(json["features"].as_array().is_some_and(|f| !f.is_empty()));
    // The app hides Send creation on a server that does not list them.
    assert!(
        json["features"]
            .as_array()
            .is_some_and(|f| f.contains(&serde_json::json!("sends")))
    );
}

#[tokio::test]
async fn config_offers_the_licence_and_the_source_without_signing_in() {
    // AGPL-3.0 section 13: every user of the server is offered the source of the version running.
    let app = App::new(false);
    let reply = app.client().get("/kem/v1/config").await;
    assert_eq!(reply.status, StatusCode::OK);
    let json = reply.json();
    assert_eq!(json["license"], "AGPL-3.0-only");
    assert_eq!(json["sourceUrl"], "https://example.org/source/0123456");
    assert_eq!(json["commit"], "0123456789abcdef0123456789abcdef01234567");
}

#[tokio::test]
async fn every_response_carries_the_current_dpop_nonce() {
    let app = App::new(false);
    let reply = app.client().get("/kem/v1/config").await;
    let nonce = reply.header("dpop-nonce").expect("a nonce").to_owned();
    assert_eq!(nonce, app.api.dpop.current_nonce(app.now()));
}

#[tokio::test]
async fn the_openapi_document_names_every_route() {
    let app = App::new(false);
    let reply = app.client().get("/kem/v1/openapi.json").await;
    assert_eq!(reply.status, StatusCode::OK);
    let json = reply.json();
    assert!(
        json["openapi"]
            .as_str()
            .is_some_and(|v| v.starts_with("3.")),
        "{}",
        json["openapi"]
    );
    for (path, method) in [
        ("/kem/v1/config", "get"),
        ("/kem/v1/openapi.json", "get"),
        ("/kem/v1/setup/verify", "post"),
        ("/kem/v1/setup/finish", "post"),
        ("/kem/v1/auth/prelogin", "post"),
        ("/kem/v1/auth/methods", "post"),
        ("/kem/v1/accounts/register/start", "post"),
        ("/kem/v1/accounts/register/finish", "post"),
        ("/kem/v1/auth/opaque/start", "post"),
        ("/kem/v1/auth/opaque/finish", "post"),
        ("/kem/v1/auth/two-factor", "post"),
        ("/kem/v1/auth/token", "post"),
        ("/kem/v1/account/two-factor/totp", "post"),
        ("/kem/v1/account/two-factor/totp/confirm", "post"),
        ("/kem/v1/account/two-factor/recovery-code", "post"),
        ("/kem/v1/items/{id}", "put"),
        ("/kem/v1/items:batch", "post"),
        ("/kem/v1/owners/{owner}/signed-writes", "put"),
        ("/kem/v1/accounts/{id}/bundles/{version}", "get"),
        ("/kem/v1/sync", "get"),
        ("/kem/v1/sync", "post"),
        ("/kem/v1/live", "get"),
    ] {
        assert!(
            json["paths"][path][method].is_object(),
            "{method} {path} is documented"
        );
    }
    assert_eq!(
        json["components"]["securitySchemes"]["dpop"]["type"],
        "apiKey"
    );
    assert!(json["components"]["schemas"]["ItemDto"].is_object());
}

#[tokio::test]
async fn errors_are_problem_json() {
    let app = App::new(false);
    let client = app.client();
    let reply = client.get("/kem/v1/nope").await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
    assert!(reply.content_type().starts_with("application/problem+json"));
    assert_eq!(reply.problem(), "not-found");
    assert_eq!(reply.json()["status"], 404);

    let bad = client
        .send(
            "POST",
            "/kem/v1/auth/prelogin",
            Req {
                raw_body: Some(b"not json".to_vec()),
                ..Req::default()
            },
        )
        .await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);
    assert_eq!(bad.problem(), "invalid-request");
    assert!(bad.content_type().starts_with("application/problem+json"));
}

#[tokio::test]
async fn bodies_refuse_unknown_fields() {
    let app = App::new(false);
    let reply = app
        .client()
        .post(
            "/kem/v1/auth/prelogin",
            json!({"email": "a@example.org", "extra": 1}),
        )
        .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_body_over_two_mebibytes_is_refused() {
    let app = App::new(false);
    let reply = app
        .client()
        .send(
            "POST",
            "/kem/v1/auth/prelogin",
            Req {
                raw_body: Some(vec![b' '; 2 * 1024 * 1024 + 1]),
                ..Req::default()
            },
        )
        .await;
    assert_eq!(reply.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(reply.problem(), "payload-too-large");

    // Just under the cap is read (and refused as malformed JSON, not as too large).
    let reply = app
        .client()
        .send(
            "POST",
            "/kem/v1/auth/prelogin",
            Req {
                raw_body: Some(vec![b' '; 2 * 1024 * 1024]),
                ..Req::default()
            },
        )
        .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
}

async fn prelogin(client: &Client, email: &str) -> Reply {
    client
        .post("/kem/v1/auth/prelogin", json!({ "email": email }))
        .await
}

#[tokio::test]
async fn prelogin_answers_for_unknown_emails_with_a_stable_fake() {
    let app = App::new(false);
    let client = app.client();
    let first = prelogin(&client, "ghost@example.org").await;
    let second = prelogin(&client, "ghost@example.org").await;
    assert_eq!(first.status, StatusCode::OK);
    assert_eq!(first.json(), second.json());
    let first_json = first.json();
    let kdf = &first_json["kdf"];
    assert_eq!(kdf["memoryKib"], 65536);
    assert_eq!(kdf["iterations"], 3);
    assert_eq!(kdf["parallelism"], 4);
    assert_eq!(unb64(kdf["salt"].as_str().expect("salt")).len(), 16);
    assert_ne!(
        first.json(),
        prelogin(&client, "other@example.org").await.json()
    );
}

#[tokio::test]
async fn methods_never_depend_on_the_account() {
    let app = App::new(true);
    let client = app.client();
    register_and_sign_in(&client, "sam@example.org").await;
    let known = client
        .post("/kem/v1/auth/methods", json!({"email": "sam@example.org"}))
        .await;
    let unknown = client
        .post(
            "/kem/v1/auth/methods",
            json!({"email": "ghost@example.org"}),
        )
        .await;
    assert_eq!(known.json(), unknown.json());
    assert_eq!(known.json()["methods"], json!(["password"]));
}

#[tokio::test]
async fn methods_list_sso_when_a_provider_is_set_up_for_the_domain() {
    use kemlock_app::ports::Clock;
    use kemlock_app::sso::SsoSettings;
    let app = App::new(true);
    let client = app.client();
    let methods = |email: &'static str| {
        let client = &client;
        async move {
            client
                .post("/kem/v1/auth/methods", json!({"email": email}))
                .await
                .json()["methods"]
                .clone()
        }
    };
    assert_eq!(methods("sam@example.org").await, json!(["password"]));

    let mut settings = SsoSettings::new("https://idp.test", "kemlock", app.crypto.now());
    app.store.set_sso(settings.clone());
    assert_eq!(methods("sam@example.org").await, json!(["password", "sso"]));
    // The answer is the same for an account that doesn't exist.
    assert_eq!(
        methods("ghost@example.org").await,
        json!(["password", "sso"])
    );

    // With verified domains required, only a proven domain is offered SSO.
    settings.require_verified_domain = true;
    app.store.set_sso(settings);
    assert_eq!(methods("sam@example.org").await, json!(["password"]));
    app.store
        .add_verified_domain("example.org", app.crypto.now());
    assert_eq!(methods("sam@example.org").await, json!(["password", "sso"]));
    assert_eq!(methods("sam@other.net").await, json!(["password"]));
}

#[tokio::test]
async fn methods_name_the_provider_the_same_for_every_email() {
    use kemlock_app::ports::Clock;
    use kemlock_app::sso::SsoSettings;
    let app = App::new(true);
    let client = app.client();
    register_and_sign_in(&client, "sam@example.org").await;
    let answer = |email: &'static str| {
        let client = &client;
        async move {
            client
                .post("/kem/v1/auth/methods", json!({"email": email}))
                .await
                .json()
        }
    };

    // No provider: no `sso` member at all, and never `ssoRequired`.
    let none = answer("sam@example.org").await;
    assert!(none.get("sso").is_none(), "{none}");
    assert!(none.get("ssoRequired").is_none(), "{none}");

    let mut settings = SsoSettings::new(
        "https://idp.test:8443/realms/k",
        "kemlock",
        app.crypto.now(),
    );
    settings.display_name = "Example Co".to_owned();
    app.store.set_sso(settings.clone());
    let known = answer("sam@example.org").await;
    assert_eq!(known["sso"], json!({"providerName": "Example Co"}));
    assert_eq!(known["methods"], json!(["password", "sso"]));
    assert!(known.get("ssoRequired").is_none(), "{known}");
    // An account that doesn't exist, and an email in another domain, get the identical answer.
    assert_eq!(answer("ghost@example.org").await, known);
    assert_eq!(answer("anyone@elsewhere.net").await, known);

    // A blank name is the issuer's host.
    settings.display_name = String::new();
    app.store.set_sso(settings.clone());
    assert_eq!(
        answer("sam@example.org").await["sso"],
        json!({"providerName": "idp.test"})
    );

    // With verified domains required, only a proven domain is offered it.
    settings.require_verified_domain = true;
    app.store.set_sso(settings);
    assert!(answer("sam@example.org").await.get("sso").is_none());
    app.store
        .add_verified_domain("example.org", app.crypto.now());
    assert_eq!(
        answer("sam@example.org").await["sso"],
        json!({"providerName": "idp.test"})
    );
    assert_eq!(
        answer("ghost@example.org").await,
        answer("sam@example.org").await
    );
    assert!(answer("sam@other.net").await.get("sso").is_none());
}

#[tokio::test]
async fn a_space_that_requires_sso_closes_the_password_to_its_members() {
    use kemlock_app::sso::{SpaceMembership, SpaceRole};
    let app = App::new(true);
    let client = app.client();
    let (reply, user) = register(&client, "sam@example.org", None).await;
    assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.json());
    let space = kemlock_domain::SpaceId::random();
    app.store.set_memberships(
        user,
        vec![SpaceMembership {
            space,
            role: SpaceRole::Member,
            require_sso: true,
        }],
    );

    let refused = sign_in_reply(&client, "sam@example.org", test_device()).await;
    assert_eq!(
        refused.status,
        StatusCode::FORBIDDEN,
        "{:?}",
        refused.json()
    );
    assert_eq!(refused.problem(), "sso-required");
    assert_eq!(refused.json()["spaceId"], space.to_string());

    // An owner of the same space still gets in: someone can always repair the provider.
    app.store.set_memberships(
        user,
        vec![SpaceMembership {
            space,
            role: SpaceRole::Owner,
            require_sso: true,
        }],
    );
    let signed = sign_in_reply(&client, "sam@example.org", test_device()).await;
    assert_eq!(signed.status, StatusCode::OK, "{:?}", signed.json());
}
#[tokio::test]
async fn sign_in_start_is_rate_limited_with_doubling_delays() {
    let app = App::new(false);
    let client = app.client();
    let body = json!({"email": "a@example.org", "request": "AAAA"});
    for _ in 0..10 {
        let reply = client.post("/kem/v1/auth/opaque/start", body.clone()).await;
        assert_ne!(reply.status, StatusCode::TOO_MANY_REQUESTS);
    }
    let limited = client.post("/kem/v1/auth/opaque/start", body.clone()).await;
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(limited.problem(), "rate-limited");
    assert_eq!(limited.header("retry-after"), Some("1"));
    assert!(
        limited
            .content_type()
            .starts_with("application/problem+json")
    );

    // Each further try doubles the wait.
    let again = client.post("/kem/v1/auth/opaque/start", body.clone()).await;
    assert_eq!(again.header("retry-after"), Some("1"));
    app.clock.advance(Duration::seconds(1));
    let later = client.post("/kem/v1/auth/opaque/start", body.clone()).await;
    assert_eq!(later.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(later.header("retry-after"), Some("2"));
}

/// Both OPAQUE login messages for `email` with `password`, from `peer`; the reply to the finish.
async fn sign_in_from(
    client: &Client,
    email: &str,
    password: &[u8],
    peer: std::net::SocketAddr,
) -> Reply {
    let (state, request) =
        kemlock_crypto::opaque::client_login_start(password).expect("client login start");
    let started = client
        .send(
            "POST",
            "/kem/v1/auth/opaque/start",
            Req {
                body: Some(json!({"email": email, "request": b64(&request)})),
                peer: Some(peer),
                ..Req::default()
            },
        )
        .await;
    assert_eq!(started.status, StatusCode::OK, "{:?}", started.json());
    let started = started.json();
    let response = unb64(started["response"].as_str().expect("response"));
    let finalization = match kemlock_crypto::opaque::client_login_finish(state, password, &response)
    {
        Ok((finalization, _, _)) => finalization,
        // A wrong password can fail on the client side already; send garbage then.
        Err(_) => vec![7u8; 64],
    };
    client
        .send(
            "POST",
            "/kem/v1/auth/opaque/finish",
            Req {
                body: Some(json!({
                    "email": email,
                    "loginState": started["loginState"],
                    "finalization": b64(&finalization),
                    "device": test_device(),
                })),
                peer: Some(peer),
                ..Req::default()
            },
        )
        .await
}

fn peer(n: u8) -> std::net::SocketAddr {
    std::net::SocketAddr::from(([10, 0, 0, n], 40_000))
}

/// The body of an `opaque/finish` for `email` with `password`, after a start made with the
/// DPoP key of `client`.
async fn finish_body(client: &Client, email: &str, password: &[u8]) -> serde_json::Value {
    let (state, request) =
        kemlock_crypto::opaque::client_login_start(password).expect("client login start");
    let started = client
        .post(
            "/kem/v1/auth/opaque/start",
            json!({"email": email, "request": b64(&request)}),
        )
        .await;
    assert_eq!(started.status, StatusCode::OK, "{:?}", started.json());
    let started = started.json();
    let response = unb64(started["response"].as_str().expect("response"));
    let (finalization, _, _) =
        kemlock_crypto::opaque::client_login_finish(state, password, &response)
            .expect("client login finish");
    json!({
        "email": email,
        "loginState": started["loginState"],
        "finalization": b64(&finalization),
        "device": test_device(),
    })
}

fn user_id_of(app: &App, email: &str) -> kemlock_domain::UserId {
    app.store
        .user_by_email(email)
        .expect("the account exists")
        .id
}

#[tokio::test]
async fn a_login_state_finishes_once() {
    let app = App::new(true);
    let client = app.client();
    register(&client, "sam@example.org", None).await;
    let body = finish_body(&client, "sam@example.org", &PASSWORD).await;

    let first = client
        .post("/kem/v1/auth/opaque/finish", body.clone())
        .await;
    assert_eq!(first.status, StatusCode::OK, "{:?}", first.json());
    // The same state and finalization again, by the same key: a replay, whatever the password.
    let again = client.post("/kem/v1/auth/opaque/finish", body).await;
    assert_eq!(again.status, StatusCode::BAD_REQUEST, "{:?}", again.json());
    assert_eq!(again.problem(), "invalid-request");
    assert!(
        again.json()["detail"]
            .as_str()
            .is_some_and(|d| d.contains("already used"))
    );
}

#[tokio::test]
async fn a_login_state_is_bound_to_the_dpop_key_that_started_it() {
    let app = App::new(true);
    let phone = app.client();
    register(&phone, "sam@example.org", None).await;
    let body = finish_body(&phone, "sam@example.org", &PASSWORD).await;

    // A second device key, holding a copy of the body, can't finish the login of the phone.
    let thief = app.client();
    let stolen = thief.post("/kem/v1/auth/opaque/finish", body.clone()).await;
    assert_eq!(
        stolen.status,
        StatusCode::UNAUTHORIZED,
        "{:?}",
        stolen.json()
    );
    assert_eq!(stolen.problem(), "unauthorized");
    assert!(
        app.store
            .devices_of(user_id_of(&app, "sam@example.org"))
            .is_empty()
    );

    // The attempt burned the state, so even the phone has to start again; then it signs in.
    let burned = phone.post("/kem/v1/auth/opaque/finish", body).await;
    assert_eq!(burned.status, StatusCode::BAD_REQUEST);
    let fresh = finish_body(&phone, "sam@example.org", &PASSWORD).await;
    let ok = phone.post("/kem/v1/auth/opaque/finish", fresh).await;
    assert_eq!(ok.status, StatusCode::OK, "{:?}", ok.json());
}

#[tokio::test]
async fn asking_for_logins_never_slows_an_account_down_from_other_addresses() {
    let app = App::new(true);
    let client = app.client();
    register_and_sign_in(&client, "sam@example.org").await;
    // Twenty starts for the same email, each from its own address: the per-IP limit never
    // trips, and nothing may be counted against the account, or anyone could lock sam out.
    for n in 1..=20u8 {
        let (_, request) = kemlock_crypto::opaque::client_login_start(&PASSWORD).expect("start");
        let reply = client
            .send(
                "POST",
                "/kem/v1/auth/opaque/start",
                Req {
                    body: Some(json!({"email": "sam@example.org", "request": b64(&request)})),
                    peer: Some(peer(n)),
                    ..Req::default()
                },
            )
            .await;
        assert_eq!(reply.status, StatusCode::OK, "start {n}");
    }
    // And sam, from yet another address, still signs in.
    let ok = sign_in_from(&client, "sam@example.org", &PASSWORD, peer(99)).await;
    assert_eq!(ok.status, StatusCode::OK, "{:?}", ok.json());
}

#[tokio::test]
async fn wrong_passwords_lock_out_only_the_address_that_sent_them() {
    let app = App::new(true);
    let client = app.client();
    register_and_sign_in(&client, "sam@example.org").await;
    app.api.limits.account.set_limit(3);
    let wrong = [9u8; 32];
    // A stranger sends wrong passwords for sam's email: three, then they wait, even with the
    // right password, because the count is theirs.
    for n in 1..=3 {
        let reply = sign_in_from(&client, "sam@example.org", &wrong, peer(1)).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "try {n}");
        assert_eq!(reply.problem(), "unauthorized");
    }
    let waiting = sign_in_from(&client, "sam@example.org", &PASSWORD, peer(1)).await;
    assert_eq!(waiting.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(waiting.problem(), "rate-limited");
    assert_eq!(waiting.header("retry-after"), Some("1"));
    // Sam, from another address, signs in at once: the stranger's count is not sam's.
    let ok = sign_in_from(&client, "sam@example.org", &PASSWORD, peer(2)).await;
    assert_eq!(ok.status, StatusCode::OK, "{:?}", ok.json());
    // Another account is not affected either, and after the wait the stranger gets a try again.
    register(&client, "alex@example.org", None).await;
    let other = sign_in_from(&client, "alex@example.org", &PASSWORD, peer(1)).await;
    assert_eq!(other.status, StatusCode::OK, "{:?}", other.json());
    app.clock.advance(Duration::seconds(1));
    let again = sign_in_from(&client, "sam@example.org", &wrong, peer(1)).await;
    assert_eq!(again.status, StatusCode::UNAUTHORIZED);
    let doubled = sign_in_from(&client, "sam@example.org", &wrong, peer(1)).await;
    assert_eq!(doubled.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(doubled.header("retry-after"), Some("2"));
}

#[tokio::test]
async fn wrong_passwords_from_many_addresses_only_slow_the_account_and_the_right_one_gets_in() {
    let app = App::new(true);
    let client = app.client();
    register_and_sign_in(&client, "sam@example.org").await;
    let wrong = [9u8; 32];
    // Ten wrong passwords, each from another address, so no hard limit is involved.
    for n in 1..=10u8 {
        let reply = sign_in_from(&client, "sam@example.org", &wrong, peer(n)).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "try {n}");
    }
    // The account is slowed now, whoever asks: the right password still signs in, a moment late.
    let started = std::time::Instant::now();
    let ok = sign_in_from(&client, "sam@example.org", &PASSWORD, peer(50)).await;
    assert_eq!(ok.status, StatusCode::OK, "{:?}", ok.json());
    assert!(
        started.elapsed() >= std::time::Duration::from_millis(900),
        "held back about a second: {:?}",
        started.elapsed()
    );
    // And a right password clears the slowdown.
    let started = std::time::Instant::now();
    let again = sign_in_from(&client, "sam@example.org", &PASSWORD, peer(51)).await;
    assert_eq!(again.status, StatusCode::OK, "{:?}", again.json());
    assert!(started.elapsed() < std::time::Duration::from_millis(500));
}

#[tokio::test]
async fn wrong_passwords_spread_over_many_addresses_are_capped_for_the_account() {
    let app = App::new(true);
    let client = app.client();
    register_and_sign_in(&client, "sam@example.org").await;
    app.api.limits.account_cap.set_limit(5);
    let wrong = [9u8; 32];
    // Five wrong passwords, each from its own address, so no per-address limit is involved.
    for n in 1..=5u8 {
        let reply = sign_in_from(&client, "sam@example.org", &wrong, peer(n)).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "try {n}");
    }
    // Past the cap the account's password checks are refused for everyone, a right password
    // included, until the wait is over.
    let refused = sign_in_from(&client, "sam@example.org", &PASSWORD, peer(50)).await;
    assert_eq!(refused.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(refused.problem(), "rate-limited");
    // Another account is not affected.
    register(&client, "alex@example.org", None).await;
    let other = sign_in_from(&client, "alex@example.org", &PASSWORD, peer(51)).await;
    assert_eq!(other.status, StatusCode::OK, "{:?}", other.json());
    app.clock.advance(Duration::seconds(1));
    let ok = sign_in_from(&client, "sam@example.org", &PASSWORD, peer(52)).await;
    assert_eq!(ok.status, StatusCode::OK, "{:?}", ok.json());
}

#[tokio::test]
async fn made_up_login_states_spend_no_one_s_attempts() {
    let app = App::new(true);
    let client = app.client();
    register_and_sign_in(&client, "sam@example.org").await;
    app.api.limits.account.set_limit(3);
    app.api.limits.account_cap.set_limit(3);
    // Twenty finishes with login states nobody made, from one address: refused as bad requests
    // before anything is counted.
    for n in 0..20 {
        let reply = client
            .send(
                "POST",
                "/kem/v1/auth/opaque/finish",
                Req {
                    body: Some(json!({
                        "email": "sam@example.org",
                        "loginState": b64(&[n as u8; 64]),
                        "finalization": b64(&[7u8; 64]),
                        "device": test_device(),
                    })),
                    peer: Some(peer(1)),
                    ..Req::default()
                },
            )
            .await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "try {n}");
    }
    // Neither that address nor the account is the worse for it.
    let ok = sign_in_from(&client, "sam@example.org", &PASSWORD, peer(1)).await;
    assert_eq!(ok.status, StatusCode::OK, "{:?}", ok.json());
}

/// Registers `email` (signups on), enrols and confirms a TOTP method, and returns its secret.
async fn two_step_account(app: &App, client: &Client, email: &str) -> String {
    let session = register_and_sign_in(client, email).await;
    let enrol = client
        .send(
            "POST",
            "/kem/v1/account/two-factor/totp",
            Req {
                access_token: Some(&session.access_token),
                ..Req::default()
            },
        )
        .await;
    assert_eq!(enrol.status, StatusCode::OK, "{:?}", enrol.json());
    let secret = enrol.json()["secret"].as_str().expect("secret").to_owned();
    let confirmed = client
        .post_authed(
            "/kem/v1/account/two-factor/totp/confirm",
            &session.access_token,
            json!({"code": totp_now(app, &secret)}),
        )
        .await;
    assert_eq!(confirmed.status, StatusCode::NO_CONTENT);
    secret
}

/// A six-digit code that is wrong for the secret now, one step either side included.
fn wrong_code(app: &App, secret: &str) -> String {
    let now = u64::try_from(app.now()).expect("a positive time");
    let key = base32_decode(secret);
    let valid: Vec<String> = [now - 30, now, now + 30]
        .into_iter()
        .map(|t| kemlock_crypto::totp::code_at(&key, t))
        .collect();
    (0..1000)
        .map(|n| format!("{n:06}"))
        .find(|c| !valid.contains(c))
        .expect("a wrong code exists")
}

/// The password step of a two-step account from `peer`; returns the challenge.
async fn challenge_from(client: &Client, email: &str, peer: std::net::SocketAddr) -> String {
    let reply = sign_in_from(client, email, &PASSWORD, peer).await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.json());
    assert_eq!(reply.json()["status"], "two_factor_required");
    reply.json()["challenge"]
        .as_str()
        .expect("challenge")
        .to_owned()
}

async fn second_step_from(
    client: &Client,
    challenge: &str,
    code: &str,
    peer: std::net::SocketAddr,
) -> Reply {
    client
        .send(
            "POST",
            "/kem/v1/auth/two-factor",
            Req {
                body: Some(json!({"challenge": challenge, "method": "totp", "code": code})),
                peer: Some(peer),
                ..Req::default()
            },
        )
        .await
}

#[tokio::test]
async fn wrong_second_step_codes_slow_the_account_down_whatever_challenge_or_address() {
    let app = App::new(true);
    let client = app.client();
    let secret = two_step_account(&app, &client, "sam@example.org").await;

    // Five wrong codes, each on a fresh challenge from a fresh address: none of the per-IP or
    // per-challenge limits is anywhere near its limit, but they all count against sam.
    for n in 1..=5u8 {
        let challenge = challenge_from(&client, "sam@example.org", peer(n)).await;
        let wrong = wrong_code(&app, &secret);
        let reply = second_step_from(&client, &challenge, &wrong, peer(n)).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "try {n}");
    }
    // The sixth try waits, even with the right code on a fresh challenge from a fresh address.
    let challenge = challenge_from(&client, "sam@example.org", peer(60)).await;
    let right = totp_now(&app, &secret);
    let waiting = second_step_from(&client, &challenge, &right, peer(60)).await;
    assert_eq!(waiting.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(waiting.problem(), "rate-limited");
    assert_eq!(waiting.header("retry-after"), Some("1"));

    // After the delay the right code works, and clears the count.
    app.clock.advance(Duration::seconds(1));
    let challenge = challenge_from(&client, "sam@example.org", peer(61)).await;
    let right = totp_now(&app, &secret);
    let ok = second_step_from(&client, &challenge, &right, peer(61)).await;
    assert_eq!(ok.status, StatusCode::OK, "{:?}", ok.json());
}

#[tokio::test]
async fn second_step_attempts_are_counted_in_the_store_so_every_replica_sees_them() {
    let app = App::new(true);
    let client = app.client();
    let secret = two_step_account(&app, &client, "sam@example.org").await;
    for n in 1..=5u8 {
        let challenge = challenge_from(&client, "sam@example.org", peer(n)).await;
        let wrong = wrong_code(&app, &secret);
        let reply = second_step_from(&client, &challenge, &wrong, peer(n)).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "try {n}");
    }
    // Another replica of the same deployment has memory of its own and the same database: it
    // turns the account away too, even with the right code.
    let other = app.replica_client();
    let challenge = challenge_from(&other, "sam@example.org", peer(70)).await;
    let right = totp_now(&app, &secret);
    let waiting = second_step_from(&other, &challenge, &right, peer(70)).await;
    assert_eq!(waiting.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(waiting.problem(), "rate-limited");
    assert_eq!(waiting.header("retry-after"), Some("1"));

    // After the wait the right code works there, and clears the count for both.
    app.clock.advance(Duration::seconds(1));
    let challenge = challenge_from(&other, "sam@example.org", peer(71)).await;
    let right = totp_now(&app, &secret);
    let ok = second_step_from(&other, &challenge, &right, peer(71)).await;
    assert_eq!(ok.status, StatusCode::OK, "{:?}", ok.json());
    let wrong = wrong_code(&app, &secret);
    let challenge = challenge_from(&client, "sam@example.org", peer(72)).await;
    let again = second_step_from(&client, &challenge, &wrong, peer(72)).await;
    assert_eq!(
        again.status,
        StatusCode::UNAUTHORIZED,
        "the count started again"
    );
}

#[tokio::test]
async fn an_account_is_given_only_so_many_second_step_challenges_in_a_while() {
    let app = App::new(true);
    let client = app.client();
    two_step_account(&app, &client, "sam@example.org").await;
    // Whoever holds the password can ask for challenges, each a place to guess codes on; each
    // from its own address, so no per-address limit is involved.
    for n in 1..=10u8 {
        challenge_from(&client, "sam@example.org", peer(n)).await;
    }
    let eleventh = sign_in_from(&client, "sam@example.org", &PASSWORD, peer(11)).await;
    assert_eq!(eleventh.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(eleventh.problem(), "rate-limited");
    // A challenge lives five minutes; some time on, the account is given another.
    app.clock.advance(Duration::seconds(301));
    challenge_from(&client, "sam@example.org", peer(12)).await;
}

#[tokio::test]
async fn a_second_step_code_works_once_and_a_replay_is_unauthorized() {
    let app = App::new(true);
    let client = app.client();
    let secret = two_step_account(&app, &client, "sam@example.org").await;
    let code = totp_now(&app, &secret);

    let challenge = challenge_from(&client, "sam@example.org", peer(1)).await;
    let first = second_step_from(&client, &challenge, &code, peer(1)).await;
    assert_eq!(first.status, StatusCode::OK, "{:?}", first.json());

    // The same code on a second sign-in, inside its window.
    let challenge = challenge_from(&client, "sam@example.org", peer(2)).await;
    let replay = second_step_from(&client, &challenge, &code, peer(2)).await;
    assert_eq!(
        replay.status,
        StatusCode::UNAUTHORIZED,
        "{:?}",
        replay.json()
    );
    assert_eq!(replay.problem(), "unauthorized");
}

#[tokio::test]
async fn an_overlong_email_is_refused_before_it_is_counted_under_any_key() {
    let app = App::new(false);
    let client = app.client();
    let huge = format!("{}@example.org", "a".repeat(100_000));
    let reply = client
        .post(
            "/kem/v1/auth/opaque/start",
            json!({"email": huge, "request": "AAAA"}),
        )
        .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert_eq!(reply.problem(), "invalid-request");
    // The refusal did not use up a try: ten more still pass the limiter.
    let body = json!({"email": "a@example.org", "request": "AAAA"});
    for _ in 0..10 {
        let again = client.post("/kem/v1/auth/opaque/start", body.clone()).await;
        assert_ne!(again.status, StatusCode::TOO_MANY_REQUESTS);
    }
}

#[tokio::test]
async fn registration_is_limited_per_ip() {
    let app = App::new(false);
    let client = app.client();
    let body = json!({"email": "a@example.org", "request": "AAAA"});
    for _ in 0..10 {
        let reply = client
            .post("/kem/v1/accounts/register/start", body.clone())
            .await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN);
    }
    let limited = client.post("/kem/v1/accounts/register/start", body).await;
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
}

// ---------------------------------------------------------------------------------------------
// First-run setup and registration

#[tokio::test]
async fn registration_finish_is_limited_per_ip_like_the_start() {
    let app = App::new(true);
    let client = app.client();
    // Bodies that fail validation still cost a try: every finish pays for OPAQUE and a database
    // write when it succeeds, so it can't be free to hammer.
    for _ in 0..10 {
        let reply = client
            .post("/kem/v1/accounts/register/finish", json!({}))
            .await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    }
    let limited = client
        .post("/kem/v1/accounts/register/finish", json!({}))
        .await;
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(limited.problem(), "rate-limited");
    // The start has its own count: the finish didn't use it up.
    let start = client
        .post(
            "/kem/v1/accounts/register/start",
            json!({"email": "a@example.org", "request": "AAAA"}),
        )
        .await;
    assert_ne!(start.status, StatusCode::TOO_MANY_REQUESTS);
}

/// A peer on this machine, for first-run setup: `127.0.0.<n>`.
fn local(n: u8) -> std::net::SocketAddr {
    std::net::SocketAddr::from(([127, 0, 0, n], 40_000))
}

/// `POST /setup/verify` with `code`, from `peer`, plus `headers`.
async fn verify_setup(
    client: &Client,
    code: &str,
    peer: Option<std::net::SocketAddr>,
    headers: Vec<(&str, String)>,
) -> Reply {
    client
        .send(
            "POST",
            "/kem/v1/setup/verify",
            Req {
                headers,
                body: Some(json!({ "code": code })),
                peer,
                ..Req::default()
            },
        )
        .await
}

async fn app_with_setup_code(app: &App) -> String {
    app.api
        .start_setup()
        .await
        .expect("setup starts")
        .expect("a code")
        .as_display()
}

#[tokio::test]
async fn setup_needs_a_secure_context() {
    let app = App::new(false);
    let code = app_with_setup_code(&app).await;
    let client = app.client();

    // A browser on another machine is not a secure context, whatever Origin or Host it writes.
    let lying = vec![
        ("origin", "http://localhost:8080".to_owned()),
        ("host", "localhost:8080".to_owned()),
    ];
    for (peer, headers) in [
        (Some(peer(5)), vec![]),
        (Some(peer(5)), lying.clone()),
        // No peer address at all counts as not local.
        (None, lying),
    ] {
        let insecure = verify_setup(&client, &code, peer, headers).await;
        assert_eq!(insecure.status, StatusCode::FORBIDDEN, "{peer:?}");
        assert_eq!(insecure.problem(), "insecure-context");
    }

    // A browser on this machine is, with the Origin of a deployment that says otherwise.
    let origin = vec![("origin", "https://elsewhere.example".to_owned())];
    let local = verify_setup(&client, &code, Some(local(1)), origin).await;
    assert_eq!(local.status, StatusCode::OK, "{:?}", local.json());
    assert!(
        local.json()["grant"]
            .as_str()
            .is_some_and(|g| !g.is_empty())
    );
    assert_eq!(local.json()["expiresIn"], 900);
}

#[tokio::test]
async fn a_loopback_proxy_that_is_not_trusted_does_not_make_clients_local() {
    // nginx on the same host forwards every client from 127.0.0.1: without being named as a
    // trusted proxy it must not turn them all into local browsers.
    let app = App::new(false);
    let code = app_with_setup_code(&app).await;
    let client = app.client();
    let forwarded = vec![("x-forwarded-for", "198.51.100.9".to_owned())];
    let reply = verify_setup(&client, &code, Some(local(1)), forwarded).await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(reply.problem(), "insecure-context");
}

#[tokio::test]
async fn a_trusted_proxy_that_says_https_makes_the_connection_secure() {
    let proxy: std::net::IpAddr = "10.0.0.1".parse().expect("an address");
    let app = App::behind(false, vec![proxy]);
    let code = app_with_setup_code(&app).await;
    let client = app.client();
    let from_proxy = Some(std::net::SocketAddr::from((proxy, 40_000)));

    let http = vec![("x-forwarded-proto", "http".to_owned())];
    let plain = verify_setup(&client, &code, from_proxy, http).await;
    assert_eq!(plain.problem(), "insecure-context");
    let silent = verify_setup(&client, &code, from_proxy, vec![]).await;
    assert_eq!(silent.problem(), "insecure-context");

    // The same header from a peer that isn't a trusted proxy is only a claim.
    let https = vec![("x-forwarded-proto", "https".to_owned())];
    let stranger = verify_setup(&client, &code, Some(peer(9)), https.clone()).await;
    assert_eq!(stranger.problem(), "insecure-context");

    let secure = verify_setup(&client, &code, from_proxy, https).await;
    assert_eq!(secure.status, StatusCode::OK, "{:?}", secure.json());
}

#[tokio::test]
async fn registering_with_a_setup_grant_needs_a_secure_connection_too() {
    let app = App::new(false);
    let code = app_with_setup_code(&app).await;
    let local_client = app.local_client();
    let grant = verify_setup(&local_client, &code, None, vec![])
        .await
        .json()["grant"]
        .as_str()
        .expect("a grant")
        .to_owned();

    // The grant in the hands of a remote client buys nothing, at either step.
    let remote = app.client();
    let start = remote
        .post(
            "/kem/v1/accounts/register/start",
            json!({"email": "admin@example.org", "request": "AAAA", "setupGrant": grant}),
        )
        .await;
    assert_eq!(start.status, StatusCode::FORBIDDEN, "{:?}", start.json());
    assert_eq!(start.problem(), "insecure-context");
    let user = kemlock_domain::UserId::random();
    let finish = remote
        .post(
            "/kem/v1/accounts/register/finish",
            json!({
                "userId": user.to_string(), "email": "admin@example.org", "upload": "AAAA",
                "kdf": {"memoryKib": 65536, "iterations": 3, "parallelism": 4, "salt": "AAAA"},
                "publicBundle": "AAAA", "bundleSignature": "AAAA",
                "sealedPrivateKeys": "AAAA", "wrappedRootKey": "AAAA",
                "setupGrant": grant,
            }),
        )
        .await;
    assert_eq!(finish.status, StatusCode::FORBIDDEN, "{:?}", finish.json());
    assert_eq!(finish.problem(), "insecure-context");
    assert!(app.store.user_by_email("admin@example.org").is_none());

    // From this machine it works.
    let (created, _) = register(&local_client, "admin@example.org", Some(&grant)).await;
    assert_eq!(created.status, StatusCode::CREATED, "{:?}", created.json());
}

#[tokio::test]
async fn wrong_setup_codes_slow_down_and_are_rate_limited() {
    let app = App::new(false);
    app.api.start_setup().await.expect("setup starts");
    let client = app.local_client();
    let mut statuses = Vec::new();
    let mut last = None;
    for _ in 0..6 {
        let reply = client
            .post("/kem/v1/setup/verify", json!({"code": "ZZZZ-ZZZZ-ZZZZ"}))
            .await;
        statuses.push(reply.status);
        last = Some(reply);
    }
    assert_eq!(
        statuses,
        vec![
            StatusCode::FORBIDDEN,
            StatusCode::FORBIDDEN,
            StatusCode::FORBIDDEN,
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::TOO_MANY_REQUESTS,
        ]
    );
    let last = last.expect("a reply");
    assert_eq!(last.problem(), "rate-limited");
    assert!(last.header("retry-after").is_some());
}

#[tokio::test]
async fn wrong_setup_codes_from_one_address_do_not_slow_another_address() {
    let app = App::new(false);
    let code = app_with_setup_code(&app).await;
    let client = app.client();
    for _ in 0..3 {
        let wrong = verify_setup(&client, "ZZZZ-ZZZZ-ZZZZ", Some(local(1)), vec![]).await;
        assert_eq!(wrong.status, StatusCode::FORBIDDEN);
    }
    let slowed = verify_setup(&client, &code, Some(local(1)), vec![]).await;
    assert_eq!(slowed.status, StatusCode::TOO_MANY_REQUESTS);
    let other = verify_setup(&client, &code, Some(local(2)), vec![]).await;
    assert_eq!(other.status, StatusCode::OK, "{:?}", other.json());
}

#[tokio::test]
async fn registration_is_closed_without_signups_or_a_grant() {
    let app = App::new(false);
    let (reply, _) = register(&app.client(), "sam@example.org", None).await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(reply.problem(), "forbidden");
}

#[tokio::test]
async fn registration_creates_an_account_once() {
    let app = App::new(true);
    let client = app.client();
    let (reply, user) = register(&client, "sam@example.org", None).await;
    assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.json());
    assert_eq!(reply.json()["userId"], user.to_string());
    assert_eq!(reply.json()["admin"], false);

    let (again, _) = register(&client, "SAM@example.org", None).await;
    assert_eq!(again.status, StatusCode::CONFLICT);
    assert_eq!(again.problem(), "already-exists");
}

#[tokio::test]
async fn registration_refuses_weak_kdf_settings() {
    let app = App::new(true);
    let client = app.client();
    let (state, request) = kemlock_crypto::opaque::client_registration_start(&PASSWORD)
        .expect("client registration start");
    let started = client
        .post(
            "/kem/v1/accounts/register/start",
            json!({"email": "sam@example.org", "request": b64(&request)}),
        )
        .await;
    let response = unb64(started.json()["response"].as_str().expect("response"));
    let (upload, _) =
        kemlock_crypto::opaque::client_registration_finish(state, &PASSWORD, &response)
            .expect("client registration finish");
    let user = kemlock_domain::UserId::random();
    let reply = client
        .post(
            "/kem/v1/accounts/register/finish",
            json!({
                "userId": user.to_string(), "email": "sam@example.org", "upload": b64(&upload),
                "kdf": {"memoryKib": 65536, "iterations": 1, "parallelism": 4, "salt": b64(&[4u8; 16])},
                "publicBundle": b64(&fakes::bundle(user)),
                "bundleSignature": b64(&fakes::bundle_signature(user)),
                "sealedPrivateKeys": b64(&[0x22u8; 64]),
                "wrappedRootKey": b64(&[0x33u8; kemlock_app::register::WRAPPED_ROOT_KEY_LEN]),
            }),
        )
        .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert!(app.store.user_by_email("sam@example.org").is_none());
}

#[tokio::test]
async fn registration_refuses_a_salt_that_is_not_sixteen_bytes() {
    let app = App::new(true);
    let client = app.client();
    let (state, request) = kemlock_crypto::opaque::client_registration_start(&PASSWORD)
        .expect("client registration start");
    let started = client
        .post(
            "/kem/v1/accounts/register/start",
            json!({"email": "sam@example.org", "request": b64(&request)}),
        )
        .await;
    let response = unb64(started.json()["response"].as_str().expect("response"));
    let (upload, _) =
        kemlock_crypto::opaque::client_registration_finish(state, &PASSWORD, &response)
            .expect("client registration finish");
    let user = kemlock_domain::UserId::random();
    for salt in [vec![4u8; 15], vec![4u8; 17], vec![4u8; 100_000]] {
        let reply = client
            .post(
                "/kem/v1/accounts/register/finish",
                json!({
                    "userId": user.to_string(), "email": "sam@example.org", "upload": b64(&upload),
                    "kdf": {"memoryKib": 65536, "iterations": 3, "parallelism": 4, "salt": b64(&salt)},
                    "publicBundle": b64(&fakes::bundle(user)),
                    "bundleSignature": b64(&fakes::bundle_signature(user)),
                    "sealedPrivateKeys": b64(&[0x22u8; 64]),
                    "wrappedRootKey": b64(&[0x33u8; kemlock_app::register::WRAPPED_ROOT_KEY_LEN]),
                }),
            )
            .await;
        assert_eq!(
            reply.status,
            StatusCode::BAD_REQUEST,
            "{} bytes",
            salt.len()
        );
    }
    assert!(app.store.user_by_email("sam@example.org").is_none());
}

// ---------------------------------------------------------------------------------------------
// DPoP

fn token_request() -> serde_json::Value {
    json!({"grantType": "not-a-grant", "refreshToken": "x"})
}

#[tokio::test]
async fn a_token_endpoint_needs_a_dpop_proof() {
    let app = App::new(false);
    let reply = app
        .client()
        .once(
            "POST",
            "/kem/v1/auth/token",
            &Req {
                body: Some(token_request()),
                no_proof: true,
                ..Req::default()
            },
        )
        .await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert_eq!(reply.problem(), "invalid-dpop-proof");
    assert!(
        reply
            .header("www-authenticate")
            .is_some_and(|h| h.starts_with("DPoP"))
    );
}

#[tokio::test]
async fn a_proof_without_the_nonce_gets_it_and_the_retry_passes() {
    let app = App::new(false);
    let client = app.client();
    let req = Req {
        body: Some(token_request()),
        ..Req::default()
    };
    let first = client.once("POST", "/kem/v1/auth/token", &req).await;
    assert_eq!(first.status, StatusCode::UNAUTHORIZED);
    assert_eq!(first.problem(), "use-dpop-nonce");
    assert_eq!(first.json()["error"], "use_dpop_nonce");
    assert!(
        first
            .header("www-authenticate")
            .is_some_and(|h| h.contains("use_dpop_nonce"))
    );
    assert_eq!(
        first.header("dpop-nonce"),
        Some(app.api.dpop.current_nonce(app.now()).as_str())
    );

    // With the nonce, the proof passes and the request reaches its own validation.
    let second = client.once("POST", "/kem/v1/auth/token", &req).await;
    assert_eq!(second.status, StatusCode::BAD_REQUEST);
    assert_eq!(second.problem(), "invalid-request");
}

#[tokio::test]
async fn nonces_rotate_every_five_minutes() {
    let app = App::new(false);
    let client = app.client();
    let req = Req {
        body: Some(token_request()),
        ..Req::default()
    };
    client
        .send(
            "POST",
            "/kem/v1/auth/token",
            Req {
                body: Some(token_request()),
                ..Req::default()
            },
        )
        .await;
    let old = client.nonce().expect("a nonce");

    app.clock.advance(Duration::minutes(11));
    let stale = client.once("POST", "/kem/v1/auth/token", &req).await;
    assert_eq!(stale.problem(), "use-dpop-nonce");
    assert_ne!(client.nonce().expect("a new nonce"), old);
    let fresh = client.once("POST", "/kem/v1/auth/token", &req).await;
    assert_eq!(fresh.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_proof_can_be_used_once() {
    let app = App::new(false);
    let client = app.client();
    // Learn the nonce.
    client.post("/kem/v1/auth/opaque/start", json!({})).await;
    let proof = client.proof_for("POST", "/kem/v1/auth/opaque/start", None);
    let req = Req {
        body: Some(json!({})),
        proof: Some(proof),
        ..Req::default()
    };
    let first = client.once("POST", "/kem/v1/auth/opaque/start", &req).await;
    assert_eq!(
        first.status,
        StatusCode::BAD_REQUEST,
        "the proof was accepted"
    );
    let replay = client.once("POST", "/kem/v1/auth/opaque/start", &req).await;
    assert_eq!(replay.status, StatusCode::UNAUTHORIZED);
    assert_eq!(replay.problem(), "invalid-dpop-proof");
}

#[tokio::test]
async fn proof_checks_before_authentication_are_limited_per_address() {
    let app = App::new(false);
    let client = app.client();
    let client = &client;
    let send = move |n: u8| {
        let req = Req {
            body: Some(token_request()),
            peer: Some(peer(n)),
            ..Req::default()
        };
        async move { client.once("POST", "/kem/v1/auth/token", &req).await }
    };
    for i in 0..120 {
        assert_ne!(send(1).await.status, StatusCode::TOO_MANY_REQUESTS, "{i}");
    }
    let limited = send(1).await;
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(limited.problem(), "rate-limited");
    assert!(limited.header("retry-after").is_some());
    // Another address is not held back by it.
    assert_ne!(send(2).await.status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn a_made_up_access_token_never_takes_room_in_the_replay_set() {
    let app = App::new(true);
    let client = app.client();
    let session = register_and_sign_in(&client, "sam@example.org").await;

    let before = app.api.dpop.tracked();
    let fake = client
        .send(
            "GET",
            "/kem/v1/sync",
            Req {
                access_token: Some("made-up-token"),
                ..Req::default()
            },
        )
        .await;
    assert_eq!(fake.status, StatusCode::UNAUTHORIZED);
    assert_eq!(fake.problem(), "unauthorized");
    assert!(
        fake.header("www-authenticate")
            .is_some_and(|h| h.contains("invalid_token"))
    );
    assert_eq!(app.api.dpop.tracked(), before, "no room was taken");

    // A real token does: its proof is remembered.
    let real = client
        .get_authed("/kem/v1/sync", &session.access_token)
        .await;
    assert_eq!(real.status, StatusCode::OK);
    assert_eq!(app.api.dpop.tracked(), before + 1);
}

#[tokio::test]
async fn one_device_may_put_only_so_many_authenticated_proofs_in_the_replay_set() {
    let app = App::new(true);
    let client = app.client();
    let session = register_and_sign_in(&client, "sam@example.org").await;
    let other_client = app.client();
    let other = register_and_sign_in(&other_client, "alex@example.org").await;
    app.api.limits.device_proof.set_limit(5);

    let before = app.api.dpop.tracked();
    for n in 0..5 {
        let reply = client
            .get_authed("/kem/v1/sync", &session.access_token)
            .await;
        assert_eq!(reply.status, StatusCode::OK, "request {n}");
    }
    // The sixth waits, before its proof is looked at: it takes no room.
    let limited = client
        .get_authed("/kem/v1/sync", &session.access_token)
        .await;
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(limited.problem(), "rate-limited");
    assert_eq!(app.api.dpop.tracked(), before + 5);
    // Another device is not held back by it.
    let ok = other_client
        .get_authed("/kem/v1/sync", &other.access_token)
        .await;
    assert_eq!(ok.status, StatusCode::OK, "{:?}", ok.json());
}

#[tokio::test]
async fn a_proof_for_another_url_or_method_is_refused() {
    let app = App::new(false);
    let client = app.client();
    client.post("/kem/v1/auth/token", token_request()).await;
    for proof in [
        client.proof_for("POST", "/kem/v1/auth/two-factor", None),
        client.proof_for("GET", "/kem/v1/auth/token", None),
    ] {
        let reply = client
            .once(
                "POST",
                "/kem/v1/auth/token",
                &Req {
                    body: Some(token_request()),
                    proof: Some(proof),
                    ..Req::default()
                },
            )
            .await;
        assert_eq!(reply.problem(), "invalid-dpop-proof");
    }
}

#[tokio::test]
async fn an_eddsa_dpop_key_works_too() {
    let app = App::new(false);
    let client = Client::new(
        app.router.clone(),
        app.clock.clone(),
        kemlock_api_kem::testing::DpopSigner::eddsa(),
    );
    let reply = client.post("/kem/v1/auth/token", token_request()).await;
    assert_eq!(
        reply.status,
        StatusCode::BAD_REQUEST,
        "the proof was accepted"
    );
}

#[tokio::test]
async fn an_authenticated_route_needs_a_dpop_token() {
    let app = App::new(true);
    let client = app.client();
    let missing = client.get("/kem/v1/sync").await;
    assert_eq!(missing.status, StatusCode::UNAUTHORIZED);
    assert!(
        missing
            .header("www-authenticate")
            .is_some_and(|h| h.starts_with("DPoP"))
    );

    let bearer = client
        .send(
            "GET",
            "/kem/v1/sync",
            Req {
                headers: vec![("authorization", "Bearer abc".to_owned())],
                ..Req::default()
            },
        )
        .await;
    assert_eq!(bearer.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn an_access_token_is_useless_with_another_key() {
    let app = App::new(true);
    let phone = app.client();
    let session = register_and_sign_in(&phone, "sam@example.org").await;
    assert_eq!(
        phone
            .get_authed("/kem/v1/sync", &session.access_token)
            .await
            .status,
        StatusCode::OK
    );

    let thief = app.client();
    let reply = thief
        .get_authed("/kem/v1/sync", &session.access_token)
        .await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert_eq!(reply.problem(), "unauthorized");
    assert!(
        reply
            .header("www-authenticate")
            .is_some_and(|h| h.contains("invalid_token"))
    );
}

#[tokio::test]
async fn a_proof_must_hash_the_access_token_it_goes_with() {
    let app = App::new(true);
    let client = app.client();
    let session = register_and_sign_in(&client, "sam@example.org").await;
    let wrong_ath = client.proof_for("GET", "/kem/v1/sync", Some("some-other-token"));
    let reply = client
        .once(
            "GET",
            "/kem/v1/sync",
            &Req {
                access_token: Some(&session.access_token),
                proof: Some(wrong_ath),
                ..Req::default()
            },
        )
        .await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert_eq!(reply.problem(), "invalid-dpop-proof");
}

#[tokio::test]
async fn access_tokens_live_ten_minutes() {
    let app = App::new(true);
    let client = app.client();
    let session = register_and_sign_in(&client, "sam@example.org").await;
    app.clock.advance(Duration::minutes(9));
    assert_eq!(
        client
            .get_authed("/kem/v1/sync", &session.access_token)
            .await
            .status,
        StatusCode::OK
    );
    app.clock.advance(Duration::minutes(1));
    let expired = client
        .get_authed("/kem/v1/sync", &session.access_token)
        .await;
    assert_eq!(expired.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_changed_security_stamp_ends_the_session() {
    let app = App::new(true);
    let client = app.client();
    let session = register_and_sign_in(&client, "sam@example.org").await;
    let mut user = app.store.user_by_email("sam@example.org").expect("user");
    user.security_stamp = uuid::Uuid::from_u128(77);
    app.store.put_user(user);
    let reply = client
        .get_authed("/kem/v1/sync", &session.access_token)
        .await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert_eq!(reply.problem(), "session-ended");
    assert_eq!(reply.json()["reason"], "security-stamp-changed");
}

// ---------------------------------------------------------------------------------------------
// Sessions

fn refresh_body(token: &str) -> serde_json::Value {
    json!({"grantType": "refresh_token", "refreshToken": token})
}

#[tokio::test]
async fn a_refresh_proof_is_remembered_only_once_the_refresh_worked() {
    let app = App::new(true);
    let client = app.client();
    let session = register_and_sign_in(&client, "sam@example.org").await;
    let open_before = app.api.dpop.tracked_open();
    let total_before = app.api.dpop.tracked();

    // Refreshes that lead nowhere take no room in either replay set, so they can't fill them.
    for _ in 0..5 {
        let bad = client
            .post("/kem/v1/auth/token", refresh_body("not-a-refresh-token"))
            .await;
        assert_eq!(bad.status, StatusCode::UNAUTHORIZED, "{:?}", bad.json());
    }
    assert_eq!(app.api.dpop.tracked(), total_before);

    // One that works is remembered with the sessions' proofs, not in the open set, and is then
    // a replay.
    let proof = client.proof_for("POST", "/kem/v1/auth/token", None);
    let req = Req {
        body: Some(refresh_body(&session.refresh_token)),
        proof: Some(proof),
        ..Req::default()
    };
    let ok = client.once("POST", "/kem/v1/auth/token", &req).await;
    assert_eq!(ok.status, StatusCode::OK, "{:?}", ok.json());
    assert_eq!(app.api.dpop.tracked_open(), open_before);
    assert_eq!(app.api.dpop.tracked(), total_before + 1);
    let replay = client.once("POST", "/kem/v1/auth/token", &req).await;
    assert_eq!(replay.status, StatusCode::UNAUTHORIZED);
    assert_eq!(replay.problem(), "invalid-dpop-proof");
}

#[tokio::test]
async fn a_refresh_rotates_tokens() {
    let app = App::new(true);
    let client = app.client();
    let first = register_and_sign_in(&client, "sam@example.org").await;
    let reply = client
        .post("/kem/v1/auth/token", refresh_body(&first.refresh_token))
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.json());
    let second = Session::from_tokens(&reply.json());
    assert_ne!(second.refresh_token, first.refresh_token);
    assert_eq!(second.device_id, first.device_id);
    assert_eq!(reply.json()["tokenType"], "DPoP");
    assert_eq!(reply.json()["expiresIn"], 600);

    // The new access token works.
    assert_eq!(
        client
            .get_authed("/kem/v1/sync", &second.access_token)
            .await
            .status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn a_refresh_token_used_twice_ends_the_session() {
    let app = App::new(true);
    let client = app.client();
    let first = register_and_sign_in(&client, "sam@example.org").await;
    let rotated = client
        .post("/kem/v1/auth/token", refresh_body(&first.refresh_token))
        .await;
    let second = Session::from_tokens(&rotated.json());

    let reuse = client
        .post("/kem/v1/auth/token", refresh_body(&first.refresh_token))
        .await;
    assert_eq!(reuse.status, StatusCode::UNAUTHORIZED);
    assert_eq!(reuse.problem(), "session-ended");
    assert_eq!(reuse.json()["reason"], "refresh-token-reuse");

    // The family is gone, including the token the device legitimately holds.
    let after = client
        .post("/kem/v1/auth/token", refresh_body(&second.refresh_token))
        .await;
    assert_eq!(after.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_refresh_token_from_another_key_is_refused() {
    let app = App::new(true);
    let phone = app.client();
    let session = register_and_sign_in(&phone, "sam@example.org").await;
    let thief = app.client();
    let reply = thief
        .post("/kem/v1/auth/token", refresh_body(&session.refresh_token))
        .await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert_eq!(reply.json()["reason"], "dpop-key-mismatch");
}

#[tokio::test]
async fn a_wrong_grant_type_is_refused() {
    let app = App::new(false);
    let reply = app
        .client()
        .post("/kem/v1/auth/token", token_request())
        .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------------------------
// Items and sync

async fn signed_in() -> (App, Client, Session) {
    let app = App::new(true);
    let client = app.client();
    let session = register_and_sign_in(&client, "sam@example.org").await;
    (app, client, session)
}

async fn put(
    client: &Client,
    session: &Session,
    id: &str,
    precondition: (&str, &str),
    body: serde_json::Value,
) -> Reply {
    client
        .send(
            "PUT",
            &format!("/kem/v1/items/{id}"),
            Req {
                access_token: Some(&session.access_token),
                headers: vec![(precondition.0, precondition.1.to_owned())],
                body: Some(body),
                ..Req::default()
            },
        )
        .await
}

#[tokio::test]
async fn a_new_item_is_created_then_replaced_with_if_match() {
    let (_app, client, session) = signed_in().await;
    let id = new_item_id();

    let created = put(
        &client,
        &session,
        &id,
        ("if-none-match", "*"),
        item_json(&session.user_id, &id, 1),
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED, "{:?}", created.json());
    assert_eq!(created.header("etag"), Some("\"1\""));
    let json = created.json();
    assert_eq!(json["id"], id);
    assert_eq!(json["revision"], 1);
    assert_eq!(json["kind"], "login");
    assert_eq!(json["format"], "kem1");
    assert_eq!(json["deleted"], false);

    let replaced = put(
        &client,
        &session,
        &id,
        ("if-match", "\"1\""),
        item_json(&session.user_id, &id, 2),
    )
    .await;
    assert_eq!(replaced.status, StatusCode::OK, "{:?}", replaced.json());
    assert_eq!(replaced.header("etag"), Some("\"2\""));
}

#[tokio::test]
async fn a_stale_write_is_409_with_the_current_revision() {
    let (_app, client, session) = signed_in().await;
    let id = new_item_id();
    put(
        &client,
        &session,
        &id,
        ("if-none-match", "*"),
        item_json(&session.user_id, &id, 1),
    )
    .await;
    put(
        &client,
        &session,
        &id,
        ("if-match", "1"),
        item_json(&session.user_id, &id, 2),
    )
    .await;

    let stale = put(
        &client,
        &session,
        &id,
        ("if-match", "1"),
        item_json(&session.user_id, &id, 2),
    )
    .await;
    assert_eq!(stale.status, StatusCode::CONFLICT);
    assert!(stale.content_type().starts_with("application/problem+json"));
    assert_eq!(stale.problem(), "stale-revision");
    assert_eq!(stale.json()["currentRevision"], 2);
    assert_eq!(stale.json()["itemId"], id);

    // Creating an item that exists is stale too.
    let again = put(
        &client,
        &session,
        &id,
        ("if-none-match", "*"),
        item_json(&session.user_id, &id, 1),
    )
    .await;
    assert_eq!(again.status, StatusCode::CONFLICT);
    assert_eq!(again.json()["currentRevision"], 2);
}

#[tokio::test]
async fn a_write_needs_a_precondition_and_a_matching_id() {
    let (_app, client, session) = signed_in().await;
    let id = new_item_id();
    let none = client
        .send(
            "PUT",
            &format!("/kem/v1/items/{id}"),
            Req {
                access_token: Some(&session.access_token),
                body: Some(item_json(&session.user_id, &id, 1)),
                ..Req::default()
            },
        )
        .await;
    assert_eq!(none.status, StatusCode::PRECONDITION_REQUIRED);
    assert_eq!(none.problem(), "precondition-required");

    let other_id = new_item_id();
    let mismatch = put(
        &client,
        &session,
        &id,
        ("if-none-match", "*"),
        item_json(&session.user_id, &other_id, 1),
    )
    .await;
    assert_eq!(mismatch.status, StatusCode::BAD_REQUEST);

    let not_a_uuid = put(
        &client,
        &session,
        "not-a-uuid",
        ("if-none-match", "*"),
        item_json(&session.user_id, &id, 1),
    )
    .await;
    assert_eq!(not_a_uuid.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn bad_items_are_refused() {
    let (_app, client, session) = signed_in().await;

    // Not base64url.
    let id = new_item_id();
    let mut bad = item_json(&session.user_id, &id, 1);
    bad["ciphertext"] = json!("not base64!");
    let reply = put(&client, &session, &id, ("if-none-match", "*"), bad).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);

    // A vault that isn't the caller's.
    let id = new_item_id();
    let theirs = item_json(&uuid::Uuid::from_u128(5).to_string(), &id, 1);
    let reply = put(&client, &session, &id, ("if-none-match", "*"), theirs).await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);

    // Over the item size limit.
    let id = new_item_id();
    let mut huge = item_json(&session.user_id, &id, 1);
    huge["ciphertext"] = json!(b64(&vec![7u8; 1024 * 1024 + 1]));
    let reply = put(&client, &session, &id, ("if-none-match", "*"), huge).await;
    assert_eq!(reply.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(reply.problem(), "item-too-large");

    // A revision that skips ahead.
    let id = new_item_id();
    let reply = put(
        &client,
        &session,
        &id,
        ("if-none-match", "*"),
        item_json(&session.user_id, &id, 5),
    )
    .await;
    assert_eq!(reply.status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn a_delete_is_a_tombstone_that_syncs() {
    let (_app, client, session) = signed_in().await;
    let id = new_item_id();
    put(
        &client,
        &session,
        &id,
        ("if-none-match", "*"),
        item_json(&session.user_id, &id, 1),
    )
    .await;
    let tombstone = json!({
        "id": id, "owner": format!("user:{}", session.user_id), "kind": "login",
        "format": "kem1", "revision": 2, "keyVersion": 1, "deleted": true,
    });
    let deleted = put(&client, &session, &id, ("if-match", "1"), tombstone).await;
    assert_eq!(deleted.status, StatusCode::OK, "{:?}", deleted.json());
    assert_eq!(deleted.json()["deleted"], true);
    assert!(deleted.json().get("ciphertext").is_none());

    let sync = client
        .get_authed("/kem/v1/sync", &session.access_token)
        .await;
    let sync_json = sync.json();
    let items = &sync_json["items"];
    assert_eq!(items.as_array().map(Vec::len), Some(1));
    assert_eq!(items[0]["deleted"], true);
    assert_eq!(items[0]["revision"], 2);
}

#[tokio::test]
async fn a_batch_stores_all_or_nothing_on_a_literal_colon_route() {
    let (app, client, session) = signed_in().await;
    let existing = new_item_id();
    put(
        &client,
        &session,
        &existing,
        ("if-none-match", "*"),
        item_json(&session.user_id, &existing, 1),
    )
    .await;

    let a = new_item_id();
    let b = new_item_id();
    let ok = client
        .post_authed(
            "/kem/v1/items:batch",
            &session.access_token,
            json!({"writes": [
                {"item": item_json(&session.user_id, &a, 1)},
                {"expectedRevision": null, "item": item_json(&session.user_id, &b, 1)},
                {"expectedRevision": 1, "item": item_json(&session.user_id, &existing, 2)},
            ]}),
        )
        .await;
    assert_eq!(ok.status, StatusCode::OK, "{:?}", ok.json());
    assert_eq!(ok.json()["items"].as_array().map(Vec::len), Some(3));

    // One stale write: nothing is stored, and the problem names the item.
    let fresh = new_item_id();
    let stale = client
        .post_authed(
            "/kem/v1/items:batch",
            &session.access_token,
            json!({"writes": [
                {"item": item_json(&session.user_id, &fresh, 1)},
                {"expectedRevision": 1, "item": item_json(&session.user_id, &existing, 2)},
            ]}),
        )
        .await;
    assert_eq!(stale.status, StatusCode::CONFLICT);
    assert_eq!(stale.problem(), "stale-revision");
    assert_eq!(stale.json()["itemId"], existing);
    assert_eq!(stale.json()["currentRevision"], 2);
    let fresh_id: ItemId = fresh.parse().expect("a uuid");
    assert!(app.store.item(fresh_id).is_none());
}

#[tokio::test]
async fn a_batch_holds_at_most_500_writes() {
    let (_app, client, session) = signed_in().await;
    let writes: Vec<_> = (0..501)
        .map(|_| json!({"item": item_json(&session.user_id, &new_item_id(), 1)}))
        .collect();
    let reply = client
        .post_authed(
            "/kem/v1/items:batch",
            &session.access_token,
            json!({ "writes": writes }),
        )
        .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn sync_pages_and_ends_with_a_cursor_that_is_unchanged() {
    let (_app, client, session) = signed_in().await;
    let first = client
        .get_authed("/kem/v1/sync", &session.access_token)
        .await;
    assert_eq!(first.status, StatusCode::OK);
    assert_eq!(first.json()["items"], json!([]));
    assert_eq!(first.json()["more"], false);

    let mut ids = Vec::new();
    for _ in 0..3 {
        let id = new_item_id();
        put(
            &client,
            &session,
            &id,
            ("if-none-match", "*"),
            item_json(&session.user_id, &id, 1),
        )
        .await;
        ids.push(id);
    }

    let page1 = client
        .get_authed("/kem/v1/sync?limit=2", &session.access_token)
        .await;
    assert_eq!(page1.status, StatusCode::OK);
    assert_eq!(page1.json()["more"], true);
    assert!(page1.header("etag").is_none(), "no ETag mid-sync");
    let cursor = page1.json()["cursor"].as_str().expect("cursor").to_owned();

    let page2 = client
        .get_authed(
            &format!("/kem/v1/sync?limit=2&since={cursor}"),
            &session.access_token,
        )
        .await;
    assert_eq!(page2.json()["more"], false);
    let seen: Vec<String> = page1.json()["items"]
        .as_array()
        .into_iter()
        .chain(page2.json()["items"].as_array())
        .flatten()
        .map(|i| i["id"].as_str().expect("id").to_owned())
        .collect();
    assert_eq!(seen, ids);

    // Nothing changed since the last cursor: 304, by `since` and by If-None-Match.
    let last = page2.json()["cursor"].as_str().expect("cursor").to_owned();
    let unchanged = client
        .get_authed(&format!("/kem/v1/sync?since={last}"), &session.access_token)
        .await;
    assert_eq!(unchanged.status, StatusCode::NOT_MODIFIED);
    assert!(unchanged.body.is_empty());
    let etag = page2
        .header("etag")
        .expect("an ETag on the last page")
        .to_owned();
    assert_eq!(unchanged.header("etag"), Some(etag.as_str()));
    let by_etag = client
        .send(
            "GET",
            "/kem/v1/sync",
            Req {
                access_token: Some(&session.access_token),
                headers: vec![("if-none-match", etag)],
                ..Req::default()
            },
        )
        .await;
    assert_eq!(by_etag.status, StatusCode::NOT_MODIFIED);

    // A new write after the cursor is the only thing returned next.
    let newest = new_item_id();
    put(
        &client,
        &session,
        &newest,
        ("if-none-match", "*"),
        item_json(&session.user_id, &newest, 1),
    )
    .await;
    let delta = client
        .get_authed(&format!("/kem/v1/sync?since={last}"), &session.access_token)
        .await;
    assert_eq!(delta.status, StatusCode::OK);
    assert_eq!(delta.json()["items"].as_array().map(Vec::len), Some(1));
    assert_eq!(delta.json()["items"][0]["id"], newest);
}

/// Two items put, then synced: the cursor and ETag of the answer.
async fn synced_cursor(client: &Client, session: &Session) -> (String, String) {
    for _ in 0..2 {
        let id = new_item_id();
        put(
            client,
            session,
            &id,
            ("if-none-match", "*"),
            item_json(&session.user_id, &id, 1),
        )
        .await;
    }
    let page = client
        .get_authed("/kem/v1/sync", &session.access_token)
        .await;
    assert_eq!(page.status, StatusCode::OK);
    let cursor = page.json()["cursor"].as_str().expect("cursor").to_owned();
    let etag = page.header("etag").expect("an ETag").to_owned();
    (cursor, etag)
}

async fn sync_with(
    client: &Client,
    session: &Session,
    method: &str,
    uri: &str,
    headers: Vec<(&str, String)>,
    body: Option<serde_json::Value>,
) -> Reply {
    client
        .send(
            method,
            uri,
            Req {
                access_token: Some(&session.access_token),
                headers,
                body,
                ..Req::default()
            },
        )
        .await
}

#[tokio::test]
async fn the_sync_cursor_may_come_in_a_header_or_a_post_body() {
    let (_app, client, session) = signed_in().await;
    let (cursor, etag) = synced_cursor(&client, &session).await;

    // Nothing changed: 304 whichever way the cursor arrives, with the same ETag.
    let by_query = sync_with(
        &client,
        &session,
        "GET",
        &format!("/kem/v1/sync?since={cursor}"),
        vec![],
        None,
    )
    .await;
    assert_eq!(by_query.status, StatusCode::NOT_MODIFIED);
    let by_header = sync_with(
        &client,
        &session,
        "GET",
        "/kem/v1/sync",
        vec![("kemlock-sync-cursor", cursor.clone())],
        None,
    )
    .await;
    let by_body = sync_with(
        &client,
        &session,
        "POST",
        "/kem/v1/sync",
        vec![],
        Some(json!({"since": cursor})),
    )
    .await;
    let by_body_header = sync_with(
        &client,
        &session,
        "POST",
        "/kem/v1/sync",
        vec![("kemlock-sync-cursor", cursor.clone())],
        Some(json!({})),
    )
    .await;
    for reply in [&by_header, &by_body, &by_body_header] {
        assert_eq!(reply.status, StatusCode::NOT_MODIFIED);
        assert!(reply.body.is_empty());
        assert_eq!(reply.header("etag"), Some(etag.as_str()));
    }

    // A new write comes back the same from all three, and a limit in the body is honoured.
    for _ in 0..2 {
        let id = new_item_id();
        put(
            &client,
            &session,
            &id,
            ("if-none-match", "*"),
            item_json(&session.user_id, &id, 1),
        )
        .await;
    }
    let get = sync_with(
        &client,
        &session,
        "GET",
        &format!("/kem/v1/sync?since={cursor}"),
        vec![],
        None,
    )
    .await;
    let header = sync_with(
        &client,
        &session,
        "GET",
        "/kem/v1/sync",
        vec![("Kemlock-Sync-Cursor", cursor.clone())],
        None,
    )
    .await;
    let post = sync_with(
        &client,
        &session,
        "POST",
        "/kem/v1/sync",
        vec![],
        Some(json!({"since": cursor})),
    )
    .await;
    assert_eq!(get.status, StatusCode::OK);
    assert_eq!(get.json()["items"].as_array().map(Vec::len), Some(2));
    assert_eq!(header.json(), get.json());
    assert_eq!(post.json(), get.json());
    let limited = sync_with(
        &client,
        &session,
        "POST",
        "/kem/v1/sync",
        vec![],
        Some(json!({"since": cursor, "limit": 1})),
    )
    .await;
    assert_eq!(limited.json()["items"].as_array().map(Vec::len), Some(1));
    assert_eq!(limited.json()["more"], true);

    // An empty body is a first sync, like a GET with nothing.
    let first = sync_with(&client, &session, "POST", "/kem/v1/sync", vec![], None).await;
    assert_eq!(first.status, StatusCode::OK);
    assert_eq!(first.json()["items"].as_array().map(Vec::len), Some(4));
}

#[tokio::test]
async fn a_cursor_in_a_header_or_body_that_cannot_be_read_needs_a_full_sync() {
    let (_app, client, session) = signed_in().await;
    for bad in ["!!!", "AAAA", ""] {
        let header = sync_with(
            &client,
            &session,
            "GET",
            "/kem/v1/sync",
            vec![("kemlock-sync-cursor", bad.to_owned())],
            None,
        )
        .await;
        assert_eq!(header.status, StatusCode::GONE, "header {bad:?}");
        assert_eq!(header.problem(), "full-sync-required");
        let body = sync_with(
            &client,
            &session,
            "POST",
            "/kem/v1/sync",
            vec![],
            Some(json!({"since": bad})),
        )
        .await;
        assert_eq!(body.status, StatusCode::GONE, "body {bad:?}");
        assert_eq!(body.problem(), "full-sync-required");
    }
    let unknown = sync_with(
        &client,
        &session,
        "POST",
        "/kem/v1/sync",
        vec![],
        Some(json!({"cursor": "x"})),
    )
    .await;
    assert_eq!(unknown.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn an_unreadable_cursor_needs_a_full_sync() {
    let (_app, client, session) = signed_in().await;
    for since in ["!!!", "AAAA", ""] {
        let reply = client
            .get_authed(
                &format!("/kem/v1/sync?since={since}"),
                &session.access_token,
            )
            .await;
        assert_eq!(reply.status, StatusCode::GONE, "{since:?}");
        assert_eq!(reply.problem(), "full-sync-required");
    }
}

#[tokio::test]
async fn a_cursor_behind_the_tombstone_horizon_needs_a_full_sync() {
    let (app, client, session) = signed_in().await;
    let id = new_item_id();
    put(
        &client,
        &session,
        &id,
        ("if-none-match", "*"),
        item_json(&session.user_id, &id, 1),
    )
    .await;
    let early = client
        .get_authed("/kem/v1/sync", &session.access_token)
        .await;
    let cursor = early.json()["cursor"].as_str().expect("cursor").to_owned();

    let owner = kemlock_domain::Owner::User(kemlock_domain::UserId(
        uuid::Uuid::parse_str(&session.user_id).expect("a user id"),
    ));
    app.store.set_purged(
        owner,
        kemlock_domain::VersionVector::from_iter([(app.store.server(), 99)]),
    );
    let stale = client
        .get_authed(
            &format!("/kem/v1/sync?since={cursor}"),
            &session.access_token,
        )
        .await;
    assert_eq!(stale.status, StatusCode::GONE);
    assert_eq!(stale.problem(), "full-sync-required");

    // A full sync without a cursor still works.
    let full = client
        .get_authed("/kem/v1/sync", &session.access_token)
        .await;
    assert_eq!(full.status, StatusCode::OK);
}

#[tokio::test]
async fn an_account_only_syncs_its_own_items() {
    let app = App::new(true);
    let sam_client = app.client();
    let alex_client = app.client();
    let sam = register_and_sign_in(&sam_client, "sam@example.org").await;
    let alex = register_and_sign_in(&alex_client, "alex@example.org").await;
    let id = new_item_id();
    put(
        &sam_client,
        &sam,
        &id,
        ("if-none-match", "*"),
        item_json(&sam.user_id, &id, 1),
    )
    .await;

    let theirs = alex_client
        .get_authed("/kem/v1/sync", &alex.access_token)
        .await;
    assert_eq!(theirs.json()["items"], json!([]));
    let mine = sam_client
        .get_authed("/kem/v1/sync", &sam.access_token)
        .await;
    assert_eq!(mine.json()["items"].as_array().map(Vec::len), Some(1));
}

#[tokio::test]
async fn a_put_nudges_the_owners_live_sockets() {
    let (app, client, session) = signed_in().await;
    let mut nudges = app.hub.subscribe();
    let id = new_item_id();
    put(
        &client,
        &session,
        &id,
        ("if-none-match", "*"),
        item_json(&session.user_id, &id, 1),
    )
    .await;
    let owner = nudges.try_recv().expect("a nudge");
    assert_eq!(owner.to_string(), format!("user:{}", session.user_id));
}

#[tokio::test]
async fn live_needs_authentication_and_an_upgrade() {
    let (_app, client, session) = signed_in().await;
    assert_eq!(
        client.get("/kem/v1/live").await.status,
        StatusCode::UNAUTHORIZED
    );
    let plain = client
        .get_authed("/kem/v1/live", &session.access_token)
        .await;
    assert!(plain.status.is_client_error(), "{}", plain.status);
    assert_ne!(plain.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_live_session_ends_with_a_stamp_change_a_removed_device_or_a_reuse() {
    let (app, client, session) = signed_in().await;
    let user = kemlock_domain::UserId(uuid::Uuid::parse_str(&session.user_id).expect("a uuid"));
    let device =
        kemlock_domain::DeviceId(uuid::Uuid::parse_str(&session.device_id).expect("a uuid"));
    let account = app.store.user(user).expect("the user exists");
    let jkt = app
        .store
        .devices_of(user)
        .first()
        .and_then(|d| d.dpop_jkt.clone())
        .expect("the device has a key");
    let live = |stamp: uuid::Uuid, jkt: String| {
        let api = app.api.clone();
        async move { api.session_is_live(user, device, &jkt, stamp).await }
    };

    // As signed in, the session stands; with another key or a stale stamp it doesn't.
    assert!(live(account.security_stamp, jkt.clone()).await);
    assert!(!live(account.security_stamp, "another-key".to_owned()).await);
    assert!(!live(uuid::Uuid::from_u128(7), jkt.clone()).await);

    // A refresh token used twice ends it: the device is unbound from its key.
    let refresh = client
        .post("/kem/v1/auth/token", refresh_body(&session.refresh_token))
        .await;
    assert_eq!(refresh.status, StatusCode::OK);
    let reuse = client
        .post("/kem/v1/auth/token", refresh_body(&session.refresh_token))
        .await;
    assert_eq!(reuse.status, StatusCode::UNAUTHORIZED);
    assert!(!live(account.security_stamp, jkt.clone()).await);

    // And a password change (a new stamp) ends the stamp the token carried.
    let mut changed = account.clone();
    changed.security_stamp = uuid::Uuid::from_u128(99);
    app.store.put_user(changed);
    assert!(!live(account.security_stamp, jkt).await);
}

// ---------------------------------------------------------------------------------------------
// Signed item writes (docs/crypto.md, "Signed item writes")

/// `item` signed by the account `user` with `key`, as a device would, for the write of it.
fn signed_with(
    key: &kemlock_crypto::sig1::SigningKey,
    user: &str,
    mut item: serde_json::Value,
) -> serde_json::Value {
    use kemlock_crypto::{item_write, owner::Owner};
    let writer = user.parse::<kemlock_domain::UserId>().expect("a user id");
    let deleted = item["deleted"].as_bool().unwrap_or(false);
    let ciphertext = item["ciphertext"].as_str().map(unb64);
    let item_key = item["itemKey"].as_str().map(unb64);
    let sealed = match (&ciphertext, &item_key) {
        (Some(c), Some(k)) => Some((c.as_slice(), k.as_slice())),
        _ => None,
    };
    let id = item["id"]
        .as_str()
        .and_then(|s| s.parse::<ItemId>().ok())
        .expect("an item id");
    let statement = item_write::Statement {
        owner: Owner::user(*writer.as_bytes()),
        item_id: *id.as_bytes(),
        kind: "login",
        revision: item["revision"].as_u64().expect("a revision"),
        deleted,
        envelope: item_write::envelope_hash(1, sealed).expect("the hash"),
        writer: *writer.as_bytes(),
        writer_key_version: 1,
    };
    item["writer"] = json!(user);
    item["writerKeyVersion"] = json!(1);
    item["writeSignature"] = json!(b64(&statement.sign(key).expect("signs")));
    item
}

#[tokio::test]
async fn a_signed_write_is_stored_served_back_and_makes_the_vault_signed_only() {
    let (_app, client, session) = signed_in().await;
    let key = common::fakes::bundle_key();
    let id = new_item_id();

    let created = put(
        &client,
        &session,
        &id,
        ("if-none-match", "*"),
        signed_with(&key, &session.user_id, item_json(&session.user_id, &id, 1)),
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED, "{:?}", created.json());
    let shown = created.json();
    assert_eq!(shown["writer"], session.user_id);
    assert_eq!(shown["writerKeyVersion"], 1);
    assert!(shown["writeSignature"].is_string());

    // Sync serves the signature back.
    let synced = client
        .send(
            "GET",
            "/kem/v1/sync",
            Req {
                access_token: Some(&session.access_token),
                ..Req::default()
            },
        )
        .await;
    assert_eq!(synced.status, StatusCode::OK);
    let items = synced.json()["items"].clone();
    assert_eq!(items[0]["writeSignature"], shown["writeSignature"]);

    // The vault is signed-only now: an unsigned write is refused, a signed one is not.
    let unsigned = put(
        &client,
        &session,
        &id,
        ("if-match", "1"),
        item_json(&session.user_id, &id, 2),
    )
    .await;
    assert_eq!(unsigned.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        unsigned.json()["type"],
        "urn:kemlock:problem:signature-required"
    );
    let signed = put(
        &client,
        &session,
        &id,
        ("if-match", "1"),
        signed_with(&key, &session.user_id, item_json(&session.user_id, &id, 2)),
    )
    .await;
    assert_eq!(signed.status, StatusCode::OK, "{:?}", signed.json());
}

#[tokio::test]
async fn a_signature_by_another_key_or_over_another_item_is_refused_and_stores_nothing() {
    let (_app, client, session) = signed_in().await;
    let id = new_item_id();
    let thief = kemlock_crypto::sig1::SigningKey::from_bytes(&[0x66; 64]);
    let forged = put(
        &client,
        &session,
        &id,
        ("if-none-match", "*"),
        signed_with(
            &thief,
            &session.user_id,
            item_json(&session.user_id, &id, 1),
        ),
    )
    .await;
    assert_eq!(forged.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        forged.json()["type"],
        "urn:kemlock:problem:invalid-signature"
    );

    // A genuine signature of one write, sent with another's ciphertext.
    let key = common::fakes::bundle_key();
    let mut swapped = signed_with(&key, &session.user_id, item_json(&session.user_id, &id, 1));
    swapped["ciphertext"] = json!(b64(&kemlock_crypto::rand::bytes::<64>()));
    let refused = put(&client, &session, &id, ("if-none-match", "*"), swapped).await;
    assert_eq!(refused.status, StatusCode::UNPROCESSABLE_ENTITY);

    // A signature with no writer, or by another account, is refused too.
    let mut partial = signed_with(&key, &session.user_id, item_json(&session.user_id, &id, 1));
    partial.as_object_mut().expect("an object").remove("writer");
    let refused = put(&client, &session, &id, ("if-none-match", "*"), partial).await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST);
    let mut other = signed_with(&key, &session.user_id, item_json(&session.user_id, &id, 1));
    other["writer"] = json!(uuid::Uuid::from_u128(5).to_string());
    let refused = put(&client, &session, &id, ("if-none-match", "*"), other).await;
    assert_eq!(refused.status, StatusCode::UNPROCESSABLE_ENTITY);

    // Nothing was stored: the id is still free, and an unsigned write is still accepted.
    let created = put(
        &client,
        &session,
        &id,
        ("if-none-match", "*"),
        item_json(&session.user_id, &id, 1),
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED, "{:?}", created.json());
}

#[tokio::test]
async fn a_signed_delete_is_accepted_and_an_unsigned_one_is_not_once_signed() {
    let (_app, client, session) = signed_in().await;
    let key = common::fakes::bundle_key();
    let id = new_item_id();
    put(
        &client,
        &session,
        &id,
        ("if-none-match", "*"),
        signed_with(&key, &session.user_id, item_json(&session.user_id, &id, 1)),
    )
    .await;
    let tombstone = |revision: u64| {
        json!({
            "id": id,
            "owner": format!("user:{}", session.user_id),
            "kind": "login",
            "format": "kem1",
            "revision": revision,
            "keyVersion": 1,
            "deleted": true,
        })
    };
    let unsigned = put(&client, &session, &id, ("if-match", "1"), tombstone(2)).await;
    assert_eq!(unsigned.status, StatusCode::UNPROCESSABLE_ENTITY);
    let signed = put(
        &client,
        &session,
        &id,
        ("if-match", "1"),
        signed_with(&key, &session.user_id, tombstone(2)),
    )
    .await;
    assert_eq!(signed.status, StatusCode::OK, "{:?}", signed.json());
    assert_eq!(signed.json()["deleted"], true);
    assert!(signed.json()["writeSignature"].is_string());
}

#[tokio::test]
async fn an_owner_may_ask_for_signed_writes_for_its_own_vault_only() {
    let (_app, client, session) = signed_in().await;
    let ask = |owner: String| {
        let client = &client;
        let token = session.access_token.clone();
        async move {
            client
                .send(
                    "PUT",
                    &format!("/kem/v1/owners/{owner}/signed-writes"),
                    Req {
                        access_token: Some(&token),
                        ..Req::default()
                    },
                )
                .await
        }
    };
    let other = ask(format!("user:{}", uuid::Uuid::from_u128(9))).await;
    assert_eq!(other.status, StatusCode::FORBIDDEN);
    let space = ask(format!("space:{}", uuid::Uuid::from_u128(9))).await;
    assert_eq!(space.status, StatusCode::FORBIDDEN);
    let own = ask(format!("user:{}", session.user_id)).await;
    assert_eq!(own.status, StatusCode::NO_CONTENT);

    let id = new_item_id();
    let unsigned = put(
        &client,
        &session,
        &id,
        ("if-none-match", "*"),
        item_json(&session.user_id, &id, 1),
    )
    .await;
    assert_eq!(unsigned.status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn an_account_reads_its_own_bundle_by_key_version_and_a_stranger_gets_a_404() {
    let (_app, client, session) = signed_in().await;
    let get = |account: String, version: u32| {
        let client = &client;
        let token = session.access_token.clone();
        async move {
            client
                .send(
                    "GET",
                    &format!("/kem/v1/accounts/{account}/bundles/{version}"),
                    Req {
                        access_token: Some(&token),
                        ..Req::default()
                    },
                )
                .await
        }
    };
    let own = get(session.user_id.clone(), 1).await;
    assert_eq!(own.status, StatusCode::OK, "{:?}", own.json());
    let json = own.json();
    assert_eq!(json["keyVersion"], 1);
    let bundle = unb64(json["publicBundle"].as_str().expect("a bundle"));
    let account: kemlock_domain::UserId = session.user_id.parse().expect("a user id");
    assert_eq!(&bundle[17..33], account.as_bytes().as_slice());
    assert!(json["bundleSignature"].is_string());

    // A version the account never had, an account that shares no space, and one that doesn't exist
    // are the same answer.
    assert_eq!(
        get(session.user_id.clone(), 2).await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        get(uuid::Uuid::from_u128(77).to_string(), 1).await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        get("not-a-uuid".to_owned(), 1).await.status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn a_signature_under_an_old_key_version_asks_the_device_to_unlock_again() {
    let (app, client, session) = signed_in().await;
    let key = common::fakes::bundle_key();
    // The account replaced its keys since this device unlocked: its row is at version 2.
    let user = session.user_id.parse::<kemlock_domain::UserId>().expect("a user id");
    let mut account = app.store.user(user).expect("the account");
    account.key_version = 2;
    app.store.put_user(account);

    let id = new_item_id();
    let stale = put(
        &client,
        &session,
        &id,
        ("if-none-match", "*"),
        signed_with(&key, &session.user_id, item_json(&session.user_id, &id, 1)),
    )
    .await;
    assert_eq!(stale.status, StatusCode::UNPROCESSABLE_ENTITY);
    let json = stale.json();
    assert_eq!(json["type"], "urn:kemlock:problem:key-version-stale");
    assert_eq!(json["currentKeyVersion"], 2);
}
