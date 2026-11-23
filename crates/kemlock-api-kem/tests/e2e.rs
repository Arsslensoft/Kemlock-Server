//! One whole life of a new server, through the router and real OPAQUE and DPoP: the setup code
//! from the log, the first admin, two-step login, finishing setup, signing in with the second
//! step, writing a `kem1` item and syncing it back.

mod common;

use axum::http::StatusCode;
use common::*;
use serde_json::json;

#[tokio::test]
async fn setup_code_to_first_admin_to_synced_item() {
    let app = App::new(false);
    let code = app
        .api
        .start_setup()
        .await
        .expect("setup starts")
        .expect("a code is made while no admin exists")
        .as_display();
    let client = app.local_client();

    // The server says it needs an admin, and that nobody else may register yet.
    let config = client.get("/kem/v1/config").await.json();
    assert_eq!(config["setup"], "needs-admin");
    let (closed, _) = register(&client, "stranger@example.org", None).await;
    assert_eq!(closed.status, StatusCode::FORBIDDEN);

    // The setup code buys a grant.
    let verified = client
        .post("/kem/v1/setup/verify", json!({ "code": code }))
        .await;
    assert_eq!(verified.status, StatusCode::OK, "{:?}", verified.json());
    let grant = verified.json()["grant"]
        .as_str()
        .expect("a grant")
        .to_owned();

    // The grant registers the first admin over real OPAQUE.
    let (registered, admin) = register(&client, "admin@example.org", Some(&grant)).await;
    assert_eq!(
        registered.status,
        StatusCode::CREATED,
        "{:?}",
        registered.json()
    );
    assert_eq!(
        registered.json()["admin"],
        true,
        "registered as the first admin"
    );
    assert!(
        !app.store.user(admin).expect("stored").is_admin(),
        "but no admin until setup finishes with a confirmed two-step method"
    );
    assert_eq!(
        client.get("/kem/v1/config").await.json()["setup"],
        "pending"
    );

    // The admin signs in (no second step is set up yet). Setup can't finish without one.
    let signed = sign_in_reply(&client, "admin@example.org", test_device()).await;
    assert_eq!(signed.status, StatusCode::OK, "{:?}", signed.json());
    assert_eq!(signed.json()["status"], "signed_in");
    let session = Session::from_tokens(&signed.json()["tokens"]);
    assert_eq!(signed.json()["tokens"]["admin"], false);
    let too_early = client
        .send(
            "POST",
            "/kem/v1/setup/finish",
            Req {
                access_token: Some(&session.access_token),
                ..Req::default()
            },
        )
        .await;
    assert_eq!(too_early.status, StatusCode::CONFLICT);
    assert_eq!(too_early.problem(), "two-step-required");

    // Two-step login: enrol an authenticator, confirm it with a code.
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
    let secret = enrol.json()["secret"]
        .as_str()
        .expect("a secret")
        .to_owned();
    assert!(
        enrol.json()["uri"]
            .as_str()
            .is_some_and(|u| u.starts_with("otpauth://totp/Kemlock:admin%40example.org"))
    );
    let wrong = client
        .post_authed(
            "/kem/v1/account/two-factor/totp/confirm",
            &session.access_token,
            json!({"code": "000000"}),
        )
        .await;
    // (An unlucky 1 in a million: the right code is 000000.)
    assert!(
        wrong.status == StatusCode::UNAUTHORIZED || totp_now(&app, &secret) == "000000",
        "{:?}",
        wrong.status
    );
    let confirmed = client
        .post_authed(
            "/kem/v1/account/two-factor/totp/confirm",
            &session.access_token,
            json!({"code": totp_now(&app, &secret)}),
        )
        .await;
    assert_eq!(confirmed.status, StatusCode::NO_CONTENT);

    // Now setup finishes, for good.
    let finished = client
        .send(
            "POST",
            "/kem/v1/setup/finish",
            Req {
                access_token: Some(&session.access_token),
                ..Req::default()
            },
        )
        .await;
    assert_eq!(
        finished.status,
        StatusCode::NO_CONTENT,
        "{:?}",
        finished.body
    );
    assert_eq!(
        client.get("/kem/v1/config").await.json()["setup"],
        "complete"
    );
    assert!(app.store.user(admin).expect("stored").is_admin());
    let reopened = client
        .post("/kem/v1/setup/verify", json!({"code": "AAAA-AAAA-AAAA"}))
        .await;
    assert_eq!(reopened.status, StatusCode::CONFLICT);
    assert_eq!(reopened.problem(), "setup-complete");

    // Signing in again asks for the second step, from the same device.
    let device = json!({"id": session.device_id, "name": "Test device", "kind": "kemlock-cli"});
    let again = sign_in_reply(&client, "admin@example.org", device).await;
    assert_eq!(again.status, StatusCode::OK, "{:?}", again.json());
    let again = again.json();
    assert_eq!(again["status"], "two_factor_required");
    assert!(again["tokens"].is_null());
    assert_eq!(again["methods"], json!(["totp"]));
    let second_step = client
        .post(
            "/kem/v1/auth/two-factor",
            json!({
                "challenge": again["challenge"],
                "method": "totp",
                "code": totp_now(&app, &secret),
            }),
        )
        .await;
    assert_eq!(
        second_step.status,
        StatusCode::OK,
        "{:?}",
        second_step.json()
    );
    assert_eq!(
        second_step.json()["admin"],
        true,
        "an admin with two-step login"
    );
    let session = Session::from_tokens(&second_step.json());
    assert_eq!(app.store.devices_of(admin).len(), 1);

    // Write one item and read it back through sync.
    let mut nudges = app.hub.subscribe();
    let id = new_item_id();
    let keys = ItemKeys::new(&session.user_id);
    let plaintext = r#"{"title":"Example","password":"hunter2"}"#;
    let item = keys.seal(&id, 1, "login", plaintext);
    let put = client
        .send(
            "PUT",
            &format!("/kem/v1/items/{id}"),
            Req {
                access_token: Some(&session.access_token),
                headers: vec![("if-none-match", "*".to_owned())],
                body: Some(item.clone()),
                ..Req::default()
            },
        )
        .await;
    assert_eq!(put.status, StatusCode::CREATED, "{:?}", put.json());
    assert!(nudges.try_recv().is_ok(), "the owner's sockets are nudged");

    let sync = client
        .get_authed("/kem/v1/sync", &session.access_token)
        .await;
    assert_eq!(sync.status, StatusCode::OK, "{:?}", sync.json());
    let sync_json = sync.json();
    assert_eq!(sync_json["more"], false);
    let items = sync_json["items"].as_array().expect("items");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0], item, "the server returns the bytes it was given");
    assert_eq!(keys.open(&items[0]), plaintext, "and the client opens them");

    // The cursor from that sync is up to date: 304.
    let cursor = sync_json["cursor"].as_str().expect("a cursor");
    let unchanged = client
        .get_authed(
            &format!("/kem/v1/sync?since={cursor}"),
            &session.access_token,
        )
        .await;
    assert_eq!(unchanged.status, StatusCode::NOT_MODIFIED);
    assert!(unchanged.body.is_empty());
}
