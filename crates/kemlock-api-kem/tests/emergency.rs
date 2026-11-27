//! Emergency access over HTTP against the fakes, with real DPoP. The timer is the use case itself,
//! run by the test where the server's job runner would.

mod common;

use axum::http::StatusCode;
use common::*;
use kemlock_app::devices::LogNotices;
use kemlock_app::emergency::ApproveDue;
use serde_json::{Value, json};
use time::Duration;

const GRANTOR: &str = "sam@example.org";
const CONTACT: &str = "kim@example.org";
/// A `kx1` sealed box of a 64-byte root key.
const SEALED_LEN: usize = 1 + 1600 + 12 + 64 + 16;

fn sealed_box() -> String {
    b64(&[0x77_u8; SEALED_LEN])
}

struct Scene {
    app: App,
    sam: Client,
    kim: Client,
    sam_session: Session,
    kim_session: Session,
}

async fn scene() -> Scene {
    let app = App::new(true);
    let sam = app.client();
    let kim = app.client();
    let sam_session = register_and_sign_in(&sam, GRANTOR).await;
    let kim_session = register_and_sign_in(&kim, CONTACT).await;
    Scene {
        app,
        sam,
        kim,
        sam_session,
        kim_session,
    }
}

impl Scene {
    async fn call(
        &self,
        who: &Client,
        session: &Session,
        method: &str,
        uri: &str,
        body: Option<Value>,
    ) -> Reply {
        who.send(
            method,
            uri,
            Req {
                access_token: Some(&session.access_token),
                body,
                ..Req::default()
            },
        )
        .await
    }

    async fn sam(&self, method: &str, uri: &str, body: Option<Value>) -> Reply {
        self.call(&self.sam, &self.sam_session, method, uri, body)
            .await
    }

    async fn kim(&self, method: &str, uri: &str, body: Option<Value>) -> Reply {
        self.call(&self.kim, &self.kim_session, method, uri, body)
            .await
    }

    /// Signs both accounts in again, after the clock moved past their access tokens.
    async fn relogin(&mut self) {
        let sam = sign_in_reply(&self.sam, GRANTOR, test_device()).await;
        self.sam_session = Session::from_tokens(&sam.json()["tokens"]);
        let kim = sign_in_reply(&self.kim, CONTACT, test_device()).await;
        self.kim_session = Session::from_tokens(&kim.json()["tokens"]);
    }

    /// Runs the timer the way the server's job would.
    async fn run_timer(&self) -> u64 {
        ApproveDue {
            users: self.app.store.clone(),
            grants: self.app.store.clone(),
            notices: LogNotices,
            env: self.app.crypto.clone(),
            events: self.app.store.clone(),
        }
        .execute()
        .await
        .expect("the timer runs")
    }

    async fn invite(&self, kind: &str, days: u32) -> String {
        let reply = self
            .sam(
                "POST",
                "/kem/v1/emergency/grants",
                Some(json!({"email": CONTACT, "kind": kind, "waitDays": days})),
            )
            .await;
        assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.json());
        reply.json()["id"].as_str().expect("id").to_owned()
    }

    /// A confirmed grant, ready for the contact to ask.
    async fn confirmed(&self, kind: &str, days: u32) -> String {
        let id = self.invite(kind, days).await;
        let accepted = self
            .kim(
                "POST",
                &format!("/kem/v1/emergency/grants/{id}/accept"),
                None,
            )
            .await;
        assert_eq!(accepted.status, StatusCode::OK, "{:?}", accepted.json());
        let confirmed = self
            .sam(
                "POST",
                &format!("/kem/v1/emergency/grants/{id}/confirm"),
                Some(json!({"sealedKey": sealed_box()})),
            )
            .await;
        assert_eq!(confirmed.status, StatusCode::OK, "{:?}", confirmed.json());
        id
    }
}

#[tokio::test]
async fn a_box_for_another_key_version_is_a_409_and_stores_nothing() {
    let s = scene().await;
    let id = s.invite("view", 7).await;
    let accepted = s
        .kim("POST", &format!("/kem/v1/emergency/grants/{id}/accept"), None)
        .await;
    assert_eq!(accepted.status, StatusCode::OK, "{:?}", accepted.json());
    let stale = s
        .sam(
            "POST",
            &format!("/kem/v1/emergency/grants/{id}/confirm"),
            Some(json!({"sealedKey": sealed_box(), "keyVersion": 99})),
        )
        .await;
    assert_eq!(stale.status, StatusCode::CONFLICT, "{:?}", stale.json());
    assert_eq!(stale.problem(), "key-version-stale");
    let current = stale.json()["currentKeyVersion"].clone();
    assert!(current.is_number(), "{:?}", stale.json());
    // Still waiting for a confirmation, and the right version is kept.
    let kept = s
        .sam(
            "POST",
            &format!("/kem/v1/emergency/grants/{id}/confirm"),
            Some(json!({"sealedKey": sealed_box(), "keyVersion": current})),
        )
        .await;
    assert_eq!(kept.status, StatusCode::OK, "{:?}", kept.json());
    assert_eq!(kept.json()["state"], "confirmed");
}

#[tokio::test]
async fn the_whole_path_from_invitation_to_the_sealed_key() {
    let mut s = scene().await;

    let invited = s
        .sam(
            "POST",
            "/kem/v1/emergency/grants",
            Some(json!({"email": CONTACT, "kind": "takeover", "waitDays": 7})),
        )
        .await;
    assert_eq!(invited.status, StatusCode::CREATED, "{:?}", invited.json());
    let invited = invited.json();
    let id = invited["id"].as_str().expect("id").to_owned();
    assert_eq!(invited["state"], "invited");
    assert_eq!(invited["granteeEmail"], CONTACT);
    assert_eq!(invited["kind"], "takeover");
    assert_eq!(invited["waitDays"], 7);
    assert!(invited.get("sealedKey").is_none());

    // The contact sees the invitation, and accepts it.
    let kim_list = s.kim("GET", "/kem/v1/emergency", None).await.json();
    assert_eq!(kim_list["grantors"][0]["grant"]["id"], id);
    assert_eq!(kim_list["grantors"][0]["grantorEmail"], GRANTOR);
    let accepted = s
        .kim(
            "POST",
            &format!("/kem/v1/emergency/grants/{id}/accept"),
            None,
        )
        .await;
    assert_eq!(accepted.status, StatusCode::OK, "{:?}", accepted.json());
    assert_eq!(accepted.json()["state"], "accepted");

    // The grantor sees the contact's keys to check and seal to.
    let sam_list = s.sam("GET", "/kem/v1/emergency", None).await.json();
    let view = &sam_list["trustedContacts"][0];
    assert_eq!(view["grant"]["id"], id);
    assert!(view["contactKeys"]["publicBundle"].as_str().is_some());
    assert!(view["contactKeys"]["keyVersion"].is_number());

    let confirmed = s
        .sam(
            "POST",
            &format!("/kem/v1/emergency/grants/{id}/confirm"),
            Some(json!({"sealedKey": sealed_box()})),
        )
        .await;
    assert_eq!(confirmed.status, StatusCode::OK, "{:?}", confirmed.json());
    assert_eq!(confirmed.json()["state"], "confirmed");

    // The contact asks; nothing is released yet.
    let started = s
        .kim(
            "POST",
            &format!("/kem/v1/emergency/grants/{id}/initiate"),
            None,
        )
        .await;
    assert_eq!(started.status, StatusCode::OK, "{:?}", started.json());
    let started = started.json();
    assert_eq!(started["state"], "recovery-initiated");
    assert!(started["dueAt"].as_str().is_some());
    let early = s
        .kim("GET", &format!("/kem/v1/emergency/grants/{id}/key"), None)
        .await;
    assert_eq!(early.status, StatusCode::FORBIDDEN);

    // The wait ends and the timer approves.
    s.app.clock.advance(Duration::days(7));
    assert_eq!(s.run_timer().await, 1);
    s.relogin().await;
    let released = s
        .kim("GET", &format!("/kem/v1/emergency/grants/{id}/key"), None)
        .await;
    assert_eq!(released.status, StatusCode::OK, "{:?}", released.json());
    let released = released.json();
    assert_eq!(released["sealedKey"], sealed_box());
    assert_eq!(released["kind"], "takeover");
    assert_eq!(released["grantId"], id);
}

#[tokio::test]
async fn the_grantors_refusal_beats_the_timer() {
    let mut s = scene().await;
    let id = s.confirmed("view", 7).await;
    let started = s
        .kim(
            "POST",
            &format!("/kem/v1/emergency/grants/{id}/initiate"),
            None,
        )
        .await;
    assert_eq!(started.status, StatusCode::OK);

    let rejected = s
        .sam(
            "POST",
            &format!("/kem/v1/emergency/grants/{id}/reject"),
            None,
        )
        .await;
    assert_eq!(rejected.status, StatusCode::OK, "{:?}", rejected.json());
    assert_eq!(rejected.json()["state"], "rejected");

    s.app.clock.advance(Duration::days(30));
    assert_eq!(s.run_timer().await, 0);
    s.relogin().await;
    let key = s
        .kim("GET", &format!("/kem/v1/emergency/grants/{id}/key"), None)
        .await;
    assert_eq!(key.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn the_grantor_can_approve_early() {
    let s = scene().await;
    let id = s.confirmed("view", 30).await;
    s.kim(
        "POST",
        &format!("/kem/v1/emergency/grants/{id}/initiate"),
        None,
    )
    .await;

    let approved = s
        .sam(
            "POST",
            &format!("/kem/v1/emergency/grants/{id}/approve"),
            None,
        )
        .await;
    assert_eq!(approved.status, StatusCode::OK, "{:?}", approved.json());

    let key = s
        .kim("GET", &format!("/kem/v1/emergency/grants/{id}/key"), None)
        .await;
    assert_eq!(key.status, StatusCode::OK);
    assert_eq!(key.json()["sealedKey"], sealed_box());
}

#[tokio::test]
async fn the_grantor_never_gets_the_contacts_box_and_a_stranger_gets_nothing() {
    let s = scene().await;
    let id = s.confirmed("view", 1).await;
    s.kim(
        "POST",
        &format!("/kem/v1/emergency/grants/{id}/initiate"),
        None,
    )
    .await;
    s.sam(
        "POST",
        &format!("/kem/v1/emergency/grants/{id}/approve"),
        None,
    )
    .await;

    let grantor = s
        .sam("GET", &format!("/kem/v1/emergency/grants/{id}/key"), None)
        .await;
    assert_eq!(grantor.status, StatusCode::NOT_FOUND);

    let stranger_client = s.app.client();
    let stranger = register_and_sign_in(&stranger_client, "lee@example.org").await;
    let reply = s
        .call(
            &stranger_client,
            &stranger,
            "GET",
            &format!("/kem/v1/emergency/grants/{id}/key"),
            None,
        )
        .await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
    let listed = s
        .call(
            &stranger_client,
            &stranger,
            "GET",
            "/kem/v1/emergency",
            None,
        )
        .await
        .json();
    assert_eq!(listed["trustedContacts"], json!([]));
    assert_eq!(listed["grantors"], json!([]));
}

#[tokio::test]
async fn lists_never_carry_the_sealed_key() {
    let s = scene().await;
    s.confirmed("takeover", 14).await;
    for reply in [
        s.sam("GET", "/kem/v1/emergency", None).await,
        s.kim("GET", "/kem/v1/emergency", None).await,
    ] {
        assert_eq!(reply.status, StatusCode::OK);
        let text = String::from_utf8_lossy(&reply.body).into_owned();
        assert!(!text.contains("sealedKey"), "{text}");
    }
}

#[tokio::test]
async fn invitations_are_checked() {
    let s = scene().await;
    for body in [
        json!({"email": CONTACT, "kind": "view", "waitDays": 0}),
        json!({"email": CONTACT, "kind": "view", "waitDays": 91}),
        json!({"email": GRANTOR, "kind": "view", "waitDays": 7}),
        json!({"email": "nope", "kind": "view", "waitDays": 7}),
        json!({"email": CONTACT, "kind": "own", "waitDays": 7}),
        json!({"email": CONTACT, "kind": "view"}),
    ] {
        let reply = s
            .sam("POST", "/kem/v1/emergency/grants", Some(body.clone()))
            .await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{body}");
    }
    s.invite("view", 7).await;
    let twice = s
        .sam(
            "POST",
            "/kem/v1/emergency/grants",
            Some(json!({"email": CONTACT, "kind": "takeover", "waitDays": 3})),
        )
        .await;
    assert_eq!(twice.status, StatusCode::CONFLICT);
    assert_eq!(twice.problem(), "already-exists");
}

#[tokio::test]
async fn steps_out_of_order_and_by_the_wrong_party_are_refused() {
    let s = scene().await;
    let id = s.invite("view", 7).await;
    let path = |step: &str| format!("/kem/v1/emergency/grants/{id}/{step}");

    // The grantor can't accept their own invitation; the contact can't confirm.
    assert_eq!(
        s.sam("POST", &path("accept"), None).await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        s.kim(
            "POST",
            &path("confirm"),
            Some(json!({"sealedKey": sealed_box()}))
        )
        .await
        .status,
        StatusCode::NOT_FOUND
    );
    // Confirming before the contact accepted is out of order.
    assert_eq!(
        s.sam(
            "POST",
            &path("confirm"),
            Some(json!({"sealedKey": sealed_box()}))
        )
        .await
        .status,
        StatusCode::BAD_REQUEST
    );
    s.kim("POST", &path("accept"), None).await;
    // A box of the wrong shape is refused.
    assert_eq!(
        s.sam(
            "POST",
            &path("confirm"),
            Some(json!({"sealedKey": b64(&[1u8; 20])}))
        )
        .await
        .status,
        StatusCode::BAD_REQUEST
    );
    // Asking before confirmation is out of order.
    assert_eq!(
        s.kim("POST", &path("initiate"), None).await.status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        s.sam("POST", "/kem/v1/emergency/grants/not-a-uuid/accept", None)
            .await
            .status,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn either_party_can_end_a_grant() {
    let s = scene().await;
    let id = s.confirmed("view", 7).await;
    let uri = format!("/kem/v1/emergency/grants/{id}");

    let stranger_client = s.app.client();
    let stranger = register_and_sign_in(&stranger_client, "lee@example.org").await;
    let denied = s
        .call(&stranger_client, &stranger, "DELETE", &uri, None)
        .await;
    assert_eq!(denied.status, StatusCode::NOT_FOUND);

    let gone = s.kim("DELETE", &uri, None).await;
    assert_eq!(gone.status, StatusCode::NO_CONTENT);
    let listed = s.sam("GET", "/kem/v1/emergency", None).await.json();
    assert_eq!(listed["trustedContacts"], json!([]));
    assert_eq!(
        s.sam("DELETE", &uri, None).await.status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn emergency_routes_need_a_signed_in_device() {
    let s = scene().await;
    let reply = s.sam.get("/kem/v1/emergency").await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
}
