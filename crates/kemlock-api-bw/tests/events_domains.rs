//! Client-reported events and equivalent domains through the router, with the shapes and
//! messages of Vaultwarden 1.37.5.

mod common;

use axum::http::StatusCode;
use common::Harness;
use kemlock_app::spaces::{SpaceChanges, SpaceRepo};
use kemlock_domain::spaces::{CustomPermissions, Member, MemberState, Space, SpaceRole};
use kemlock_domain::{SpaceId, UserId};
use serde_json::{Value, json};
use uuid::Uuid;

fn sorted_keys(value: &Value) -> Vec<String> {
    let mut keys: Vec<String> = value
        .as_object()
        .expect("an object")
        .keys()
        .cloned()
        .collect();
    keys.sort();
    keys
}

/// A space the user is a confirmed member of, with `role`.
async fn space_with(h: &Harness, user: UserId, role: SpaceRole) -> Uuid {
    let id = SpaceId::random();
    let now = h.env.time();
    let mut changes = SpaceChanges::new(id);
    changes.space = Some(Space {
        id,
        name: b"Contract organization".to_vec(),
        key_version: 1,
        keys_pending_since: None,
        created_at: now,
        updated_at: now,
    });
    let mut member = Member::invited(id, user, role, CustomPermissions::NONE, user, now);
    member.state = MemberState::Confirmed;
    changes.members.push(member);
    SpaceRepo::create(&h.store, changes).await.expect("a space");
    id.0
}

const RANGE: &str = "start=2026-11-01T00:00:00Z&end=2026-12-01T00:00:00Z";

#[tokio::test]
async fn collected_events_are_accepted_and_what_a_client_can_not_forge_is_ignored() {
    let h = Harness::new().await;
    let (token, user) = h.signed_in("ada@example.com").await;
    let org = space_with(&h, user, SpaceRole::Member).await;
    let stranger = Uuid::new_v4();

    let events = json!([
        // A vault export, a banner click, an organization export and a cipher view.
        {"type": 1007, "date": "2026-11-21T12:00:00.000Z"},
        {"type": 1522, "date": "2026-11-21T12:00:00.000Z", "organizationId": org.to_string()},
        {"type": 1602, "date": "2026-11-21T12:00:00.000Z", "organizationId": org.to_string()},
        {"type": 1107, "date": "2026-11-21T12:00:00.000Z", "cipherId": Uuid::new_v4().to_string()},
        // An organization the account is not in, and a type only the server writes.
        {"type": 1602, "date": "2026-11-21T12:00:00.000Z", "organizationId": stranger.to_string()},
        {"type": 1000, "date": "2026-11-21T12:00:00.000Z"},
        {"type": 9999, "date": "2026-11-21T12:00:00.000Z"}
    ]);
    let (status, body) = h
        .json("POST", "/events/collect", Some(&token), Some(events))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.is_null(), "Vaultwarden answers with an empty body");

    let (status, body) = h
        .json("POST", "/events/collect", Some(&token), Some(json!([])))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn a_collected_event_needs_a_token_a_list_and_a_date() {
    let h = Harness::new().await;
    let (token, _) = h.signed_in("ada@example.com").await;

    let (status, _) = h
        .json("POST", "/events/collect", None, Some(json!([])))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, _) = h
        .json(
            "POST",
            "/events/collect",
            Some(&token),
            Some(json!({"type": 1007})),
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    let (status, body) = h
        .json(
            "POST",
            "/events/collect",
            Some(&token),
            Some(json!([{"type": 1007, "date": "last tuesday"}])),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "Invalid event date");
}

#[tokio::test]
async fn the_event_lists_answer_an_empty_page_to_admins_and_nobody_else() {
    let h = Harness::new().await;
    let (admin, admin_id) = h.signed_in("ada@example.com").await;
    let (member, member_id) = h.signed_in("bob@example.com").await;
    let org = space_with(&h, admin_id, SpaceRole::Owner).await;
    // Bob is in Ada's organization as an ordinary member.
    let now = h.env.time();
    let mut bob = Member::invited(
        SpaceId(org),
        member_id,
        SpaceRole::Member,
        CustomPermissions::NONE,
        admin_id,
        now,
    );
    bob.state = MemberState::Confirmed;
    let mut changes = SpaceChanges::new(SpaceId(org));
    changes.members.push(bob);
    SpaceRepo::apply(&h.store, changes).await.expect("a member");

    let uri = format!("/api/organizations/{org}/events?{RANGE}");
    let (status, page) = h.json("GET", &uri, Some(&admin), None).await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(sorted_keys(&page), ["continuationToken", "data", "object"]);
    assert_eq!(page["data"], json!([]));
    assert_eq!(page["object"], "list");
    assert!(page["continuationToken"].is_null());

    let uri = format!("/api/organizations/{org}/users/{member_id}/events?{RANGE}");
    let (status, page) = h.json("GET", &uri, Some(&admin), None).await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(page["data"], json!([]));

    // A member who isn't an admin gets a 401, as does anyone with no membership at all.
    let uri = format!("/api/organizations/{org}/events?{RANGE}");
    let (status, _) = h.json("GET", &uri, Some(&member), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let other = Uuid::new_v4();
    let (status, _) = h
        .json(
            "GET",
            &format!("/api/organizations/{other}/events?{RANGE}"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Without its date range the route matches nothing.
    let (status, _) = h
        .json(
            "GET",
            &format!("/api/organizations/{org}/events"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // A cipher's events are an empty page for anyone signed in.
    let (status, page) = h
        .json(
            "GET",
            &format!("/api/ciphers/{}/events?{RANGE}", Uuid::new_v4()),
            Some(&member),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(page["data"], json!([]));
}

async fn revision(h: &Harness, token: &str) -> i64 {
    h.json("GET", "/api/accounts/revision-date", Some(token), None)
        .await
        .1
        .as_i64()
        .expect("a number")
}

#[tokio::test]
async fn the_domains_start_as_bitwardens_list_with_none_excluded() {
    let h = Harness::new().await;
    let (token, _) = h.signed_in("ada@example.com").await;

    let (status, domains) = h
        .json("GET", "/api/settings/domains", Some(&token), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{domains}");
    assert_eq!(
        sorted_keys(&domains),
        ["equivalentDomains", "globalEquivalentDomains", "object"]
    );
    assert_eq!(domains["object"], "domains");
    assert_eq!(domains["equivalentDomains"], json!([]));
    let globals = domains["globalEquivalentDomains"]
        .as_array()
        .expect("a list");
    assert!(globals.len() > 20);
    for global in globals {
        assert_eq!(sorted_keys(global), ["domains", "excluded", "type"]);
        assert_eq!(global["excluded"], false);
        assert!(global["domains"].as_array().is_some_and(|d| d.len() > 1));
    }
    let youtube = globals
        .iter()
        .find(|g| g["type"] == 0)
        .expect("Bitwarden's type 0");
    assert!(
        youtube["domains"]
            .as_array()
            .is_some_and(|d| d.contains(&json!("youtube.com")))
    );
}

#[tokio::test]
async fn an_accounts_choices_are_kept_flagged_and_left_out_of_a_sync() {
    let h = Harness::new().await;
    let (token, _) = h.signed_in("ada@example.com").await;
    let before = revision(&h, &token).await;

    for method in ["POST", "PUT"] {
        let (status, body) = h
            .json(
                method,
                "/api/settings/domains",
                Some(&token),
                Some(json!({
                    "excludedGlobalEquivalentDomains": [0, 3],
                    "equivalentDomains": [["a.example", "b.example"], ["c.example", "d.example"]]
                })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{method} {body}");
        assert_eq!(body, json!({}));
    }
    assert!(
        revision(&h, &token).await > before,
        "a save moves the revision date"
    );

    let (_, domains) = h
        .json("GET", "/api/settings/domains", Some(&token), None)
        .await;
    assert_eq!(
        domains["equivalentDomains"],
        json!([["a.example", "b.example"], ["c.example", "d.example"]])
    );
    let globals = domains["globalEquivalentDomains"]
        .as_array()
        .expect("a list");
    for global in globals {
        let excluded = global["type"] == 0 || global["type"] == 3;
        assert_eq!(global["excluded"], excluded, "{global}");
    }

    // A sync leaves the excluded sets out, and a client may ask not to have the object at all.
    let (_, sync) = h.json("GET", "/api/sync", Some(&token), None).await;
    let synced = sync["domains"]["globalEquivalentDomains"]
        .as_array()
        .expect("a list");
    assert_eq!(synced.len(), globals.len() - 2);
    assert!(synced.iter().all(|g| g["excluded"] == false));
    assert_eq!(
        sync["domains"]["equivalentDomains"],
        domains["equivalentDomains"]
    );
    let (_, sync) = h
        .json("GET", "/api/sync?excludeDomains=true", Some(&token), None)
        .await;
    assert!(sync["domains"].is_null());

    // A save with nothing in it clears both.
    let (status, _) = h
        .json(
            "POST",
            "/api/settings/domains",
            Some(&token),
            Some(json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (_, cleared) = h
        .json("GET", "/api/settings/domains", Some(&token), None)
        .await;
    assert_eq!(cleared["equivalentDomains"], json!([]));
    assert!(
        cleared["globalEquivalentDomains"]
            .as_array()
            .is_some_and(|g| g.iter().all(|g| g["excluded"] == false))
    );
}

#[tokio::test]
async fn one_accounts_domains_are_not_anothers() {
    let h = Harness::new().await;
    let (ada, _) = h.signed_in("ada@example.com").await;
    let (bob, _) = h.signed_in("bob@example.com").await;
    h.json(
        "POST",
        "/api/settings/domains",
        Some(&ada),
        Some(json!({"equivalentDomains": [["x.example", "y.example"]]})),
    )
    .await;
    let (_, domains) = h
        .json("GET", "/api/settings/domains", Some(&bob), None)
        .await;
    assert_eq!(domains["equivalentDomains"], json!([]));
}
