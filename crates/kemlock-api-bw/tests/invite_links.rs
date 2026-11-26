//! The invitation links the Kemlock API and the admin API are given (`invite_links`): the same link
//! as the Bitwarden route, for a caller those APIs already authenticated. The rules are the
//! route's: the space is a Bitwarden organization, the asker is a confirmed admin (an owner for a
//! manager, admin or owner), and the member is still invited.

mod common;

use axum::http::StatusCode;
use common::{DOMAIN, Harness};
use kemlock_app::bitwarden::{Asker, InviteLinkError, MemberInviteLink};
use kemlock_domain::{SpaceId, UserId};
use serde_json::{Value, json};
use uuid::Uuid;

const ORG_KEY: &str = "4.orgkeywrappedforthefirstowner";

/// An organization of `owner`, as the web vault makes one.
async fn organization(h: &Harness, owner: &str) -> String {
    let (status, org) = h
        .json(
            "POST",
            "/api/organizations",
            Some(owner),
            Some(json!({
                "name": "Link organization",
                "billingEmail": "billing@example.com",
                "planType": 0,
                "key": ORG_KEY,
                "keys": {"publicKey": "MIIBIjANorganizationpublickey", "encryptedPrivateKey": "2.orgprivate|key|mac"},
                "collectionName": "2.defaultcollection|name|mac"
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{org}");
    org["id"].as_str().expect("an id").to_owned()
}

/// Invites `email` with Bitwarden's member type `kind` (0 owner, 1 admin, 2 user).
async fn invite(h: &Harness, owner: &str, org: &str, email: &str, kind: i32) {
    let (status, body) = h
        .json(
            "POST",
            &format!("/api/organizations/{org}/users/invite"),
            Some(owner),
            Some(json!({"emails": [email], "type": kind, "collections": [], "groups": []})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// The invitee accepts in the web vault's space page, and the owner confirms.
async fn confirmed(h: &Harness, owner: &str, org: &str, member: UserId) {
    h.accept_in_space(org, member).await;
    let (status, body) = h
        .json(
            "POST",
            &format!("/api/organizations/{org}/users/{member}/confirm"),
            Some(owner),
            Some(json!({"key": "junk"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

fn space(org: &str) -> SpaceId {
    SpaceId(org.parse::<Uuid>().expect("an organization id"))
}

async fn link(
    h: &Harness,
    org: &str,
    member: UserId,
    asker: Asker,
) -> Result<MemberInviteLink, InviteLinkError> {
    h.links.member_link(space(org), member, asker).await
}

fn token_of(link: &str) -> String {
    link.rsplit_once("token=")
        .map(|(_, token)| token.to_owned())
        .expect("a link with a token")
}

async fn accept_without_signing_in(
    h: &Harness,
    org: &str,
    member: UserId,
    token: &str,
) -> (StatusCode, Value) {
    h.json(
        "POST",
        &format!("/api/organizations/{org}/users/{member}/accept"),
        None,
        Some(json!({"token": token})),
    )
    .await
}

#[tokio::test]
async fn an_owner_gets_the_link_of_an_invited_account_and_it_accepts() {
    let h = Harness::new().await;
    let (ada, ada_id) = h.signed_in("ada@example.com").await;
    let (_bob, bob_id) = h.signed_in("bob@example.com").await;
    let org = organization(&h, &ada).await;
    invite(&h, &ada, &org, "bob@example.com", 2).await;

    let given = link(&h, &org, bob_id, Asker::Member(ada_id))
        .await
        .expect("a link");
    assert!(
        given.link.starts_with(&format!(
            "{DOMAIN}/#/accept-organization/?organizationId={org}"
        )),
        "{}",
        given.link
    );
    // Five days, as Vaultwarden's invitations last.
    assert_eq!(
        given.expires_at,
        h.env.time().unix_timestamp() + 5 * 24 * 3600
    );

    // The same link as the Bitwarden route's, and it accepts for the account.
    let (status, body) = h
        .json(
            "GET",
            &format!("/api/organizations/{org}/users/{bob_id}/invite-link"),
            Some(&ada),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["link"], given.link);
    let (status, body) = accept_without_signing_in(&h, &org, bob_id, &token_of(&given.link)).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // Accepted, there is nothing to hand over.
    assert_eq!(
        link(&h, &org, bob_id, Asker::Member(ada_id)).await,
        Err(InviteLinkError::NotInvited)
    );
    assert_eq!(
        link(&h, &org, bob_id, Asker::Server).await,
        Err(InviteLinkError::NotInvited)
    );
}

#[tokio::test]
async fn an_admin_hands_over_a_users_link_and_an_owner_a_managers_or_admins() {
    let h = Harness::new().await;
    let (ada, ada_id) = h.signed_in("ada@example.com").await;
    let (_carol, carol_id) = h.signed_in("carol@example.com").await;
    let (_dave, dave_id) = h.signed_in("dave@example.com").await;
    let (_erin, erin_id) = h.signed_in("erin@example.com").await;
    let org = organization(&h, &ada).await;
    invite(&h, &ada, &org, "carol@example.com", 1).await;
    confirmed(&h, &ada, &org, carol_id).await;
    invite(&h, &ada, &org, "dave@example.com", 2).await;
    invite(&h, &ada, &org, "erin@example.com", 1).await;

    // An admin may hand over the invitation of a plain user, not of an admin.
    assert!(
        link(&h, &org, dave_id, Asker::Member(carol_id))
            .await
            .is_ok()
    );
    assert!(matches!(
        link(&h, &org, erin_id, Asker::Member(carol_id)).await,
        Err(InviteLinkError::Forbidden(_))
    ));
    // The owner may, and so may the server admin.
    assert!(link(&h, &org, erin_id, Asker::Member(ada_id)).await.is_ok());
    assert!(link(&h, &org, erin_id, Asker::Server).await.is_ok());
}

#[tokio::test]
async fn only_a_confirmed_admin_of_the_organization_may_ask() {
    let h = Harness::new().await;
    let (ada, _ada_id) = h.signed_in("ada@example.com").await;
    let (_bob, bob_id) = h.signed_in("bob@example.com").await;
    let (_cy, cy_id) = h.signed_in("cy@example.com").await;
    let (_dave, dave_id) = h.signed_in("dave@example.com").await;
    let (_stranger, stranger_id) = h.signed_in("stranger@example.com").await;
    let org = organization(&h, &ada).await;
    invite(&h, &ada, &org, "bob@example.com", 2).await;
    invite(&h, &ada, &org, "cy@example.com", 2).await;
    confirmed(&h, &ada, &org, cy_id).await;
    invite(&h, &ada, &org, "dave@example.com", 2).await;

    // An invited member, and a confirmed plain member, are not administrators.
    for asker in [bob_id, cy_id] {
        assert!(
            matches!(
                link(&h, &org, dave_id, Asker::Member(asker)).await,
                Err(InviteLinkError::Forbidden(_))
            ),
            "{asker}"
        );
    }
    // Someone outside the organization learns nothing of it.
    assert_eq!(
        link(&h, &org, dave_id, Asker::Member(stranger_id)).await,
        Err(InviteLinkError::NotFound)
    );
}

#[tokio::test]
async fn a_space_that_is_not_an_organization_has_no_link() {
    let h = Harness::new().await;
    let (_ada, ada_id) = h.signed_in("ada@example.com").await;
    let nowhere = SpaceId(Uuid::new_v4());
    for asker in [Asker::Member(ada_id), Asker::Server] {
        assert_eq!(
            h.links.member_link(nowhere, ada_id, asker).await,
            Err(InviteLinkError::NotOrganization)
        );
    }
}

#[tokio::test]
async fn someone_who_was_never_invited_has_no_link() {
    let h = Harness::new().await;
    let (ada, ada_id) = h.signed_in("ada@example.com").await;
    let (_bob, bob_id) = h.signed_in("bob@example.com").await;
    let org = organization(&h, &ada).await;
    assert_eq!(
        link(&h, &org, bob_id, Asker::Member(ada_id)).await,
        Err(InviteLinkError::NotFound)
    );
    assert_eq!(
        link(&h, &org, bob_id, Asker::Server).await,
        Err(InviteLinkError::NotFound)
    );
}

#[tokio::test]
async fn the_bitwarden_route_gives_its_link_with_no_cache() {
    let h = Harness::new().await;
    let (ada, _) = h.signed_in("ada@example.com").await;
    let (_bob, bob_id) = h.signed_in("bob@example.com").await;
    let org = organization(&h, &ada).await;
    invite(&h, &ada, &org, "bob@example.com", 2).await;

    let bearer = format!("Bearer {ada}");
    let (status, headers, _) = h
        .send(
            "GET",
            &format!("/api/organizations/{org}/users/{bob_id}/invite-link"),
            &[("authorization", bearer.as_str())],
            axum::body::Body::empty(),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers.get("cache-control").and_then(|v| v.to_str().ok()),
        Some("no-store")
    );
}
