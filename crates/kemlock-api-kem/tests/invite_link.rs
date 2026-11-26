//! The accept link of a Bitwarden invitation, `GET /kem/v1/spaces/{id}/members/{user}/invite-link`,
//! in-process. The Bitwarden API's links are a fake that records who asked and answers what a test
//! set; the real rules (who may ask, who is still invited) are tested with that API.

mod common;

use axum::Extension;
use axum::Router;
use axum::http::StatusCode;
use common::{App, Client, Session, register_and_sign_in};
use kemlock_api_kem::invite_link_router;
use kemlock_api_kem::testing::DpopSigner;
use kemlock_app::bitwarden::{
    Asker, BwInviteLinks, InviteLinkError, MemberInviteLink, SharedInviteLinks,
};
use kemlock_app::notices::BoxFuture;
use kemlock_domain::{SpaceId, UserId};
use std::str::FromStr;
use std::sync::{Arc, Mutex};

const LINK: &str = "https://vault.test/#/accept-organization/?token=secret";

#[derive(Clone)]
struct FakeLinks {
    asked: Arc<Mutex<Vec<(SpaceId, UserId, Asker)>>>,
    answer: Result<MemberInviteLink, InviteLinkError>,
}

impl FakeLinks {
    fn answering(answer: Result<MemberInviteLink, InviteLinkError>) -> Self {
        FakeLinks {
            asked: Arc::default(),
            answer,
        }
    }

    fn working() -> Self {
        Self::answering(Ok(MemberInviteLink {
            link: LINK.to_owned(),
            expires_at: 1_800_000_000,
        }))
    }

    fn asked(&self) -> Vec<(SpaceId, UserId, Asker)> {
        self.asked.lock().expect("the lock isn't poisoned").clone()
    }
}

impl BwInviteLinks for FakeLinks {
    fn member_link(
        &self,
        space: SpaceId,
        member: UserId,
        asker: Asker,
    ) -> BoxFuture<'_, Result<MemberInviteLink, InviteLinkError>> {
        Box::pin(async move {
            self.asked
                .lock()
                .expect("the lock isn't poisoned")
                .push((space, member, asker));
            self.answer.clone()
        })
    }

    fn is_organization(&self, _space: SpaceId) -> BoxFuture<'_, bool> {
        Box::pin(async move { !matches!(self.answer, Err(InviteLinkError::NotOrganization)) })
    }

    fn pending_invitations(&self, _space: SpaceId) -> BoxFuture<'_, Option<Vec<UserId>>> {
        Box::pin(async { None })
    }
}

/// A device signed in to a server with these links, or with none.
async fn signed_in(links: Option<&FakeLinks>) -> (Client, Session) {
    let app = App::new(true);
    let mut router: Router = app
        .router
        .clone()
        .merge(invite_link_router(app.api.clone()));
    if let Some(links) = links {
        let shared: SharedInviteLinks = Arc::new(links.clone());
        router = router.layer(Extension(shared));
    }
    let client = Client::new(router, app.clock.clone(), DpopSigner::es256());
    let session = register_and_sign_in(&client, "ada@example.org").await;
    (client, session)
}

fn uri(space: SpaceId, member: UserId) -> String {
    format!("/kem/v1/spaces/{space}/members/{member}/invite-link")
}

#[tokio::test]
async fn an_admin_of_the_organization_gets_the_link_and_nobody_caches_it() {
    let links = FakeLinks::working();
    let (client, session) = signed_in(Some(&links)).await;
    let (space, member) = (SpaceId::random(), UserId::random());

    let reply = client
        .get_authed(&uri(space, member), &session.access_token)
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.json());
    assert_eq!(reply.json()["link"], LINK);
    assert_eq!(reply.json()["expiresAt"], 1_800_000_000);
    assert_eq!(reply.header("cache-control"), Some("no-store"));
    // The asker is the signed-in account, never a name the request carries.
    let caller = UserId::from_str(&session.user_id).expect("a user id");
    assert_eq!(links.asked(), [(space, member, Asker::Member(caller))]);
}

#[tokio::test]
async fn the_link_needs_a_signed_in_device() {
    let links = FakeLinks::working();
    let (client, _session) = signed_in(Some(&links)).await;
    let reply = client.get(&uri(SpaceId::random(), UserId::random())).await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert!(links.asked().is_empty());
}

#[tokio::test]
async fn each_refusal_of_the_links_has_its_answer() {
    for (refusal, status, slug) in [
        (InviteLinkError::NotOrganization, StatusCode::NOT_FOUND, ""),
        (InviteLinkError::NotFound, StatusCode::NOT_FOUND, ""),
        (
            InviteLinkError::Forbidden("only a confirmed owner or admin may"),
            StatusCode::FORBIDDEN,
            "forbidden",
        ),
        (
            InviteLinkError::NotInvited,
            StatusCode::CONFLICT,
            "not-invited",
        ),
    ] {
        let links = FakeLinks::answering(Err(refusal.clone()));
        let (client, session) = signed_in(Some(&links)).await;
        let reply = client
            .get_authed(
                &uri(SpaceId::random(), UserId::random()),
                &session.access_token,
            )
            .await;
        assert_eq!(reply.status, status, "{refusal:?}: {:?}", reply.json());
        assert_eq!(reply.content_type(), "application/problem+json");
        if !slug.is_empty() {
            assert_eq!(reply.problem(), slug, "{refusal:?}");
        }
        assert!(
            reply.json().get("link").is_none(),
            "a refusal carries no link"
        );
    }
}

#[tokio::test]
async fn a_server_without_the_bitwarden_api_has_no_organizations() {
    let (client, session) = signed_in(None).await;
    let reply = client
        .get_authed(
            &uri(SpaceId::random(), UserId::random()),
            &session.access_token,
        )
        .await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn ids_that_arent_uuids_are_a_bad_request_and_ask_nothing() {
    let links = FakeLinks::working();
    let (client, session) = signed_in(Some(&links)).await;
    for path in [
        "/kem/v1/spaces/not-a-space/members/not-a-member/invite-link".to_owned(),
        format!(
            "/kem/v1/spaces/{}/members/not-a-member/invite-link",
            SpaceId::random()
        ),
    ] {
        let reply = client.get_authed(&path, &session.access_token).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{path}");
    }
    assert!(links.asked().is_empty());
}
