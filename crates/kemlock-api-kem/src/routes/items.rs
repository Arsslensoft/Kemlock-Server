//! Items and sync: `PUT /items/{id}`, `POST /items:batch`, `GET /sync` and `GET /live`.

use super::view::MaybeView;
use crate::dto::{
    BatchResponse, ItemDto, ResolveResponse, SiblingSetDto, SyncBody, SyncQuery, SyncResponse,
};
use crate::extract::{Authed, Body};
use crate::problem::Problem;
use crate::routes::duplicates::{batch_with_tags, item_with_tags};
use crate::routes::spaces::{Caller, Env, nonce_header};
use crate::state::{Crypto, Store};
use axum::extract::rejection::QueryRejection;
use axum::extract::ws::WebSocketUpgrade;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use kemlock_app::ports::{ItemStore, StoreError, TokenSigner};
use kemlock_app::spaces::sync_owners::owners_of;
use kemlock_app::spaces::{SpaceRepo, SpacesError};
use kemlock_app::{AppError, SyncOutcome, b64url};
use kemlock_domain::spaces::CollectionId;
use kemlock_domain::{ItemId, Owner, Revision, SyncCursor};
use std::collections::BTreeMap;

/// A revision from an `If-Match` value: `4`, `"4"` or `W/"4"`.
pub(super) fn parse_revision(value: &HeaderValue) -> Result<Revision, Problem> {
    let text = value
        .to_str()
        .map_err(|_| Problem::bad_request("If-Match isn't text"))?
        .trim();
    let text = text.strip_prefix("W/").unwrap_or(text).trim_matches('"');
    text.parse::<u64>()
        .map(Revision)
        .map_err(|_| Problem::bad_request("If-Match must be the revision number"))
}

/// The revision a write expects: `If-Match: <revision>` for a replace, `If-None-Match: *` for a
/// new item. One of the two is required.
fn expected_revision(headers: &HeaderMap) -> Result<Option<Revision>, Problem> {
    match (
        headers.get(header::IF_MATCH),
        headers.get(header::IF_NONE_MATCH),
    ) {
        (Some(_), Some(_)) => Err(Problem::bad_request(
            "send If-Match or If-None-Match, not both",
        )),
        (Some(value), None) => parse_revision(value).map(Some),
        (None, Some(value)) if value.as_bytes().trim_ascii() == b"*" => Ok(None),
        (None, Some(_)) => Err(Problem::bad_request("If-None-Match must be *")),
        (None, None) => Err(Problem::precondition_required(
            "send If-Match: <revision>, or If-None-Match: * for a new item",
        )),
    }
}

/// The cursor in an `If-None-Match` value, when the client uses the ETag it was given.
fn etag_cursor(headers: &HeaderMap) -> Option<String> {
    let text = headers.get(header::IF_NONE_MATCH)?.to_str().ok()?.trim();
    let text = text.strip_prefix("W/").unwrap_or(text).trim_matches('"');
    (!text.is_empty() && text != "*").then(|| text.to_owned())
}

fn etag(value: &str) -> Result<HeaderValue, Problem> {
    HeaderValue::from_str(&format!("\"{value}\""))
        .map_err(|_| Problem::bad_request("the value can't be an ETag"))
}

/// `PUT /kem/v1/items/{id}`: creates, replaces or deletes one item. `If-Match: <revision>`
/// names the revision replaced; `If-None-Match: *` makes a new item. A stale write is a 409
/// that names the current revision.
async fn put_item<S, P, K, R>(
    State(env): State<Env<S, P, K, R>>,
    caller: Caller,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + Clone + 'static,
{
    let id: ItemId = id
        .parse()
        .map_err(|_| Problem::bad_request("the item id isn't a UUID"))?;
    let expected = expected_revision(&headers)?;
    let (dto, tags) = item_with_tags(&body)?;
    if dto.id != id {
        return Err(Problem::bad_request("the body's id isn't the path's id"));
    }
    let collection = dto.collection();
    let write = dto.into_write(expected)?;
    let actor = caller.actor();
    let item = match (write.owner, collection) {
        (Owner::User(_), None) => env.api.put_item().execute(&actor, write).await?,
        (Owner::User(_), Some(_)) => {
            return Err(Problem::bad_request(
                "an item of a vault has no collectionId",
            ));
        }
        (Owner::Space(_), None) => {
            return Err(Problem::bad_request(
                "an item of a space needs a collectionId",
            ));
        }
        (Owner::Space(_), Some(collection)) => {
            env.api
                .put_space_item(env.spaces.clone())
                .execute(&actor, collection, write)
                .await?
        }
    };
    let status = if expected.is_none() {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    let mut response = match tags {
        None => (
            status,
            Json(ItemDto::from_item(&item).in_collection(collection)),
        )
            .into_response(),
        Some(tags) => {
            let mut answer = env
                .api
                .answer_with_tags(env.spaces.clone(), &actor, &item, tags)
                .await;
            if let Some(c) = collection {
                answer["collectionId"] = serde_json::json!(c);
            }
            (status, Json(answer)).into_response()
        }
    };
    response
        .headers_mut()
        .insert(header::ETAG, etag(&item.revision.0.to_string())?);
    Ok(response)
}

/// `POST /kem/v1/items:batch`: up to 500 puts and deletes, all or none.
async fn put_batch<S, P, K, R>(
    State(env): State<Env<S, P, K, R>>,
    caller: Caller,
    body: Body,
) -> Result<Response, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + Clone + 'static,
{
    let (request, tags) = batch_with_tags(&body)?;
    let mut writes = Vec::with_capacity(request.writes.len());
    for w in request.writes {
        let collection = w.item.collection();
        let write = w.item.into_write(w.expected_revision.map(Revision))?;
        writes.push((write, collection));
    }
    let actor = caller.actor();
    // A batch of vault items alone is the plain batch; one that names a space or a collection
    // goes through the spaces' step, which stores vault and space items together.
    if writes
        .iter()
        .all(|(w, c)| matches!(w.owner, Owner::User(_)) && c.is_none())
    {
        let writes = writes.into_iter().map(|(w, _)| w).collect();
        let stored = env.api.put_batch().execute(&actor, writes).await?;
        if tags.is_empty() {
            return Ok(Json(BatchResponse {
                items: stored.iter().map(ItemDto::from_item).collect(),
            })
            .into_response());
        }
        let answer = env
            .api
            .answer_batch_with_tags(env.spaces.clone(), &actor, &stored, tags)
            .await;
        return Ok(Json(answer).into_response());
    }
    let collections: BTreeMap<ItemId, CollectionId> = writes
        .iter()
        .filter_map(|(w, c)| c.map(|c| (w.id, c)))
        .collect();
    let stored = env
        .api
        .put_space_batch(env.spaces.clone())
        .execute(&actor, writes)
        .await?;
    if !tags.is_empty() {
        let mut answer = env
            .api
            .answer_batch_with_tags(env.spaces.clone(), &actor, &stored, tags)
            .await;
        if let Some(items) = answer
            .get_mut("items")
            .and_then(serde_json::Value::as_array_mut)
        {
            for (shown, item) in items.iter_mut().zip(&stored) {
                if let Some(c) = collections.get(&item.id) {
                    shown["collectionId"] = serde_json::json!(c);
                }
            }
        }
        return Ok(Json(answer).into_response());
    }
    Ok(Json(BatchResponse {
        items: stored
            .iter()
            .map(|i| ItemDto::from_item(i).in_collection(collections.get(&i.id).copied()))
            .collect(),
    })
    .into_response())
}

/// The header that carries the sync cursor, for a cursor too long for a URL.
pub(crate) const SYNC_CURSOR_HEADER: &str = "kemlock-sync-cursor";

/// The cursor text in the `Kemlock-Sync-Cursor` header, if the request has one.
fn cursor_header(headers: &HeaderMap) -> Result<Option<String>, Problem> {
    headers
        .get(SYNC_CURSOR_HEADER)
        .map(|value| {
            value
                .to_str()
                .map(|text| text.trim().to_owned())
                .map_err(|_| Problem::bad_request("Kemlock-Sync-Cursor isn't text"))
        })
        .transpose()
}

/// `GET /kem/v1/sync?since=<cursor>`: what changed since the cursor, in the account's own vault
/// and in every space it is a confirmed member of. 304 when nothing did, 410 when the cursor is
/// too old to trust. The cursor grows with the spaces, so it may also come in the
/// `Kemlock-Sync-Cursor` header (`since` wins when both are sent).
async fn sync<S, P, K, R>(
    State(env): State<Env<S, P, K, R>>,
    caller: Caller,
    view: MaybeView,
    headers: HeaderMap,
    query: Result<Query<SyncQuery>, QueryRejection>,
) -> Result<Response, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + Clone + 'static,
{
    let Query(query) = query.map_err(|e| Problem::bad_request(e.body_text()))?;
    let since = match query.since {
        Some(text) => Some(text),
        None => cursor_header(&headers)?,
    };
    run_sync(&env, &caller, view, &headers, since, query.limit).await
}

/// `POST /kem/v1/sync` with `{"since": <cursor>, "limit": <n>}`: the same answers as the `GET`,
/// for a cursor that fits neither a URL nor a header. Both members are optional; the
/// `Kemlock-Sync-Cursor` header is read when the body has no `since`.
async fn sync_post<S, P, K, R>(
    State(env): State<Env<S, P, K, R>>,
    caller: Caller,
    view: MaybeView,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + Clone + 'static,
{
    let request: SyncBody = if body.0.trim_ascii().is_empty() {
        SyncBody::default()
    } else {
        body.json()?
    };
    let since = match request.since {
        Some(text) => Some(text),
        None => cursor_header(&headers)?,
    };
    run_sync(&env, &caller, view, &headers, since, request.limit).await
}

/// The sync both routes answer with. `since` is the cursor as sent; `If-None-Match` stands in
/// for it when the request names none.
async fn run_sync<S, P, K, R>(
    env: &Env<S, P, K, R>,
    caller: &Caller,
    MaybeView(view): MaybeView,
    headers: &HeaderMap,
    since: Option<String>,
    limit: Option<u32>,
) -> Result<Response, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + Clone + 'static,
{
    let since = match since.or_else(|| etag_cursor(headers)) {
        None => SyncCursor::default(),
        // A cursor that can't be read is one this server didn't give. Versions 1 and 2 are read;
        // see `SyncCursor`.
        Some(text) => b64url::decode(&text)
            .and_then(|bytes| SyncCursor::from_cursor_bytes(&bytes).ok())
            .ok_or(AppError::FullSyncRequired)?,
    };
    let outcome = env
        .api
        .sync_delta(env.spaces.clone())
        .execute(caller.actor().user, &since, limit)
        .await?;
    match outcome {
        SyncOutcome::Unchanged => {
            let tag = etag(&b64url::encode(&since.to_cursor_bytes()))?;
            Ok((StatusCode::NOT_MODIFIED, [(header::ETAG, tag)]).into_response())
        }
        SyncOutcome::Page(page) => {
            let cursor = b64url::encode(&page.next.to_cursor_bytes());
            let more = page.more;
            let tag = etag(&cursor)?;
            // The collection of each item of a space, which a reader needs to find its key.
            let space_items: Vec<ItemId> = page
                .items
                .iter()
                .filter(|i| matches!(i.owner, Owner::Space(_)))
                .map(|i| i.id)
                .collect();
            let collections: BTreeMap<ItemId, CollectionId> = if space_items.is_empty() {
                BTreeMap::new()
            } else {
                env.spaces
                    .item_collections(&space_items)
                    .await
                    .map_err(SpacesError::from)?
                    .into_iter()
                    .collect()
            };
            // The siblings of the account's own vault, listed on every page that isn't a 304, so a
            // device that has just synced a head sees what sits beside it.
            let siblings: Vec<SiblingSetDto> = match view {
                Some(view) => view
                    .siblings(Owner::User(caller.actor().user))
                    .await
                    .map_err(|e| Problem::from(AppError::from(e)))?
                    .iter()
                    .map(SiblingSetDto::from_set)
                    .collect(),
                None => Vec::new(),
            };
            let mut response = Json(SyncResponse {
                items: page
                    .items
                    .iter()
                    .map(|i| {
                        ItemDto::from_item(i)
                            .in_collection(collections.get(&i.id).copied())
                            .held(page.held.contains(&i.id))
                    })
                    .collect(),
                cursor,
                more,
                siblings,
            })
            .into_response();
            if !more {
                response.headers_mut().insert(header::ETAG, tag);
            }
            Ok(response)
        }
    }
}

/// The problem for a store that wouldn't resolve: a head already sent to a peer can no longer
/// replace its siblings, which the device fixes by writing a newer version.
fn resolve_problem(e: StoreError) -> Problem {
    match e {
        StoreError::Backend(message) if message.contains("already sent") => Problem::new(
            StatusCode::CONFLICT,
            "siblings-already-sent",
            "The siblings can no longer be replaced",
        )
        .detail(
            "the merged version was already sent to another server: write a newer version, \n             then resolve again",
        ),
        other => Problem::from(AppError::from(other)),
    }
}

/// `POST /kem/v1/items/{id}/siblings/resolve`: the device merged the item's siblings and wrote
/// the result as a new revision; this drops the siblings and names them in that revision's
/// lineage. 404 for an item outside the caller's own vault, and when the server has no
/// federation; 409 when the revision was already sent to a peer.
async fn resolve_siblings<S, P, K, R>(
    State(env): State<Env<S, P, K, R>>,
    caller: Caller,
    MaybeView(view): MaybeView,
    Path(id): Path<String>,
) -> Result<Json<ResolveResponse>, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + Clone + 'static,
{
    let id: ItemId = id
        .parse()
        .map_err(|_| Problem::bad_request("the item id isn't a UUID"))?;
    let view = view.ok_or_else(Problem::not_found)?;
    let owner = Owner::User(caller.actor().user);
    let stored = ItemStore::get(&env.api.store, id)
        .await
        .map_err(|e| Problem::from(AppError::from(e)))?;
    if stored.is_none_or(|item| item.owner != owner) {
        return Err(Problem::not_found());
    }
    let resolved = view
        .resolve_siblings(owner, id)
        .await
        .map_err(resolve_problem)?;
    Ok(Json(ResolveResponse { resolved }))
}

/// `GET /kem/v1/live`: a WebSocket of "sync now" nudges for the account's vault and the spaces
/// it is in when the socket opens. The upgrade is authenticated like any other request; a
/// membership that changes later reaches the socket when it reconnects with a fresh token.
async fn live<S, P, K, R>(
    State(env): State<Env<S, P, K, R>>,
    caller: Caller,
    upgrade: WebSocketUpgrade,
) -> Result<Response, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + Clone + 'static,
{
    let api = env.api.clone();
    let hub = api.hub.clone();
    let owners = owners_of(&env.spaces, caller.0.actor.user).await?;
    // The socket ends with the access token that opened it, and sooner if the session ends.
    let lifetime = crate::live::until_expiry(caller.0.expires_at, api.now());
    let Authed {
        actor,
        jkt,
        security_stamp,
        ..
    } = caller.0;
    Ok(upgrade.on_upgrade(move |socket| {
        crate::live::serve_socket(socket, hub, owners, lifetime, move || {
            let api = api.clone();
            let jkt = jkt.clone();
            async move {
                api.session_is_live(actor.user, actor.device, &jkt, security_stamp)
                    .await
            }
        })
    }))
}

/// The item and sync routes. They need the space store as well as the API's, to sync spaces and
/// to write into them, so they have a state of their own, like the spaces routes.
pub(crate) fn router<S, P, K, R>(env: Env<S, P, K, R>) -> Router
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + Clone + 'static,
{
    Router::new()
        .route("/kem/v1/items/{id}", put(put_item::<S, P, K, R>))
        .route("/kem/v1/items:batch", post(put_batch::<S, P, K, R>))
        .route(
            "/kem/v1/items/{id}/siblings/resolve",
            post(resolve_siblings::<S, P, K, R>),
        )
        .route(
            "/kem/v1/sync",
            get(sync::<S, P, K, R>).post(sync_post::<S, P, K, R>),
        )
        .route("/kem/v1/live", get(live::<S, P, K, R>))
        .layer(middleware::from_fn_with_state(
            env.clone(),
            nonce_header::<S, P, K, R>,
        ))
        .with_state(env)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(*name, HeaderValue::from_static(value));
        }
        map
    }

    #[test]
    fn if_match_gives_the_expected_revision_in_any_spelling() {
        for text in ["4", "\"4\"", "W/\"4\"", " 4 "] {
            let h = headers(&[("if-match", text)]);
            assert_eq!(expected_revision(&h), Ok(Some(Revision(4))), "{text}");
        }
    }

    #[test]
    fn if_none_match_star_means_a_new_item() {
        let h = headers(&[("if-none-match", "*")]);
        assert_eq!(expected_revision(&h), Ok(None));
    }

    #[test]
    fn a_missing_conflicting_or_bad_precondition_is_refused() {
        let status = |h: HeaderMap| expected_revision(&h).expect_err("refused").status;
        assert_eq!(status(HeaderMap::new()), StatusCode::PRECONDITION_REQUIRED);
        assert_eq!(
            status(headers(&[("if-match", "1"), ("if-none-match", "*")])),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            status(headers(&[("if-match", "abc")])),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            status(headers(&[("if-none-match", "\"3\"")])),
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn an_etag_is_read_back_as_a_cursor() {
        assert_eq!(
            etag_cursor(&headers(&[("if-none-match", "\"abc\"")])),
            Some("abc".to_owned())
        );
        assert_eq!(
            etag_cursor(&headers(&[("if-none-match", "W/\"abc\"")])),
            Some("abc".to_owned())
        );
        assert_eq!(etag_cursor(&headers(&[("if-none-match", "*")])), None);
        assert_eq!(etag_cursor(&HeaderMap::new()), None);
    }
}
