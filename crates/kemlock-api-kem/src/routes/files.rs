//! Files: `POST /kem/v1/items/{id}/files` starts an attachment upload, `PUT …/files/{fileId}`
//! streams its bytes (`Content-Length` required), `GET` streams them back and `DELETE` removes
//! the file. With pre-signed URLs on, `POST` answers with a bucket URL, the bytes go there
//! directly, and `POST …/files/{fileId}/finish` settles them. Every route is DPoP-authenticated
//! like the item routes.
//!
//! These routes need a blob store and an attachment repository besides the API's own state, so
//! they are a router of their own, built by [`files_router`] and merged by the server:
//! `Router::merge(files_router(api, blobs, attachments, config))`. They are meant to run under a
//! longer timeout than the JSON routes, because a file takes as long as its upload does.
//!
//! The body is never buffered: it is read chunk by chunk into blob storage, which refuses bytes
//! that don't start like a `KMA1` file. Files are named by id in these URLs; the server keeps no
//! file names, because the app seals them inside the item.

use crate::extract::{Authed, Body, DPOP_NONCE};
use crate::openapi::ProblemDoc;
use crate::problem::Problem;
use crate::state::{Api, Crypto, Store};
use axum::body::{Body as HttpBody, BodyDataStream, Bytes};
use axum::extract::rejection::QueryRejection;
use axum::extract::{FromRequestParts, Path, Query, Request, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{post, put};
use axum::{Json, Router};
use futures_util::StreamExt;
use kemlock_app::files::{
    AttachmentRepo, BlobStore, BodyError, BodySource, DeleteFile, Download, FileError, FilesConfig,
    FinishUpload, StartUpload, UploadBytes,
};
use kemlock_app::ports::TokenSigner;
use kemlock_app::quota::QuotaRefusal;
use kemlock_domain::{Attachment, AttachmentId, ItemId};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use utoipa::{OpenApi, ToSchema};
use uuid::Uuid;

/// `POST /items/{id}/files`: the size of the `KMA1` file about to be sent.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StartFileRequest {
    /// The exact length in bytes of the file the client will upload, `KMA1` header and tags
    /// included. The upload must match it.
    pub size: u64,
}

/// A started upload.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct StartFileResponse {
    /// The attachment's id: write it into the item's JSON.
    pub file_id: Uuid,
    pub item_id: Uuid,
    pub size: u64,
    /// The most bytes this server takes for one file.
    pub max_size: u64,
    /// Where to `PUT` the bytes: this server's own file route, or a pre-signed bucket URL.
    pub upload_url: String,
    /// Whether `upload_url` is a bucket URL. Then send the bytes there with no `Authorization`
    /// or `DPoP` header, and call `…/finish` afterwards.
    pub presigned: bool,
    /// Seconds a pre-signed URL stays valid.
    pub expires_in: Option<u64>,
}

/// A file as stored.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct FileDto {
    pub file_id: Uuid,
    pub item_id: Uuid,
    pub size: u64,
    /// `pending` or `ready`.
    pub status: String,
}

impl FileDto {
    fn of(a: &Attachment) -> Self {
        FileDto {
            file_id: a.id.0,
            item_id: a.item.0,
            size: a.size,
            status: a.status.as_str().to_owned(),
        }
    }
}

/// A pre-signed download URL.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DownloadLinkDto {
    pub url: String,
    pub expires_in: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DownloadQuery {
    /// Ask for a pre-signed bucket URL instead of the bytes, where the server has them on.
    presign: Option<bool>,
}

struct FilesInner<S, P, K, B, A> {
    api: Api<S, P, K>,
    blobs: B,
    attachments: A,
    config: FilesConfig,
}

/// The state of the file routes: the API's own state, blob storage, the attachment repository
/// and the file settings. Cheap to clone.
pub struct FilesApi<S, P, K, B, A>(Arc<FilesInner<S, P, K, B, A>>);

impl<S, P, K, B, A> Clone for FilesApi<S, P, K, B, A> {
    fn clone(&self) -> Self {
        FilesApi(Arc::clone(&self.0))
    }
}

impl<S, P, K, B, A> std::fmt::Debug for FilesApi<S, P, K, B, A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FilesApi").finish_non_exhaustive()
    }
}

impl<S, P, K, B, A> FilesApi<S, P, K, B, A> {
    pub fn new(api: Api<S, P, K>, blobs: B, attachments: A, config: FilesConfig) -> Self {
        FilesApi(Arc::new(FilesInner {
            api,
            blobs,
            attachments,
            config,
        }))
    }

    /// The file settings now: the largest file is the one the console last saved, when it saved
    /// one, else the one the routes were built with.
    fn config(&self) -> FilesConfig {
        let mut config = self.0.config;
        if let Some(max_size) = self.0.api.live.max_file_size() {
            config.limits.max_size = max_size;
        }
        config.user_quota = self.0.api.live.user_attachment_limit();
        config.space_quota = self.0.api.live.space_attachment_limit();
        config
    }
}

/// An authenticated request, checked by the API's own extractor against the API's own state.
pub(crate) struct FileAuthed(Authed);

impl<S, P, K, B, A> FromRequestParts<FilesApi<S, P, K, B, A>> for FileAuthed
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    B: Send + Sync + 'static,
    A: Send + Sync + 'static,
{
    type Rejection = Problem;

    async fn from_request_parts(
        parts: &mut Parts,
        files: &FilesApi<S, P, K, B, A>,
    ) -> Result<Self, Problem> {
        <Authed as FromRequestParts<Api<S, P, K>>>::from_request_parts(parts, &files.0.api)
            .await
            .map(FileAuthed)
    }
}

/// The request body as the use case reads it: chunk by chunk, never whole.
struct RequestBody(BodyDataStream);

impl BodySource for RequestBody {
    async fn next_chunk(&mut self) -> Result<Option<Bytes>, BodyError> {
        loop {
            match self.0.next().await {
                Some(Ok(chunk)) if chunk.is_empty() => {}
                Some(Ok(chunk)) => return Ok(Some(chunk)),
                Some(Err(_)) => return Err(BodyError),
                None => return Ok(None),
            }
        }
    }
}

/// A quota that refuses a file: 403 when the feature is switched off, 413 when the owner is over
/// the limit or the file would take them over it. The text is Vaultwarden's.
pub(crate) fn quota_problem(refusal: QuotaRefusal, message: &'static str) -> Problem {
    match refusal {
        QuotaRefusal::Disabled => Problem::new(StatusCode::FORBIDDEN, "storage-disabled", message),
        QuotaRefusal::Reached => Problem::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "storage-limit-reached",
            message,
        ),
        QuotaRefusal::Exceeded => Problem::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "storage-limit-exceeded",
            message,
        ),
    }
}

fn parse_item(text: &str) -> Result<ItemId, Problem> {
    text.parse()
        .map_err(|_| Problem::bad_request("the item id isn't a UUID"))
}

fn parse_file(text: &str) -> Result<AttachmentId, Problem> {
    text.parse()
        .map_err(|_| Problem::bad_request("the file id isn't a UUID"))
}

/// The request's `Content-Length`. A body of unknown length (chunked) is refused, because the
/// upload must match the size announced and the cap is checked against it before any byte is read.
fn content_length(headers: &HeaderMap) -> Result<u64, Problem> {
    let length_required = || {
        Problem::new(
            StatusCode::LENGTH_REQUIRED,
            "length-required",
            "Content-Length is required",
        )
        .detail("send the file with its Content-Length, not chunked")
    };
    if headers.contains_key(header::TRANSFER_ENCODING) {
        return Err(length_required());
    }
    let value = headers
        .get(header::CONTENT_LENGTH)
        .ok_or_else(length_required)?;
    value
        .to_str()
        .ok()
        .and_then(|text| text.trim().parse::<u64>().ok())
        .ok_or_else(|| Problem::bad_request("Content-Length isn't a number"))
}

/// Every response carries the current DPoP nonce, as the other routes do.
async fn nonce_header<S, P, K>(
    State(api): State<Api<S, P, K>>,
    request: Request,
    next: Next,
) -> Response
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
{
    let mut response = next.run(request).await;
    if let Ok(value) = HeaderValue::from_str(&api.dpop.current_nonce(api.now())) {
        response.headers_mut().insert(DPOP_NONCE, value);
    }
    response
}

impl<S, P, K, B, A> FilesApi<S, P, K, B, A>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    B: BlobStore + Clone + 'static,
    A: AttachmentRepo + Clone + 'static,
{
    fn start(&self) -> StartUpload<S, A, B, P> {
        StartUpload {
            items: self.0.api.store.clone(),
            attachments: self.0.attachments.clone(),
            blobs: self.0.blobs.clone(),
            clock: self.0.api.crypto.clone(),
            config: self.config(),
        }
    }

    fn upload(&self) -> UploadBytes<A, B, S, P> {
        UploadBytes {
            attachments: self.0.attachments.clone(),
            blobs: self.0.blobs.clone(),
            events: self.0.api.store.clone(),
            clock: self.0.api.crypto.clone(),
            config: self.config(),
        }
    }

    fn finish(&self) -> FinishUpload<A, B, S, P> {
        FinishUpload {
            attachments: self.0.attachments.clone(),
            blobs: self.0.blobs.clone(),
            events: self.0.api.store.clone(),
            clock: self.0.api.crypto.clone(),
        }
    }

    fn download(&self) -> Download<S, A, B> {
        Download {
            items: self.0.api.store.clone(),
            attachments: self.0.attachments.clone(),
            blobs: self.0.blobs.clone(),
        }
    }

    fn delete(&self) -> DeleteFile<A, B, S, P> {
        DeleteFile {
            attachments: self.0.attachments.clone(),
            blobs: self.0.blobs.clone(),
            events: self.0.api.store.clone(),
            clock: self.0.api.crypto.clone(),
        }
    }

    /// This server's own URL of a file, which is where its bytes go without pre-signing.
    fn own_url(&self, item: ItemId, file: AttachmentId) -> String {
        format!(
            "{}/kem/v1/items/{item}/files/{file}",
            self.0.api.config.domain.trim_end_matches('/')
        )
    }

    fn problem(&self, error: FileError) -> Problem {
        match error {
            FileError::Invalid(detail) => Problem::bad_request(detail),
            FileError::TooLarge => Problem::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                "file-too-large",
                "The file is larger than this server allows",
            )
            .with("maxSize", json!(self.config().limits.max_size)),
            FileError::Quota(refusal) => quota_problem(refusal, refusal.attachment_message()),
            FileError::NotKma1(why) => Problem::new(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "not-kma1",
                "The bytes are not a KMA1 file",
            )
            .detail(why),
            FileError::LengthMismatch => Problem::new(
                StatusCode::BAD_REQUEST,
                "length-mismatch",
                "The body isn't the size announced when the upload started",
            ),
            FileError::Forbidden => {
                Problem::new(StatusCode::FORBIDDEN, "forbidden", "This isn't allowed")
            }
            FileError::NotFound => Problem::not_found(),
            FileError::AlreadyUploaded => Problem::new(
                StatusCode::CONFLICT,
                "already-uploaded",
                "The file was uploaded already",
            ),
            FileError::Interrupted => Problem::new(
                StatusCode::BAD_REQUEST,
                "upload-interrupted",
                "The upload broke off before its end",
            ),
            FileError::Store(message) | FileError::Blob(message) => {
                tracing::error!(%message, "a file operation failed");
                Problem::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal",
                    "Something went wrong on the server",
                )
            }
        }
    }

    /// `POST /kem/v1/items/{id}/files`: starts an upload of a file of `size` bytes. Answers 201
    /// with the file id and where to send the bytes.
    pub(crate) async fn handle_start(
        State(files): State<Self>,
        FileAuthed(authed): FileAuthed,
        Path(item): Path<String>,
        body: Body,
    ) -> Result<Response, Problem> {
        let item = parse_item(&item)?;
        let request: StartFileRequest = body.json()?;
        let started = files
            .start()
            .execute(&authed.actor, item, request.size)
            .await
            .map_err(|e| files.problem(e))?;
        let attachment = &started.attachment;
        let own = files.own_url(item, attachment.id);
        let (upload_url, presigned, expires_in) = match &started.upload {
            Some(link) => (link.url.clone(), true, Some(link.expires_in.as_secs())),
            None => (own.clone(), false, None),
        };
        let mut response = (
            StatusCode::CREATED,
            Json(StartFileResponse {
                file_id: attachment.id.0,
                item_id: item.0,
                size: attachment.size,
                max_size: files.config().limits.max_size,
                upload_url,
                presigned,
                expires_in,
            }),
        )
            .into_response();
        if let Ok(location) = HeaderValue::from_str(&own) {
            response.headers_mut().insert(header::LOCATION, location);
        }
        Ok(response)
    }

    /// `PUT /kem/v1/items/{id}/files/{fileId}`: the file's bytes, streamed. `Content-Length` is
    /// required and must be the size announced. Bytes that don't start like a `KMA1` file are
    /// refused with 415.
    pub(crate) async fn handle_upload(
        State(files): State<Self>,
        FileAuthed(authed): FileAuthed,
        Path((item, file)): Path<(String, String)>,
        headers: HeaderMap,
        body: HttpBody,
    ) -> Result<Response, Problem> {
        let (item, file) = (parse_item(&item)?, parse_file(&file)?);
        let length = content_length(&headers)?;
        let mut source = RequestBody(body.into_data_stream());
        let attachment = files
            .upload()
            .execute(&authed.actor, item, file, length, &mut source)
            .await
            .map_err(|e| files.problem(e))?;
        Ok(Json(FileDto::of(&attachment)).into_response())
    }

    /// `POST /kem/v1/items/{id}/files/{fileId}/finish`: settles a file sent straight to the
    /// bucket. Harmless for a file the server received itself.
    pub(crate) async fn handle_finish(
        State(files): State<Self>,
        FileAuthed(authed): FileAuthed,
        Path((item, file)): Path<(String, String)>,
    ) -> Result<Response, Problem> {
        let (item, file) = (parse_item(&item)?, parse_file(&file)?);
        let attachment = files
            .finish()
            .execute(&authed.actor, item, file)
            .await
            .map_err(|e| files.problem(e))?;
        Ok(Json(FileDto::of(&attachment)).into_response())
    }

    /// `GET /kem/v1/items/{id}/files/{fileId}`: the file's bytes, streamed. With `?presign=true`
    /// and pre-signed URLs on, a short-lived bucket URL as JSON instead.
    pub(crate) async fn handle_download(
        State(files): State<Self>,
        FileAuthed(authed): FileAuthed,
        Path((item, file)): Path<(String, String)>,
        query: Result<Query<DownloadQuery>, QueryRejection>,
    ) -> Result<Response, Problem> {
        let Query(query) = query.map_err(|e| Problem::bad_request(e.body_text()))?;
        let (item, file) = (parse_item(&item)?, parse_file(&file)?);
        if query.presign == Some(true)
            && let Some(link) = files
                .download()
                .link(&authed.actor, item, file)
                .await
                .map_err(|e| files.problem(e))?
        {
            return Ok(Json(DownloadLinkDto {
                url: link.url,
                expires_in: link.expires_in.as_secs(),
            })
            .into_response());
        }
        let downloaded = files
            .download()
            .open(&authed.actor, item, file)
            .await
            .map_err(|e| files.problem(e))?;
        let size = downloaded.read.size;
        let mut response = Response::new(HttpBody::from_stream(downloaded.read.body));
        let headers = response.headers_mut();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        );
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from(size));
        headers.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("private, no-store"),
        );
        headers.insert(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        );
        Ok(response)
    }

    /// `DELETE /kem/v1/items/{id}/files/{fileId}`: removes the file's bytes and row. The client
    /// also writes the item without the file's id.
    pub(crate) async fn handle_delete(
        State(files): State<Self>,
        FileAuthed(authed): FileAuthed,
        Path((item, file)): Path<(String, String)>,
    ) -> Result<StatusCode, Problem> {
        let (item, file) = (parse_item(&item)?, parse_file(&file)?);
        files
            .delete()
            .execute(&authed.actor, item, file)
            .await
            .map_err(|e| files.problem(e))?;
        Ok(StatusCode::NO_CONTENT)
    }
}

/// The file routes. Merge them into the `/kem/v1` router, under a timeout of their own: an
/// upload takes as long as the connection does.
pub fn files_router<S, P, K, B, A>(
    api: Api<S, P, K>,
    blobs: B,
    attachments: A,
    config: FilesConfig,
) -> Router
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    B: BlobStore + Clone + 'static,
    A: AttachmentRepo + Clone + 'static,
{
    let files = FilesApi::new(api.clone(), blobs, attachments, config);
    Router::new()
        .route(
            "/kem/v1/items/{id}/files",
            post(FilesApi::<S, P, K, B, A>::handle_start),
        )
        .route(
            "/kem/v1/items/{id}/files/{file}",
            put(FilesApi::<S, P, K, B, A>::handle_upload)
                .get(FilesApi::<S, P, K, B, A>::handle_download)
                .delete(FilesApi::<S, P, K, B, A>::handle_delete),
        )
        .route(
            "/kem/v1/items/{id}/files/{file}/finish",
            post(FilesApi::<S, P, K, B, A>::handle_finish),
        )
        .layer(middleware::from_fn_with_state(api, nonce_header::<S, P, K>))
        .with_state(files)
}

#[utoipa::path(
    post, path = "/kem/v1/items/{id}/files", tag = "files",
    security(("dpop" = [])),
    params(("id" = String, Path, description = "The item's id")),
    request_body = StartFileRequest,
    responses(
        (status = 201, description = "Started: the file id and where to send the bytes", body = StartFileResponse),
        (status = 403, description = "Another account's item", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 413, description = "Larger than the server's limit (`maxSize`)", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_start() {}

#[utoipa::path(
    put, path = "/kem/v1/items/{id}/files/{file}", tag = "files",
    security(("dpop" = [])),
    params(
        ("id" = String, Path, description = "The item's id"),
        ("file" = String, Path, description = "The file id from the start call"),
        ("Content-Length" = u64, Header, description = "Required; the size announced at the start"),
    ),
    request_body(content = Vec<u8>, content_type = "application/octet-stream", description = "The KMA1 file"),
    responses(
        (status = 200, description = "Stored", body = FileDto),
        (status = 400, description = "The body isn't the size announced", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 409, description = "Uploaded already", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 411, description = "No Content-Length", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 415, description = "Not a KMA1 file", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_upload() {}

#[utoipa::path(
    post, path = "/kem/v1/items/{id}/files/{file}/finish", tag = "files",
    security(("dpop" = [])),
    params(
        ("id" = String, Path, description = "The item's id"),
        ("file" = String, Path, description = "The file id from the start call"),
    ),
    responses(
        (status = 200, description = "Ready", body = FileDto),
        (status = 400, description = "Nothing, or not the announced size, was uploaded", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_finish() {}

#[utoipa::path(
    get, path = "/kem/v1/items/{id}/files/{file}", tag = "files",
    security(("dpop" = [])),
    params(
        ("id" = String, Path, description = "The item's id"),
        ("file" = String, Path, description = "The file id"),
        ("presign" = Option<bool>, Query, description = "Ask for a pre-signed bucket URL, where the server has them on"),
    ),
    responses(
        (status = 200, description = "The KMA1 file, or with `presign` a JSON `{url, expiresIn}`"),
        (status = 404, description = "No such ready file of this account", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_download() {}

#[utoipa::path(
    delete, path = "/kem/v1/items/{id}/files/{file}", tag = "files",
    security(("dpop" = [])),
    params(
        ("id" = String, Path, description = "The item's id"),
        ("file" = String, Path, description = "The file id"),
    ),
    responses(
        (status = 204, description = "Deleted"),
        (status = 404, description = "No such file of this account", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_delete() {}

/// The file routes' part of the OpenAPI document. The API's own document
/// (`crate::openapi::ApiDoc`) doesn't list them, because the file routes need ports it doesn't
/// have; a server that serves them can `merge` this into it.
#[derive(Debug, OpenApi)]
#[openapi(
    paths(doc_start, doc_upload, doc_finish, doc_download, doc_delete),
    components(schemas(StartFileRequest, StartFileResponse, FileDto, DownloadLinkDto))
)]
pub struct FilesDoc;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_quota_refusal_is_a_403_when_off_and_a_413_when_full_with_vaultwardens_words() {
        let off = quota_problem(
            QuotaRefusal::Disabled,
            QuotaRefusal::Disabled.attachment_message(),
        );
        assert_eq!(off.status, StatusCode::FORBIDDEN);
        assert_eq!(off.title, "Attachments are disabled");
        let full = quota_problem(QuotaRefusal::Reached, QuotaRefusal::Reached.send_message());
        assert_eq!(full.status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(
            full.title,
            "Send storage limit reached! Delete some sends to free up space"
        );
        let over = quota_problem(
            QuotaRefusal::Exceeded,
            QuotaRefusal::Exceeded.attachment_message(),
        );
        assert_eq!(over.status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(over.slug, "storage-limit-exceeded");
    }

    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(*name, HeaderValue::from_static(value));
        }
        map
    }

    #[test]
    fn content_length_is_read_as_a_number() {
        assert_eq!(
            content_length(&headers(&[("content-length", "65680")])),
            Ok(65_680)
        );
        assert_eq!(
            content_length(&headers(&[("content-length", " 12 ")])),
            Ok(12)
        );
    }

    #[test]
    fn a_missing_chunked_or_garbled_length_is_refused() {
        let status = |h: HeaderMap| content_length(&h).expect_err("refused").status;
        assert_eq!(status(HeaderMap::new()), StatusCode::LENGTH_REQUIRED);
        assert_eq!(
            status(headers(&[("transfer-encoding", "chunked")])),
            StatusCode::LENGTH_REQUIRED
        );
        assert_eq!(
            status(headers(&[("content-length", "lots")])),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            status(headers(&[("content-length", "-1")])),
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn ids_must_be_uuids() {
        assert!(parse_item("7f3c4b1e-0000-4000-8000-000000000000").is_ok());
        assert_eq!(
            parse_item("nope").expect_err("refused").status,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            parse_file("").expect_err("refused").status,
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn the_document_names_every_file_route() {
        let json = serde_json::to_value(FilesDoc::openapi()).expect("serialises");
        for (path, method) in [
            ("/kem/v1/items/{id}/files", "post"),
            ("/kem/v1/items/{id}/files/{file}", "put"),
            ("/kem/v1/items/{id}/files/{file}", "get"),
            ("/kem/v1/items/{id}/files/{file}", "delete"),
            ("/kem/v1/items/{id}/files/{file}/finish", "post"),
        ] {
            assert!(
                json["paths"][path][method].is_object(),
                "{method} {path} is documented"
            );
        }
        assert!(json["components"]["schemas"]["StartFileResponse"].is_object());
    }
}
