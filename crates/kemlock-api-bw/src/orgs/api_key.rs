//! The organization API key: made on first ask, rotated on request, and what the Directory
//! Connector signs in with (`client_credentials`, scope `api.organization`) to get a token for the
//! public API.
//!
//! As Vaultwarden 1.37.5 has it: the key is 30 letters and digits kept in one document of the
//! organization with its own id; a token made from it names that id as its subject and the
//! organization as its client subject and lives an hour. A rotation makes a new id as well as a new
//! key, so the tokens of the old key are refused at once (Vaultwarden keeps the id, and they live
//! out their hour).

use super::guard::Ctx;
use super::model::{ApiKeyDoc, KIND_API_KEY};
use crate::app::{App, BwStore};
use crate::dates::format_date;
use crate::env::{random_alphanumeric, random_uuid};
use crate::error::{BwError, BwResult};
use kemlock_crypto::hash;
use kemlock_domain::SpaceId;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

/// The scope, and the issuer's suffix, of an organization token.
pub(crate) const SCOPE: &str = "api.organization";

/// How long an organization token lasts, in seconds.
const TOKEN_TTL: i64 = 3600;

const CLIENT_PREFIX: &str = "organization.";

/// What an organization token says: Vaultwarden's `OrgApiKeyLoginJwtClaims`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct OrgApiClaims {
    pub nbf: i64,
    pub exp: i64,
    pub iss: String,
    /// The key's id.
    pub sub: String,
    /// `organization.<organization id>`.
    pub client_id: String,
    /// The organization id.
    pub client_sub: String,
    pub scope: Vec<String>,
}

impl<S: BwStore> App<S> {
    /// The key of an organization, when it has made one.
    pub(crate) async fn org_api_key(&self, org: SpaceId) -> BwResult<Option<ApiKeyDoc>> {
        self.doc(org.0, KIND_API_KEY, "").await
    }
}

/// `POST /api/organizations/{id}/api-key` and `rotate-api-key`: the key, made if there is none, or
/// a new one when `rotate`.
pub(crate) async fn api_key<S: BwStore>(app: &App<S>, ctx: &Ctx, rotate: bool) -> BwResult<Value> {
    let now = format_date(app.now());
    let doc = match app.org_api_key(ctx.org.id).await? {
        Some(mut doc) if rotate => {
            doc.api_key = random_alphanumeric(app.env.as_ref(), 30);
            // A new id too: a token names the key's id, so the tokens of the old key stop working
            // at once (Vaultwarden keeps the id, and an old token lives out its hour).
            doc.id = random_uuid(app.env.as_ref()).to_string();
            doc.revision_date = now;
            app.put_doc(ctx.org.id.0, KIND_API_KEY, "", &doc).await?;
            doc
        }
        Some(doc) => doc,
        None => {
            let doc = ApiKeyDoc {
                id: random_uuid(app.env.as_ref()).to_string(),
                api_key: random_alphanumeric(app.env.as_ref(), 30),
                atype: 0,
                revision_date: now,
            };
            app.put_doc(ctx.org.id.0, KIND_API_KEY, "", &doc).await?;
            doc
        }
    };
    Ok(json!({
        "apiKey": doc.api_key,
        "revisionDate": doc.revision_date,
        "object": "apiKey",
    }))
}

/// The token request of the Directory Connector: `client_id` is `organization.<id>`, the secret
/// is the organization's API key.
pub(crate) async fn login<S: BwStore>(
    app: &App<S>,
    client_id: &str,
    client_secret: &str,
) -> BwResult<Value> {
    let Some(org_text) = client_id.strip_prefix(CLIENT_PREFIX) else {
        return Err(BwError::msg("Malformed client_id"));
    };
    let key = match Uuid::parse_str(org_text) {
        Ok(org) => app.org_api_key(SpaceId(org)).await?,
        Err(_) => None,
    };
    let Some(key) = key else {
        return Err(BwError::msg("Invalid client_id"));
    };
    if !hash::ct_eq(key.api_key.as_bytes(), client_secret.as_bytes()) {
        return Err(BwError::msg("Incorrect client_secret"));
    }
    let now = app.now_secs();
    let claims = OrgApiClaims {
        nbf: now,
        exp: now + TOKEN_TTL,
        iss: app.settings.issuer(SCOPE),
        sub: key.id,
        client_id: client_id.to_owned(),
        client_sub: org_text.to_lowercase(),
        scope: vec![SCOPE.to_owned()],
    };
    let token = app
        .keys
        .encode(&claims)
        .map_err(|e| BwError::Server(e.to_string()))?;
    Ok(json!({
        "access_token": token,
        "expires_in": TOKEN_TTL,
        "token_type": "Bearer",
        "scope": SCOPE,
        "unofficialServer": true,
    }))
}

/// The organization a public API request is for, from its `Authorization` header: Vaultwarden's
/// `PublicToken` guard. Every failure is a bare 401.
pub(crate) async fn authenticate<S: BwStore>(
    app: &App<S>,
    header: Option<&str>,
) -> BwResult<SpaceId> {
    let Some(header) = header else {
        tracing::warn!("a public API request has no access token");
        return Err(BwError::Unauthorized);
    };
    let token = header.rsplit("Bearer ").next().unwrap_or(header);
    let claims: OrgApiClaims = app
        .keys
        .decode(token, &app.settings.issuer(SCOPE), app.now_secs())
        .map_err(|e| {
            tracing::warn!(error = %e, "a public API token was refused");
            BwError::Unauthorized
        })?;
    let Some(org_text) = claims.client_id.strip_prefix(CLIENT_PREFIX) else {
        return Err(BwError::Unauthorized);
    };
    let org = Uuid::parse_str(org_text)
        .map(SpaceId)
        .map_err(|_| BwError::Unauthorized)?;
    // The token is for the organization it names, and for the key as it is: an organization that
    // is gone, or whose key was deleted, closes it.
    if !org_text.eq_ignore_ascii_case(&claims.client_sub) {
        return Err(BwError::Unauthorized);
    }
    match app.org_api_key(org).await? {
        Some(key) if key.id == claims.sub => Ok(org),
        _ => Err(BwError::Unauthorized),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claims_round_trip_as_json() {
        let claims = OrgApiClaims {
            nbf: 1,
            exp: 2,
            iss: "https://vault.test|api.organization".to_owned(),
            sub: "key".to_owned(),
            client_id: "organization.o".to_owned(),
            client_sub: "o".to_owned(),
            scope: vec![SCOPE.to_owned()],
        };
        let text = serde_json::to_string(&claims).expect("serialises");
        let back: OrgApiClaims = serde_json::from_str(&text).expect("parses");
        assert_eq!(back, claims);
    }
}
