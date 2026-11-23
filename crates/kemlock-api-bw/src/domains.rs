//! Equivalent domains: `/api/settings/domains`, and the `domains` object of `/api/sync`.
//!
//! Bitwarden ships a list of global equivalent domains (`global_domains.json`, Vaultwarden
//! 1.37.5's copy, with its type numbers); an account excludes some of them and adds sets of its
//! own. Vaultwarden keeps both in two columns of the user row; here they are one JSON document in
//! the Bitwarden side store (scope: the account, kind `domains`, no key).

use crate::app::{App, Authed, BwStore};
use crate::error::{BwError, BwResult};
use crate::routes::{JsonResult, ok, parse};
use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::routing::get;
use kemlock_app::bitwarden::BwOrgStore;
use kemlock_app::bw_events::UserSync;
use kemlock_domain::UserId;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// Bitwarden's global equivalent domains, as Vaultwarden 1.37.5 embeds them.
const GLOBAL_DOMAINS: &str = include_str!("global_domains.json");

const KIND: &str = "domains";

/// What an account chose.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Choice {
    #[serde(default)]
    equivalent_domains: Vec<Vec<String>>,
    #[serde(default)]
    excluded_global_equivalent_domains: Vec<i32>,
}

async fn load<S: BwStore>(app: &App<S>, user: UserId) -> BwResult<Choice> {
    let text = BwOrgStore::doc_get(&app.store, user.0, KIND, "").await?;
    Ok(text
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default())
}

/// `get_eq_domains`: the account's sets, and every global set flagged `excluded` or not. With
/// `no_excluded`, as in a sync, the excluded global sets are left out.
fn domains_json(choice: &Choice, no_excluded: bool) -> BwResult<Value> {
    let mut globals: Vec<Value> = serde_json::from_str(GLOBAL_DOMAINS)
        .map_err(|e| BwError::Server(format!("the global domains don't parse: {e}")))?;
    for global in &mut globals {
        let excluded = global.get("type").and_then(Value::as_i64).is_some_and(|t| {
            choice
                .excluded_global_equivalent_domains
                .iter()
                .any(|e| i64::from(*e) == t)
        });
        global["excluded"] = Value::Bool(excluded);
    }
    if no_excluded {
        globals.retain(|g| g["excluded"] != Value::Bool(true));
    }
    Ok(json!({
        "equivalentDomains": choice.equivalent_domains,
        "globalEquivalentDomains": globals,
        "object": "domains",
    }))
}

/// The `domains` value of `/api/sync`: null when the client excludes it.
pub(crate) async fn sync_json<S: BwStore>(
    app: &App<S>,
    authed: &Authed,
    exclude: bool,
) -> BwResult<Value> {
    if exclude {
        return Ok(Value::Null);
    }
    domains_json(&load(app, authed.user.id).await?, true)
}

async fn get_domains<S: BwStore>(State(app): State<App<S>>, authed: Authed) -> JsonResult {
    ok(domains_json(&load(&app, authed.user.id).await?, false)?)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EquivDomainData {
    excluded_global_equivalent_domains: Option<Vec<i32>>,
    equivalent_domains: Option<Vec<Vec<String>>>,
}

async fn post_domains<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    body: Bytes,
) -> JsonResult {
    let data: EquivDomainData = parse(&body)?;
    let choice = Choice {
        equivalent_domains: data.equivalent_domains.unwrap_or_default(),
        excluded_global_equivalent_domains: data
            .excluded_global_equivalent_domains
            .unwrap_or_default(),
    };
    let text = serde_json::to_string(&choice).map_err(|e| BwError::Server(e.to_string()))?;
    BwOrgStore::doc_put(&app.store, authed.user.id.0, KIND, "", &text).await?;
    app.touch(authed.user.id).await?;
    app.user_synced(&authed, UserSync::Settings);
    ok(json!({}))
}

pub(crate) fn routes<S: BwStore>() -> Router<App<S>> {
    Router::new().route(
        "/api/settings/domains",
        get(get_domains::<S>)
            .post(post_domains::<S>)
            .put(post_domains::<S>),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_global_list_parses_and_flags_what_the_account_excluded() {
        let all = domains_json(&Choice::default(), false).expect("a list");
        let globals = all["globalEquivalentDomains"].as_array().expect("a list");
        assert!(globals.len() > 20);
        assert!(globals.iter().all(|g| g["excluded"] == json!(false)));
        assert_eq!(all["object"], "domains");

        let choice = Choice {
            equivalent_domains: vec![vec!["a.example".to_owned(), "b.example".to_owned()]],
            excluded_global_equivalent_domains: vec![0],
        };
        let shown = domains_json(&choice, false).expect("a list");
        let youtube = shown["globalEquivalentDomains"]
            .as_array()
            .and_then(|all| all.iter().find(|g| g["type"] == json!(0)))
            .expect("type 0 is there");
        assert_eq!(youtube["excluded"], json!(true));
        assert_eq!(
            shown["equivalentDomains"],
            json!([["a.example", "b.example"]])
        );

        let synced = domains_json(&choice, true).expect("a list");
        assert_eq!(
            synced["globalEquivalentDomains"].as_array().map(Vec::len),
            Some(globals.len() - 1)
        );
    }
}
