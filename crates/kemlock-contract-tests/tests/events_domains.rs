//! Client-reported events and equivalent domains, as Vaultwarden 1.37.5 answers them.
//!
//! The sources are Vaultwarden's `src/api/core/events.rs` (the collect route is mounted at
//! `/events`, not `/api`) and `src/api/core/mod.rs` (`/api/settings/domains`). Organization events
//! are off by default there, so the event lists are empty pages.

use kemlock_contract_tests::{Session, fresh_session};
use serde_json::{Value, json};

fn sorted_keys(value: &Value) -> Vec<String> {
    let mut keys: Vec<String> = value
        .as_object()
        .unwrap_or_else(|| panic!("an object, got {value}"))
        .keys()
        .cloned()
        .collect();
    keys.sort();
    keys
}

#[tokio::test]
async fn collected_events_are_accepted_with_an_empty_body() {
    // Bitwarden's apps post vault exports and cipher views here after any export or copy.
    let s = fresh_session().await;
    let events = json!([
        {"type": 1007, "date": "2026-11-21T12:00:00.000Z"},
        {"type": 1107, "date": "2026-11-21T12:00:00.000Z", "cipherId": "6a3c5f2e-9d1b-4c7e-8a40-0f9e7d6c5b4a"},
        {"type": 9999, "date": "2026-11-21T12:00:00.000Z"}
    ]);
    let reply = s
        .send(s.call("POST", "/events/collect").json(&events))
        .await;
    assert!(
        reply.is_success(),
        "POST /events/collect is accepted: {} {}",
        reply.status,
        reply.text()
    );
    assert!(
        reply.body.is_empty(),
        "with an empty body: {}",
        reply.text()
    );

    let none = s
        .send(s.call("POST", "/events/collect").json(&json!([])))
        .await;
    assert!(none.is_success(), "{} {}", none.status, none.text());
}

#[tokio::test]
async fn collecting_needs_a_token_and_a_list() {
    let s = fresh_session().await;
    let unsigned = s
        .http
        .send(
            s.http
                .call("POST", "/events/collect")
                .json(&json!([{"type": 1007, "date": "2026-11-21T12:00:00.000Z"}])),
        )
        .await;
    assert_eq!(unsigned.status, 401, "{}", unsigned.text());

    let wrong = s
        .send(
            s.call("POST", "/events/collect")
                .json(&json!({"type": 1007})),
        )
        .await;
    assert_eq!(wrong.status, 422, "{}", wrong.text());
}

#[tokio::test]
async fn a_ciphers_events_are_an_empty_page() {
    let s = fresh_session().await;
    let page = s
        .get("/api/ciphers/6a3c5f2e-9d1b-4c7e-8a40-0f9e7d6c5b4a/events?start=2026-11-01T00:00:00Z&end=2026-12-01T00:00:00Z")
        .await
        .ok_json("GET /api/ciphers/{id}/events");
    assert_eq!(sorted_keys(&page), ["continuationToken", "data", "object"]);
    assert_eq!(page["data"], json!([]));
    assert_eq!(page["object"], "list");
    assert!(page["continuationToken"].is_null());
}

#[tokio::test]
async fn the_domains_are_bitwardens_list_and_the_accounts_choices() {
    let s = fresh_session().await;
    let domains = s
        .get("/api/settings/domains")
        .await
        .ok_json("GET /api/settings/domains");
    assert_eq!(
        sorted_keys(&domains),
        ["equivalentDomains", "globalEquivalentDomains", "object"]
    );
    assert_eq!(domains["object"], "domains");
    assert_eq!(domains["equivalentDomains"], json!([]));
    let globals = domains["globalEquivalentDomains"]
        .as_array()
        .expect("a list");
    assert!(!globals.is_empty());
    for global in globals {
        assert_eq!(
            sorted_keys(global),
            ["domains", "excluded", "type"],
            "{global}"
        );
        assert_eq!(global["excluded"], false);
    }

    let saved = s
        .post(
            "/api/settings/domains",
            &json!({
                "excludedGlobalEquivalentDomains": [0],
                "equivalentDomains": [["a.example", "b.example"]]
            }),
        )
        .await
        .ok_json("POST /api/settings/domains");
    assert_eq!(saved, json!({}), "a save answers an empty object");

    let after = s
        .get("/api/settings/domains")
        .await
        .ok_json("GET /api/settings/domains");
    assert_eq!(
        after["equivalentDomains"],
        json!([["a.example", "b.example"]])
    );
    for global in after["globalEquivalentDomains"].as_array().expect("a list") {
        assert_eq!(global["excluded"], global["type"] == 0, "{global}");
    }

    // A PUT does the same.
    let put = s
        .put(
            "/api/settings/domains",
            &json!({"equivalentDomains": [["c.example", "d.example"]]}),
        )
        .await;
    assert!(put.is_success(), "{} {}", put.status, put.text());
    let after = s
        .get("/api/settings/domains")
        .await
        .ok_json("GET /api/settings/domains");
    assert_eq!(
        after["equivalentDomains"],
        json!([["c.example", "d.example"]])
    );
    assert!(
        after["globalEquivalentDomains"]
            .as_array()
            .is_some_and(|g| g.iter().all(|g| g["excluded"] == false)),
        "a save with no excluded list clears it"
    );
}

async fn sync_with_domains(s: &Session, query: &str) -> Value {
    s.get(&format!("/api/sync{query}"))
        .await
        .ok_json("GET /api/sync")
}

#[tokio::test]
async fn a_sync_carries_the_domains_without_the_excluded_sets_unless_it_asks_not_to() {
    let s = fresh_session().await;
    s.post(
        "/api/settings/domains",
        &json!({
            "excludedGlobalEquivalentDomains": [0, 3],
            "equivalentDomains": [["a.example", "b.example"]]
        }),
    )
    .await
    .ok_json("save");

    let sync = sync_with_domains(&s, "").await;
    let domains = &sync["domains"];
    assert_eq!(domains["object"], "domains", "{domains}");
    assert_eq!(
        domains["equivalentDomains"],
        json!([["a.example", "b.example"]])
    );
    let globals = domains["globalEquivalentDomains"]
        .as_array()
        .expect("a list");
    assert!(
        globals
            .iter()
            .all(|g| g["type"] != 0 && g["type"] != 3 && g["excluded"] == false),
        "the excluded sets are left out of a sync"
    );

    let without = sync_with_domains(&s, "?excludeDomains=true").await;
    assert!(without["domains"].is_null(), "{}", without["domains"]);
}
