//! `GET /api/config`: what the server says of itself.

use kemlock_contract_tests::shape::assert_single_spelling;
use kemlock_contract_tests::util::{key_of, version_at_least};
use kemlock_contract_tests::{Reply, client};
use serde_json::Value;

async fn config() -> Reply {
    let http = client();
    // Without a token and without any header of the apps: the config is read before signing in
    http.send(http.bare("GET", "/api/config")).await
}

#[tokio::test]
async fn config_is_an_object_named_config_with_a_bitwarden_version() {
    // Kemlock: `VwApi.config` (vw_api.dart:235-242) reads the address as a Bitwarden-compatible
    // server only when `object` is `config`; `keepsSshKeyItems` (vw_items.dart:59-62) turns SSH key
    // items on only when `version` is 2024.12.0 or later, and says "Vaultwarden sets no feature flag
    // for them (1.37.5 reports 2026.6.0)". Amethystora reads `version` and `server.name` for show only
    // (spec-protocol.md:64-65, vaultwarden.rs:305).
    let reply = config().await;
    let body = reply.ok_json("GET /api/config");
    assert_single_spelling("/api/config", &body);
    assert_eq!(
        body["object"], "config",
        "Vaultwarden's config says object: \"config\"; the app refuses a server that doesn't \
         (vw_api.dart:238); got {body}"
    );
    let version = body["version"].as_str().unwrap_or_default();
    assert!(
        version_at_least(version, "2024.12.0"),
        "version must be a Bitwarden server version of 2024.12.0 or later (Vaultwarden 1.37.5 says \
         2026.6.0) and never Kemlock Server's own: the app writes SSH key items only from \
         2024.12.0 (vw_items.dart:44); got {version:?}"
    );
    let year: u64 = version
        .split('.')
        .next()
        .and_then(|part| part.parse().ok())
        .unwrap_or(0);
    assert!(
        year >= 2024,
        "version is Bitwarden's calendar version (2026.6.0 on Vaultwarden 1.37.5); got {version:?}"
    );
}

#[tokio::test]
async fn config_names_the_server_and_its_environment_as_vaultwardens_does() {
    // The keys of Vaultwarden 1.37.5's config that clients read: `server` (name and url),
    // `environment` (the addresses of the vault, API and identity), `featureStates` (an object of
    // flags) and `gitHash`. The apps never use an address the server hands over (spec-protocol.md:60),
    // but Bitwarden's own apps do read `environment`.
    let reply = config().await;
    let body = reply.ok_json("GET /api/config");
    let server = key_of(&body, "server").unwrap_or(&Value::Null);
    assert!(
        server.is_object()
            && key_of(server, "name")
                .and_then(Value::as_str)
                .is_some_and(|name| !name.is_empty()),
        "server is an object with a name; got {server}"
    );
    let environment = key_of(&body, "environment").unwrap_or(&Value::Null);
    assert!(
        environment.is_object(),
        "environment is an object; got {environment}"
    );
    for name in ["vault", "api", "identity"] {
        assert!(
            key_of(environment, name).is_some_and(Value::is_string),
            "environment.{name} is an address as text; got {environment}"
        );
    }
    assert!(
        key_of(&body, "featureStates").is_some_and(Value::is_object),
        "featureStates is an object of flags (Bitwarden's apps read it); got {body}"
    );
}

#[tokio::test]
async fn the_server_calls_itself_vaultwarden_as_the_apps_own_test_expects() {
    // The Kemlock app's own server test asserts `server.name == 'Vaultwarden'`
    // (mobile/test/vaultwarden_server/api_test.dart:49-52), and CI runs that test against this
    // server. Amethystora prints the name and never acts on it (vaultwarden.rs:305). If the design
    // decides the name should differ, the app's test must change with it: this test stands for it.
    let reply = config().await;
    let body = reply.ok_json("GET /api/config");
    let name = key_of(&body, "server")
        .and_then(|server| key_of(server, "name"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    assert_eq!(
        name, "Vaultwarden",
        "Vaultwarden's config says server.name \"Vaultwarden\" and api_test.dart:51 expects it"
    );
}
