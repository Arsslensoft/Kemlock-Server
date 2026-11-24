//! Forward-only migrations, written with the schema builder so one definition makes the same
//! tables on SQLite, PostgreSQL and MySQL.
//!
//! Conventions: ids are `uuid` columns (a 16-byte blob on SQLite and MySQL, native on
//! PostgreSQL); times are `timestamp with time zone`, always written in UTC; ciphertext and keys
//! are binary; counters are 64-bit integers. Every statement is `IF NOT EXISTS`, so a migration
//! that stopped half way on a backend without transactional DDL (MySQL) can run again.

mod cols;
mod m20261121_000001_server_meta;
mod m20261121_000002_accounts;
mod m20261121_000003_items;
mod m20261121_000004_events_settings;
mod m20261122_010001_attachments;
mod m20261122_020001_bw_accounts;
mod m20261122_030001_spaces;
mod m20261122_040001_sso;
mod m20261122_050001_auth_requests_and_copies;
mod m20261122_050002_emergency_access;
mod m20261122_060001_federation;
mod m20261123_010001_space_policies;
mod m20261123_020001_manifests_and_api_use;
mod m20261123_030001_passkeys;
mod m20261123_040001_notify;
mod m20261123_050001_bw_docs;
mod m20261123_060001_sends;
mod m20261123_060002_space_policy_settings;
mod m20261123_070001_admin;
mod m20261123_080001_privacy;
mod m20261123_090001_duplicates;
mod m20261123_100001_federation_wiring;
mod m20261123_110001_vaultwarden_import;
mod m20261124_010001_merge_space_policies;
mod m20261125_010001_recovery_codes;
mod m20261125_020001_event_reader_index;
mod m20261125_030001_bw_devices;
mod m20261125_050001_federation_erasures;
mod m20261125_090001_peer_events;
mod m20261125_090002_key_records;
mod m20261125_090003_learned_keys;
mod m20261126_010001_space_chain;
mod m20261126_020001_two_step_version;
mod m20261126_030001_pending_changes;
mod m20261126_040001_federation_insight;
mod m20261127_030001_space_recovery_boxes;
mod m20261128_010001_bw_user_key_ids;
mod m20261128_020001_held_demotions;

use sea_orm_migration::prelude::*;

pub(crate) use m20261121_000001_server_meta::job_leases_table;

#[derive(Debug)]
pub(crate) struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20261121_000001_server_meta::Migration),
            Box::new(m20261121_000002_accounts::Migration),
            Box::new(m20261121_000003_items::Migration),
            Box::new(m20261121_000004_events_settings::Migration),
            Box::new(m20261122_010001_attachments::Migration),
            Box::new(m20261122_050001_auth_requests_and_copies::Migration),
            Box::new(m20261122_050002_emergency_access::Migration),
            Box::new(m20261122_020001_bw_accounts::Migration),
            Box::new(m20261122_030001_spaces::Migration),
            Box::new(m20261122_040001_sso::Migration),
            Box::new(m20261122_060001_federation::Migration),
            Box::new(m20261123_010001_space_policies::Migration),
            Box::new(m20261123_020001_manifests_and_api_use::Migration),
            Box::new(m20261123_090001_duplicates::Migration),
            Box::new(m20261123_110001_vaultwarden_import::Migration),
            Box::new(m20261123_060001_sends::Migration),
            Box::new(m20261123_060002_space_policy_settings::Migration),
            Box::new(m20261123_040001_notify::Migration),
            Box::new(m20261123_070001_admin::Migration),
            Box::new(m20261123_030001_passkeys::Migration),
            Box::new(m20261123_080001_privacy::Migration),
            Box::new(m20261123_050001_bw_docs::Migration),
            Box::new(m20261123_100001_federation_wiring::Migration),
            Box::new(m20261124_010001_merge_space_policies::Migration),
            Box::new(m20261125_010001_recovery_codes::Migration),
            Box::new(m20261125_020001_event_reader_index::Migration),
            Box::new(m20261125_050001_federation_erasures::Migration),
            Box::new(m20261125_030001_bw_devices::Migration),
            Box::new(m20261125_090001_peer_events::Migration),
            Box::new(m20261125_090002_key_records::Migration),
            Box::new(m20261125_090003_learned_keys::Migration),
            Box::new(m20261126_010001_space_chain::Migration),
            Box::new(m20261126_020001_two_step_version::Migration),
            Box::new(m20261126_030001_pending_changes::Migration),
            Box::new(m20261126_040001_federation_insight::Migration),
            Box::new(m20261127_030001_space_recovery_boxes::Migration),
            Box::new(m20261128_010001_bw_user_key_ids::Migration),
            Box::new(m20261128_020001_held_demotions::Migration),
        ]
    }
}
