//! One module per table: the SeaORM entity and the mapping between its rows and the domain.
//!
//! Nothing here leaves the crate. SeaORM's derive macros write `pub` items, which are not
//! reachable from outside, so the lint that flags that is allowed for these modules.
#![allow(unreachable_pub)]

pub(crate) mod admin;
pub(crate) mod attachments;
pub(crate) mod auth_requests;
pub(crate) mod bw_account_extras;
pub(crate) mod bw_accounts;
pub(crate) mod bw_attachments;
pub(crate) mod bw_devices;
pub(crate) mod bw_docs;
pub(crate) mod bw_tries;
pub(crate) mod bw_user_key_ids;
pub(crate) mod changes;
pub(crate) mod custom_fields;
pub(crate) mod dedup_owners;
pub(crate) mod device_api_use;
pub(crate) mod device_key_copies;
pub(crate) mod devices;
pub(crate) mod duplicate_dismissals;
pub(crate) mod email_changes;
pub(crate) mod email_confirmations;
pub(crate) mod emergency_access;
pub(crate) mod events;
pub(crate) mod federation;
pub(crate) mod federation_insight;
pub(crate) mod federation_keys;
pub(crate) mod federation_logs;
pub(crate) mod federation_wiring;
pub(crate) mod item_tags;
pub(crate) mod items;
pub(crate) mod job_leases;
pub(crate) mod live_nudges;
pub(crate) mod passkeys;
pub(crate) mod pending_erasures;
pub(crate) mod policies;
pub(crate) mod push_tokens;
pub(crate) mod recovery_kits;
pub(crate) mod refresh_tokens;
pub(crate) mod revoked_families;
pub(crate) mod rotation_previous_keys;
pub(crate) mod rotation_staged_items;
pub(crate) mod second_step_attempts;
pub(crate) mod sends;
pub(crate) mod server_meta;
pub(crate) mod settings;
pub(crate) mod sign_in_log;
pub(crate) mod signed_manifests;
pub(crate) mod space_chain;
pub(crate) mod space_recovery;
pub(crate) mod space_tables;
pub(crate) mod sso;
pub(crate) mod sync_horizon;
pub(crate) mod two_factor;
pub(crate) mod two_factor_recovery;
pub(crate) mod two_step_versions;
pub(crate) mod users;
pub(crate) mod vw_import_ids;
pub(crate) mod vw_rows;
pub(crate) mod webauthn_challenges;
