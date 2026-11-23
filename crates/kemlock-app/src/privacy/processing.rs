//! The processing summary: a Markdown and JSON draft of the record of processing activities
//! (GDPR Art. 30(1)), written from the server's settings. The admin console's Compliance › Export
//! processing summary runs it. The operator adds its name and the DPO's contact if the draft
//! doesn't have them, and owns the result: the operator is the controller.
//!
//! It covers Art. 30(1)'s points: the controller, the purposes, the categories of people and data,
//! the recipients (the mail provider, the identity provider, the push relay, S3 storage, the
//! backup destination, federation peers), transfers, the time limits from the retention table and
//! the security measures.

use super::ports::{PrivacySettings, ProcessingInputs, ProcessingSource};
use crate::error::AppError;
use crate::ports::Clock;
use kemlock_domain::privacy::{DEVICE_APPROVAL_MINUTES, Retention, TOMBSTONE_DAYS};
use serde_json::{Value, json};

/// The format name inside the JSON.
pub const SUMMARY_FORMAT: &str = "kemlock-processing-summary/1";

const NAME_PLACEHOLDER: &str = "[operator name: add before use]";
const DPO_PLACEHOLDER: &str = "[DPO or privacy contact: add before use]";

/// The draft, in both forms.
#[derive(Clone, Debug, PartialEq)]
pub struct ProcessingSummary {
    pub json: Value,
    pub markdown: String,
}

/// One recipient of personal data and why.
struct Recipient {
    name: String,
    role: &'static str,
    data: &'static str,
}

fn recipients(inputs: &ProcessingInputs) -> Vec<Recipient> {
    let mut out = Vec::new();
    if let Some(host) = &inputs.smtp_provider {
        out.push(Recipient {
            name: format!("Mail provider ({host})"),
            role: "processor",
            data: "recipient addresses and message text of notices the server sends; bodies are never stored by the server",
        });
    }
    if let Some(issuer) = &inputs.identity_provider {
        out.push(Recipient {
            name: format!("Identity provider ({issuer})"),
            role: "controller or processor, as the operator set it up",
            data: "the sign-in handshake of people who use single sign-on",
        });
    }
    if inputs.push_relay {
        out.push(Recipient {
            name: "Kemlock push relay".to_owned(),
            role: "processor, under a DPA",
            data: "device push tokens, the server's installation id, the server's IP address and times; no email, account id or item",
        });
    }
    if let Some(endpoint) = &inputs.s3_storage {
        out.push(Recipient {
            name: format!("Object storage ({endpoint})"),
            role: "processor",
            data: "encrypted attachment files under random ids",
        });
    }
    if let Some(destination) = &inputs.backup_destination {
        out.push(Recipient {
            name: format!("Backup destination ({destination})"),
            role: "processor, if a third party",
            data: "backup archives, encrypted to the operator's age key, which the server cannot read",
        });
    }
    if inputs.federation_peers > 0 {
        out.push(Recipient {
            name: format!("Federated servers ({})", inputs.federation_peers),
            role: "controllers of their own copy",
            data: "encrypted items of vaults that are federated, and the metadata that syncing them needs",
        });
    }
    out
}

fn retention_rows(r: &Retention) -> Vec<(&'static str, String, &'static str)> {
    let ip = if r.keeps_full_ips() {
        format!(
            "truncated on write (IPv4 /24, IPv6 /48); the full address is kept {} days beside it",
            r.full_ip_days
        )
    } else {
        "truncated on write (IPv4 /24, IPv6 /48); the full address is never kept".to_owned()
    };
    let grace = if r.deleted_account_grace_days == 0 {
        "erased at once".to_owned()
    } else {
        format!(
            "erased after a grace period of {} days",
            r.deleted_account_grace_days
        )
    };
    vec![
        (
            "Event log",
            format!("{} days", r.event_log_days),
            "deleted; events of an erased account keep no name or email",
        ),
        (
            "Sign-in log",
            format!("{} days", r.sign_in_log_days),
            "deleted",
        ),
        ("IP addresses", ip, "dropped with their log row"),
        (
            "Tombstones",
            format!("{TOMBSTONE_DAYS} days"),
            "purged; a device offline longer runs a full sync",
        ),
        (
            "Trash",
            format!("{} days", r.trash_days),
            "Bitwarden-API items: the item, its files and its history are deleted. Kemlock items keep their trash inside the ciphertext, which the server cannot read: the apps empty it",
        ),
        (
            "Deleted accounts",
            grace,
            "rows and files removed; backups age out",
        ),
        (
            "Device approvals",
            format!("{DEVICE_APPROVAL_MINUTES} minutes"),
            "expire unused",
        ),
        (
            "Backups",
            format!("{} days", r.backup_days),
            "oldest deleted; erasure reaches backups only as they age out",
        ),
        (
            "Email log (recipient, template, result)",
            format!("{} days", r.email_log_days),
            "deleted; message bodies are never stored",
        ),
    ]
}

const PURPOSES: [&str; 4] = [
    "Providing the password-vault service: signing accounts in, storing and syncing their end-to-end encrypted vaults, and sharing items in spaces.",
    "Security of the service: the event log, the sign-in log and alerts, so that abuse and breaches can be seen and answered.",
    "Operating the service: sending account notices by email, keeping backups, and keeping the software running.",
    "Meeting legal duties: answering access, erasure and other requests from account holders, and notifying breaches.",
];

const SUBJECTS: [&str; 3] = [
    "Account holders: the people who have an account on this server.",
    "Members of spaces: people invited to a shared vault.",
    "Emergency contacts: people an account holder named as able to ask for access.",
];

const CATEGORIES: [&str; 6] = [
    "Account data: email address, display name, role, the sign-in settings and the keys the account's apps made (public keys, and private keys sealed so the server cannot open them).",
    "Device data: device names and kinds, and when each was last seen.",
    "Logs: sign-in times and results and events (who did what, when), with IP addresses truncated.",
    "Vault metadata: item counts, sizes, kinds and dates. Item contents, names, folders and keys stay sealed on devices.",
    "Sealed content: ciphertext of items and attachments, which the server stores and cannot read.",
    "Contact data of invitees and emergency contacts: the email address the account holder gave.",
];

const SECURITY: [&str; 9] = [
    "End-to-end encryption: the server never holds a key that opens a vault.",
    "OPAQUE password authentication: the server keeps no password hash to guess offline.",
    "Secrets the server must read (the OPAQUE server secret, SMTP, SSO and two-step secrets) are sealed under server.key, which is never in a backup.",
    "Access tokens bound to the device's key (DPoP); refresh tokens stored only as hashes.",
    "Rate limits on sign-in, two-step codes and registration.",
    "Truncated IP addresses and the shortest retention by default; telemetry off.",
    "Backups encrypted to an age recipient the server holds only the public half of.",
    "An event log with admin email alerts, and an incident export for breach notices.",
    "Transport security is the operator's: serve the server over HTTPS behind a proxy the operator runs.",
];

/// Builds the draft for these settings.
pub fn render_processing_summary(
    inputs: &ProcessingInputs,
    retention: &Retention,
) -> ProcessingSummary {
    let name = inputs.operator_name.as_deref().unwrap_or(NAME_PLACEHOLDER);
    let dpo = inputs.dpo_contact.as_deref().unwrap_or(DPO_PLACEHOLDER);
    let recips = recipients(inputs);
    let rows = retention_rows(retention);

    let mut optional = Vec::new();
    if inputs.update_check {
        optional.push(
            "Update check: one request a day to the release feed, carrying the server's IP and version, nothing about users.",
        );
    }
    if inputs.website_icons {
        optional.push(
            "Website icons: the server fetches an item's icon from its domain, so that site sees the server's IP and the server learns which domains people store.",
        );
    }

    let transfers = if recips.is_empty() {
        "None: no recipient outside the operator's own server is set up.".to_owned()
    } else {
        "Depends on where each recipient above runs. The operator must record the country and the safeguard (adequacy decision, standard contractual clauses) for each one outside the EEA.".to_owned()
    };

    let json = json!({
        "format": SUMMARY_FORMAT,
        "controller": { "name": name, "dpoContact": dpo },
        "purposes": PURPOSES,
        "dataSubjects": SUBJECTS,
        "dataCategories": CATEGORIES,
        "recipients": recips.iter().map(|r| json!({
            "name": r.name, "role": r.role, "data": r.data,
        })).collect::<Vec<_>>(),
        "optionalProcessing": optional,
        "transfers": transfers,
        "retention": rows.iter().map(|(data, period, then)| json!({
            "data": data, "period": period, "then": then,
        })).collect::<Vec<_>>(),
        "securityMeasures": SECURITY,
        "notes": [
            "This is a draft written from the server's settings. The operator is the controller and must check it.",
            "The exemption for organisations under 250 staff rarely applies, since a password server's processing is not occasional (Art. 30(5)).",
        ],
    });

    let list =
        |items: &[&str]| -> String { items.iter().map(|i| format!("- {i}\n")).collect::<String>() };
    let mut md = String::new();
    md.push_str("# Record of processing activities (draft)\n\n");
    md.push_str("Written from the Kemlock Server's settings for GDPR Art. 30(1). The operator is the controller, checks it and keeps it.\n\n");
    md.push_str("## Controller\n\n");
    md.push_str(&format!(
        "- Name: {name}\n- Data protection officer or privacy contact: {dpo}\n\n"
    ));
    md.push_str("## Purposes\n\n");
    md.push_str(&list(&PURPOSES));
    md.push_str("\n## Categories of people\n\n");
    md.push_str(&list(&SUBJECTS));
    md.push_str("\n## Categories of personal data\n\n");
    md.push_str(&list(&CATEGORIES));
    md.push_str("\n## Recipients\n\n");
    if recips.is_empty() {
        md.push_str("None outside this server.\n");
    }
    for r in &recips {
        md.push_str(&format!("- {} ({}): {}\n", r.name, r.role, r.data));
    }
    if !optional.is_empty() {
        md.push_str("\n## Optional processing the admin turned on\n\n");
        md.push_str(&list(&optional));
    }
    md.push_str("\n## Transfers to third countries\n\n");
    md.push_str(&transfers);
    md.push_str("\n\n## Time limits for erasure\n\n| Data | Kept | Then |\n|---|---|---|\n");
    for (data, period, then) in &rows {
        md.push_str(&format!("| {data} | {period} | {then} |\n"));
    }
    md.push_str("\n## Security measures (Art. 32)\n\n");
    md.push_str(&list(&SECURITY));
    md.push_str("\nThe exemption for organisations under 250 staff rarely applies: a password server's processing is not occasional (Art. 30(5)).\n");

    ProcessingSummary { json, markdown: md }
}

/// Reads the installation's settings and writes the summary.
#[derive(Debug)]
pub struct ExportProcessingSummary<S, P, C> {
    pub source: S,
    pub settings: P,
    pub clock: C,
}

impl<S: ProcessingSource, P: PrivacySettings, C: Clock> ExportProcessingSummary<S, P, C> {
    pub async fn execute(&self) -> Result<ProcessingSummary, AppError> {
        let inputs = self.source.inputs().await?;
        let retention = self.settings.retention().await?;
        let mut summary = render_processing_summary(&inputs, &retention);
        if let Value::Object(map) = &mut summary.json {
            let at = super::export::iso(self.clock.now());
            map.insert("generatedAt".to_owned(), Value::String(at.clone()));
            summary.markdown.push_str(&format!("\nGenerated {at}.\n"));
        }
        Ok(summary)
    }
}
