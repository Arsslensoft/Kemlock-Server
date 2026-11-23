//! The incident export: the facts GDPR Art. 33(3) asks for in a breach notice to the supervisory
//! authority, drawn from the event log and the sign-in log: the accounts affected, the time
//! window and the categories of data. The admin console runs it from the Compliance page.
//!
//! The authority must be told "without undue delay and, where feasible, not later than 72 hours"
//! after the operator becomes aware of a breach (Art. 33(1)); when the admin says when that was,
//! the export prints the deadline. The server can't judge whether a breach is likely to put people
//! at risk: that call, the description of the breach and the contact point are the operator's.

use super::export::iso;
use super::ports::PrivacyLog;
use crate::error::AppError;
use crate::ports::{Clock, Event, UserRepo};
use kemlock_domain::UserId;
use kemlock_domain::privacy::{SignInOutcome, StoredEvent};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use time::{Duration, OffsetDateTime};

/// The format name inside the JSON.
pub const INCIDENT_FORMAT: &str = "kemlock-incident-export/1";

/// The Art. 33(1) window.
pub const NOTIFY_WITHIN: Duration = Duration::hours(72);

/// What to export.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IncidentRequest {
    /// The window the incident covers, `from` included and `to` excluded.
    pub from: OffsetDateTime,
    pub to: OffsetDateTime,
    /// Only these accounts; `None` lists every account with activity in the window.
    pub accounts: Option<Vec<UserId>>,
    /// When the operator became aware of the breach, for the 72-hour deadline.
    pub aware_at: Option<OffsetDateTime>,
    /// Categories of data the operator adds to the ones the logs show.
    pub extra_categories: Vec<String>,
}

/// The export, in both forms.
#[derive(Clone, Debug, PartialEq)]
pub struct IncidentExport {
    pub json: Value,
    pub markdown: String,
    pub affected_accounts: usize,
}

/// The category of data an event action touches.
fn category_of(action: &str) -> &'static str {
    if action.starts_with("auth.") {
        "Sign-in activity: times, results, truncated IP addresses and device ids"
    } else if action.starts_with("account.export") {
        "Account record and encrypted vault, as exported"
    } else if action.starts_with("account.") {
        "Account records"
    } else if action.contains("item") {
        "Vault metadata: item ids, counts and times (item contents are encrypted; the server cannot read them)"
    } else if action.contains("file") || action.contains("attachment") {
        "Attachment records (the files are encrypted)"
    } else if action.contains("space") || action.contains("member") || action.contains("collection")
    {
        "Space membership and collection records"
    } else if action.contains("device") || action.contains("key") {
        "Device and key records"
    } else {
        "Other event-log records"
    }
}

#[derive(Default)]
struct Activity {
    events: u64,
    sign_ins: u64,
    first: Option<OffsetDateTime>,
    last: Option<OffsetDateTime>,
}

impl Activity {
    fn touch(&mut self, at: OffsetDateTime) {
        self.first = Some(self.first.map_or(at, |f| f.min(at)));
        self.last = Some(self.last.map_or(at, |l| l.max(at)));
    }
}

#[derive(Debug)]
pub struct ExportIncident<U, L, C> {
    pub users: U,
    pub log: L,
    pub clock: C,
}

impl<U: UserRepo, L: PrivacyLog, C: Clock> ExportIncident<U, L, C> {
    pub async fn execute(
        &self,
        request: &IncidentRequest,
        requested_by: UserId,
    ) -> Result<IncidentExport, AppError> {
        if request.to <= request.from {
            return Err(AppError::Invalid("the window must end after it starts"));
        }
        let now = self.clock.now();
        let events: Vec<StoredEvent> = self.log.events_between(request.from, request.to).await?;
        let sign_ins = self.log.sign_ins_between(request.from, request.to).await?;

        let wanted = |user: UserId| {
            request
                .accounts
                .as_ref()
                .is_none_or(|only| only.contains(&user))
        };
        let mut activity: BTreeMap<UserId, Activity> = BTreeMap::new();
        let mut action_counts: BTreeMap<String, u64> = BTreeMap::new();
        let mut categories: BTreeSet<String> = BTreeSet::new();
        for event in &events {
            let Some(actor) = event.actor.filter(|a| wanted(*a)) else {
                continue;
            };
            let entry = activity.entry(actor).or_default();
            entry.events += 1;
            entry.touch(event.at);
            *action_counts.entry(event.action.clone()).or_default() += 1;
            categories.insert(category_of(&event.action).to_owned());
        }
        let (mut successes, mut failures) = (0u64, 0u64);
        for attempt in &sign_ins {
            match attempt.outcome {
                SignInOutcome::Success => successes += 1,
                SignInOutcome::Failure => failures += 1,
            }
            let Some(user) = attempt.user.filter(|u| wanted(*u)) else {
                continue;
            };
            let entry = activity.entry(user).or_default();
            entry.sign_ins += 1;
            entry.touch(attempt.at);
        }
        if !sign_ins.is_empty() {
            categories.insert(category_of("auth.sign_in").to_owned());
        }
        categories.insert(
            "Account identifiers and email addresses (the accounts listed here)".to_owned(),
        );
        categories.extend(request.extra_categories.iter().cloned());

        let mut accounts = Vec::new();
        for (user, seen) in &activity {
            // An erased account has no row: its events keep no name or email.
            let email = self
                .users
                .by_id(*user)
                .await?
                .map(|u| u.email.as_str().to_owned());
            accounts.push((*user, email, seen));
        }

        let notify_by = request.aware_at.map(|at| at + NOTIFY_WITHIN);
        let json = json!({
            "format": INCIDENT_FORMAT,
            "generatedAt": iso(now),
            "window": { "from": iso(request.from), "to": iso(request.to) },
            "awareAt": request.aware_at.map(iso),
            "notifyAuthorityBy": notify_by.map(iso),
            "affectedAccountCount": accounts.len(),
            "affectedAccounts": accounts.iter().map(|(id, email, seen)| json!({
                "id": id.to_string(),
                "email": email,
                "events": seen.events,
                "signIns": seen.sign_ins,
                "firstSeen": seen.first.map(iso),
                "lastSeen": seen.last.map(iso),
            })).collect::<Vec<_>>(),
            "eventCounts": action_counts,
            "signInCounts": { "success": successes, "failure": failures },
            "dataCategories": categories,
            "notes": [
                "Art. 33(3) asks for the nature of the breach, the contact point, the likely consequences and the measures taken. This export gives the accounts, the window and the categories; the operator writes the rest.",
                "Item contents, names and keys are sealed on devices; the server holds only ciphertext it cannot read.",
            ],
        });

        let mut md = String::new();
        md.push_str("# Incident export (draft)\n\n");
        md.push_str(&format!(
            "- Window: {} to {}\n- Generated: {}\n",
            iso(request.from),
            iso(request.to),
            iso(now)
        ));
        if let (Some(aware), Some(by)) = (request.aware_at, notify_by) {
            md.push_str(&format!(
                "- Operator aware: {}\n- Notify the supervisory authority by: {} (72 hours, Art. 33(1))\n",
                iso(aware),
                iso(by)
            ));
        }
        md.push_str(&format!(
            "- Sign-in attempts in the window: {successes} succeeded, {failures} failed\n\n"
        ));
        md.push_str(&format!("## Affected accounts ({})\n\n", accounts.len()));
        md.push_str("| Account | Email | Events | Sign-ins | First seen | Last seen |\n|---|---|---|---|---|---|\n");
        for (id, email, seen) in &accounts {
            md.push_str(&format!(
                "| {id} | {} | {} | {} | {} | {} |\n",
                email.as_deref().unwrap_or("(erased)"),
                seen.events,
                seen.sign_ins,
                seen.first.map(iso).unwrap_or_default(),
                seen.last.map(iso).unwrap_or_default()
            ));
        }
        md.push_str("\n## Categories of data\n\n");
        for category in &categories {
            md.push_str(&format!("- {category}\n"));
        }
        if !action_counts.is_empty() {
            md.push_str("\n## Events by action\n\n");
            for (action, count) in &action_counts {
                md.push_str(&format!("- {action}: {count}\n"));
            }
        }
        md.push_str("\nThe operator adds the nature of the breach, the contact point, the likely consequences and the measures taken (Art. 33(3)).\n");

        // The export is part of the record of the incident.
        let event = Event {
            actor: Some(requested_by),
            device: None,
            action: "incident.export",
            target: None,
            at: now,
        };
        if let Err(e) = self.log.record_event(event, None).await {
            tracing::warn!(error = %e, "couldn't record an incident export");
        }
        Ok(IncidentExport {
            json,
            markdown: md,
            affected_accounts: accounts.len(),
        })
    }
}
