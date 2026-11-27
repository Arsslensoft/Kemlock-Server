//! The dry-run plan: what a move would put in Kemlock Server, in words, without writing anything.

use crate::diff::SnapshotDiff;
use crate::mapping::{FileKind, MappedImport};
use crate::snapshot::SnapshotMeta;
use kemlock_domain::Owner;
use std::fmt::Write;

fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["bytes", "KiB", "MiB", "GiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} bytes")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// Renders the plan. `diff` is the change between the two copies of a two-pass move.
pub fn render_plan(
    meta: &SnapshotMeta,
    mapped: &MappedImport,
    diff: Option<&SnapshotDiff>,
) -> String {
    let mut out = String::new();
    // Writing to a String can't fail.
    let _ = write_plan(&mut out, meta, mapped, diff);
    out
}

fn write_plan(
    out: &mut String,
    meta: &SnapshotMeta,
    mapped: &MappedImport,
    diff: Option<&SnapshotDiff>,
) -> std::fmt::Result {
    writeln!(
        out,
        "Vaultwarden {} ({}), read from {}",
        meta.release, meta.database, meta.source
    )?;
    writeln!(out)?;

    let personal = mapped
        .items
        .iter()
        .filter(|i| matches!(i.owner, Owner::User(_)))
        .count();
    let shared = mapped.items.len() - personal;
    writeln!(
        out,
        "accounts        {:>6}   Compatible mode; same master passwords, keys and KDF settings",
        mapped.accounts.len()
    )?;
    writeln!(
        out,
        "items           {:>6}   `bw` rows, still encrypted ({personal} personal, {shared} in organizations)",
        mapped.items.len()
    )?;
    writeln!(out, "folders         {:>6}", mapped.folders.len())?;
    writeln!(
        out,
        "item settings   {:>6}   folder, favorite and archive state per user",
        mapped.cipher_states.len()
    )?;
    writeln!(
        out,
        "attachments     {:>6}   rows",
        mapped.attachments.len()
    )?;
    let attachment_files = mapped
        .files
        .iter()
        .filter(|f| f.kind == FileKind::Attachment)
        .count();
    let send_files = mapped.files.len() - attachment_files;
    writeln!(
        out,
        "files to copy   {:>6}   {attachment_files} attachment files, {send_files} send files, {} in all",
        mapped.files.len(),
        human_bytes(mapped.file_bytes())
    )?;
    writeln!(out)?;

    writeln!(out, "carried as stored:")?;
    for table in &mapped.carried {
        if !table.is_empty() {
            writeln!(out, "  {:<22} {:>6} rows", table.name(), table.len())?;
        }
    }
    writeln!(out)?;

    writeln!(
        out,
        "rsa_key.pem     {}",
        if mapped.rsa_key.is_some() {
            "carried; signed-in apps stay signed in"
        } else {
            "not found"
        }
    )?;
    writeln!(
        out,
        "settings        {} carried from config.json",
        mapped.settings.values.len()
    )?;
    // Each value that will be written, so nobody agrees to a setting they never saw.
    for (name, value) in &mapped.settings.values {
        writeln!(out, "                  {name} = {value}")?;
    }
    if !mapped.settings.ignored.is_empty() {
        writeln!(
            out,
            "                not carried: {}",
            // Names come from the source's file: quoted and escaped, so one can't forge a line.
            mapped
                .settings
                .ignored
                .iter()
                .map(|name| format!("{name:?}"))
                .collect::<Vec<_>>()
                .join(", ")
        )?;
    }
    if !mapped.settings.secrets.is_empty() {
        writeln!(
            out,
            "                to enter again: {}",
            mapped.settings.secrets.join(", ")
        )?;
    }

    if !mapped.warnings.is_empty() {
        writeln!(out)?;
        writeln!(out, "read before moving:")?;
        for warning in &mapped.warnings {
            writeln!(out, "  - {warning}")?;
        }
    }

    if let Some(diff) = diff {
        writeln!(out)?;
        writeln!(out, "changed between the two copies:")?;
        for line in diff.to_string().lines() {
            writeln!(out, "  {line}")?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mapping::{FileCopy, MappedRsaKey};
    use std::path::PathBuf;

    #[test]
    fn sizes_are_printed_for_people() {
        assert_eq!(human_bytes(10), "10 bytes");
        assert_eq!(human_bytes(1536), "1.5 KiB");
        assert_eq!(human_bytes(3 * 1024 * 1024), "3.0 MiB");
    }

    #[test]
    fn the_plan_counts_and_warns() {
        let meta = SnapshotMeta {
            database: "SQLite",
            release: "1.37.5",
            source: "/data".into(),
        };
        let mut mapped = MappedImport::default();
        mapped.files.push(FileCopy {
            kind: FileKind::Attachment,
            from: PathBuf::from("/data/attachments/c/a"),
            storage_key: "attachments/c/a".into(),
            size: 2048,
        });
        mapped.rsa_key = Some(MappedRsaKey {
            private_pem: b"pem".to_vec(),
            public_pem: None,
        });
        mapped.warnings.push("something to read".into());
        mapped.settings.secrets.push("smtp_password".into());
        mapped
            .settings
            .values
            .insert("signups_allowed".into(), serde_json::json!(false));
        mapped
            .settings
            .values
            .insert("smtp_host".into(), serde_json::json!("mail.example.org"));
        let plan = render_plan(&meta, &mapped, None);
        assert!(
            plan.starts_with("Vaultwarden 1.37.5 (SQLite), read from /data"),
            "{plan}"
        );
        assert!(
            plan.contains("1 attachment files, 0 send files, 2.0 KiB in all"),
            "{plan}"
        );
        assert!(plan.contains("rsa_key.pem     carried"), "{plan}");
        assert!(plan.contains("to enter again: smtp_password"), "{plan}");
        assert!(plan.contains("signups_allowed = false"), "{plan}");
        assert!(plan.contains("smtp_host = \"mail.example.org\""), "{plan}");
        assert!(plan.contains("- something to read"), "{plan}");
        assert!(!plan.contains("changed between"), "{plan}");
    }

    #[test]
    fn a_setting_name_from_the_source_cannot_forge_a_plan_line() {
        let meta = SnapshotMeta {
            database: "SQLite",
            release: "1.37.5",
            source: "/data".into(),
        };
        let mut mapped = MappedImport::default();
        mapped
            .settings
            .ignored
            .push("x\nrsa_key.pem     carried".into());
        let plan = render_plan(&meta, &mapped, None);
        // No key file in this source: the real line says "not found", so a "carried" line could
        // only be forged.
        assert!(plan.contains("\nrsa_key.pem     not found"), "{plan}");
        assert!(!plan.contains("\nrsa_key.pem     carried"), "{plan}");
        assert!(plan.contains(r#""x\nrsa_key.pem     carried""#), "{plan}");
    }
}
