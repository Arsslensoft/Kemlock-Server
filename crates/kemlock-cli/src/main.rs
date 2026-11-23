//! kemlock-cli: migrate, healthcheck, reset-admin, backup, restore, import-vaultwarden.
//!
//! It reads the same configuration as the server (environment, then the TOML file), so
//! `kemlock-cli migrate` and the container's `HEALTHCHECK` need nothing more.

mod backup_cmd;
mod import_vaultwarden;

use kemlock_server::Config;
use kemlock_server::healthcheck::healthy;
use std::process::ExitCode;

const USAGE: &str = "\
kemlock-cli: administration for Kemlock Server

usage: kemlock-cli <command>

commands:
  migrate        apply pending database migrations, then exit
  healthcheck    ask the local server's /alive and exit 0 if it answers 200, else 1
  reset-admin    start over with a new first admin (needs --yes; not available yet)
  import-vaultwarden --from <folder|url> [--files <folder>] [--twice] [--apply]
                 move in from Vaultwarden: prints a dry-run plan; --apply writes it to the server
                 move in from Vaultwarden: prints a dry-run plan; --apply writes (see below)
  backup [--to <folder|s3://bucket/prefix>] [--recipient <age1...>]
                 take an encrypted backup now (settings: KEMLOCK_BACKUP_*); server.key is never in it
  restore <archive> --identity <file> [--server-key <file>] --yes
                 replace the database and files with an archive's (stop the server first)
  restore --check <archive> --identity <file> --server-key <file> [--record]
                 the drill: restore into a scratch folder, start a read-only server there and
                 compare row counts and file hashes with the archive's manifest
  restore --pre-migration <version> --yes
                 put back the SQLite copy made before the upgrade to that version
  help           show this text

The commands read the server's configuration: DATABASE_URL, DATA_FOLDER, ROCKET_PORT and the
optional TOML file (KEMLOCK_CONFIG), and KEMLOCK_SERVER_KEY. import-vaultwarden never
writes to Vaultwarden's data (without --apply it reads no configuration at all); its --from is
a Vaultwarden data folder or a mysql:// or
postgres:// URL, --files the data folder beside a MySQL or PostgreSQL server, and --twice copies
once while Vaultwarden runs and again, for what changed, after you stop it.";

#[derive(Debug, Clone, PartialEq, Eq)]
enum Command {
    Migrate,
    Healthcheck,
    ResetAdmin { yes: bool },
    ImportVaultwarden(import_vaultwarden::ImportArgs),
    Backup(backup_cmd::BackupArgs),
    Restore(backup_cmd::RestoreArgs),
    Help,
}

fn parse(args: &[String]) -> Result<Command, String> {
    let (name, rest) = args
        .split_first()
        .ok_or_else(|| "no command given".to_owned())?;
    let no_extra = |command: Command| {
        if rest.is_empty() {
            Ok(command)
        } else {
            Err(format!("{name} takes no arguments, got {}", rest.join(" ")))
        }
    };
    match name.as_str() {
        "migrate" => no_extra(Command::Migrate),
        "healthcheck" => no_extra(Command::Healthcheck),
        "help" | "--help" | "-h" => Ok(Command::Help),
        "reset-admin" => match rest {
            [] => Ok(Command::ResetAdmin { yes: false }),
            [flag] if flag == "--yes" => Ok(Command::ResetAdmin { yes: true }),
            _ => Err("reset-admin takes only --yes".to_owned()),
        },
        "import-vaultwarden" => {
            import_vaultwarden::parse_args(rest).map(Command::ImportVaultwarden)
        }
        "backup" => backup_cmd::parse_backup(rest).map(Command::Backup),
        "restore" => backup_cmd::parse_restore(rest).map(Command::Restore),
        other => Err(format!("unknown command {other:?}")),
    }
}

fn healthcheck(config: &Config) -> ExitCode {
    if healthy(config.port) {
        ExitCode::SUCCESS
    } else {
        eprintln!(
            "kemlock-cli: nothing answered /alive on port {}",
            config.port
        );
        ExitCode::FAILURE
    }
}

async fn migrate(config: &Config) -> ExitCode {
    println!("migrating {}", redact(&config.database_url));
    match kemlock_store_sql::SqlStore::connect(&config.database_url).await {
        Ok(store) => {
            // `connect` migrates; `migrate` is idempotent and makes the intent explicit.
            let result = store.migrate().await;
            let _ = store.close().await;
            match result {
                Ok(()) => {
                    println!("the database is up to date");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("kemlock-cli: migration failed: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        Err(e) => {
            eprintln!("kemlock-cli: can't open the database: {e}");
            ExitCode::FAILURE
        }
    }
}

/// A database URL without its password, for printing.
fn redact(url: &str) -> String {
    match (url.split_once("://"), url.rfind('@')) {
        (Some((scheme, _)), Some(at)) if at > scheme.len() + 3 => {
            let host = &url[at + 1..];
            let userinfo = &url[scheme.len() + 3..at];
            let user = userinfo.split(':').next().unwrap_or_default();
            format!("{scheme}://{user}:***@{host}")
        }
        _ => url.to_owned(),
    }
}

fn reset_admin(yes: bool) -> u8 {
    println!(
        "reset-admin would remove the admin role from every account, close setup's finished \
         state and print a new setup code at the server's next start, so a new first admin can \
         be made. Accounts, vaults and devices stay as they are."
    );
    if !yes {
        eprintln!(
            "kemlock-cli: refusing without --yes: this changes who can administer the server"
        );
        return 2;
    }
    eprintln!(
        "kemlock-cli: reset-admin isn't implemented yet. The admin console and the store's \
         settings it needs come in a later release; until then, restore from a backup or ask on \
         the project's issue tracker."
    );
    1
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = match parse(&args) {
        Ok(command) => command,
        Err(message) => {
            eprintln!("kemlock-cli: {message}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    if command == Command::Help {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    // The Vaultwarden import reads no server configuration, only its arguments.
    let command = match command {
        Command::ImportVaultwarden(args) => {
            return ExitCode::from(import_vaultwarden::run(args).await);
        }
        other => other,
    };
    let config = match Config::load() {
        Ok(config) => config,
        Err(e) => {
            eprintln!("kemlock-cli: {e}");
            return ExitCode::from(2);
        }
    };
    match command {
        Command::Migrate => migrate(&config).await,
        Command::Healthcheck => healthcheck(&config),
        Command::ResetAdmin { yes } => ExitCode::from(reset_admin(yes)),
        Command::Backup(args) => {
            ExitCode::from(backup_cmd::run_backup_command(&config, args).await)
        }
        Command::Restore(args) => {
            ExitCode::from(backup_cmd::run_restore_command(&config, args).await)
        }
        Command::Help | Command::ImportVaultwarden(_) => ExitCode::SUCCESS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn commands_parse() {
        assert_eq!(parse(&args(&["migrate"])), Ok(Command::Migrate));
        assert_eq!(parse(&args(&["healthcheck"])), Ok(Command::Healthcheck));
        assert_eq!(parse(&args(&["help"])), Ok(Command::Help));
        assert_eq!(parse(&args(&["--help"])), Ok(Command::Help));
        assert_eq!(
            parse(&args(&["reset-admin"])),
            Ok(Command::ResetAdmin { yes: false })
        );
        assert_eq!(
            parse(&args(&["reset-admin", "--yes"])),
            Ok(Command::ResetAdmin { yes: true })
        );
    }

    #[test]
    fn import_vaultwarden_parses_its_arguments() {
        let parsed = parse(&args(&["import-vaultwarden", "--from", "/data", "--twice"]));
        match parsed {
            Ok(Command::ImportVaultwarden(a)) => {
                assert_eq!(a.from, "/data");
                assert!(a.twice);
                assert!(!a.apply, "a dry run unless --apply is given");
            }
            other => panic!("unexpected {other:?}"),
        }
        assert!(parse(&args(&["import-vaultwarden"])).is_err());
    }

    #[test]
    fn bad_commands_are_refused() {
        assert!(parse(&[]).is_err());
        assert!(parse(&args(&["explode"])).is_err());
        assert!(parse(&args(&["migrate", "now"])).is_err());
        assert!(parse(&args(&["reset-admin", "--please"])).is_err());
    }

    #[test]
    fn passwords_are_hidden_when_printing_a_database_url() {
        assert_eq!(
            redact("postgres://kemlock:hunter2@db:5432/kemlock"),
            "postgres://kemlock:***@db:5432/kemlock"
        );
        assert_eq!(
            redact("sqlite://data/db.sqlite3?mode=rwc"),
            "sqlite://data/db.sqlite3?mode=rwc"
        );
        assert_eq!(redact("sqlite::memory:"), "sqlite::memory:");
    }

    #[test]
    fn reset_admin_refuses_without_yes_and_says_not_yet_with_it() {
        assert_eq!(reset_admin(false), 2);
        assert_eq!(reset_admin(true), 1);
    }
}
