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
  reset-admin [--promote <email>] --yes
                 start over with a new first admin: demotes every admin, then the next start
                 prints a new setup code (needs --yes); with --promote <email>, that existing
                 account (it needs a confirmed two-step method) becomes the admin instead
  import-vaultwarden --from <folder|url> [--files <folder>] [--twice] [--apply]
                 move in from Vaultwarden: prints a dry-run plan; --apply writes it to the server
                 move in from Vaultwarden: prints a dry-run plan; --apply writes (see below)
  backup [--to <folder|s3://bucket/prefix>] [--recipient <age1...>] [--allow-unauthenticated]
                 take an encrypted backup now (settings: KEMLOCK_BACKUP_*); server.key is never in it;
                 without a readable server.key it refuses, unless --allow-unauthenticated
  restore <archive> --identity <file> [--server-key <file>] [--allow-unauthenticated] --yes
                 replace the database and files with an archive's (stop the server first); the
                 archive's authentication code is checked with the server.key, and an archive
                 made before archives were authenticated needs --allow-unauthenticated
  restore --check <archive> --identity <file> --server-key <file> [--record]
                 [--allow-unauthenticated]
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
    ResetAdmin { yes: bool, promote: Option<String> },
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
        "reset-admin" => {
            let mut yes = false;
            let mut promote = None;
            let mut it = rest.iter();
            while let Some(arg) = it.next() {
                match arg.as_str() {
                    "--yes" => yes = true,
                    "--promote" => match it.next() {
                        Some(email) => promote = Some(email.clone()),
                        None => return Err("--promote needs an email".to_owned()),
                    },
                    _ => {
                        return Err("reset-admin takes only --yes and --promote <email>".to_owned());
                    }
                }
            }
            Ok(Command::ResetAdmin { yes, promote })
        }
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

/// The time, from the system clock.
struct SystemClock;

impl kemlock_app::ports::Clock for SystemClock {
    fn now(&self) -> time::OffsetDateTime {
        time::OffsetDateTime::now_utc()
    }
}

async fn reset_admin(config: &Config, yes: bool, promote: Option<String>) -> u8 {
    println!(
        "reset-admin removes the admin role from every account and the first-admin marker, so \
         the server prints a new setup code at its next start and a new first admin can be made. \
         Accounts, vaults and devices stay as they are."
    );
    if !yes {
        eprintln!(
            "kemlock-cli: refusing without --yes: this changes who can administer the server"
        );
        return 2;
    }
    let promote = match promote.as_deref().map(kemlock_domain::Email::parse) {
        Some(Ok(email)) => Some(email),
        Some(Err(_)) => {
            eprintln!("kemlock-cli: --promote needs an email address");
            return 2;
        }
        None => None,
    };
    let store = match kemlock_store_sql::SqlStore::connect(&config.database_url).await {
        Ok(store) => store,
        Err(e) => {
            eprintln!("kemlock-cli: can't open the database: {e}");
            return 1;
        }
    };
    let reset = kemlock_app::reset_admin::ResetAdmin {
        users: store.clone(),
        admins: store.clone(),
        events: store.clone(),
        settings: store.clone(),
        two_factor: store.clone(),
        clock: SystemClock,
    };
    let result = reset.execute(promote.as_ref()).await;
    let _ = store.close().await;
    match result {
        Ok(demoted) if promote.is_some() => {
            for email in &demoted {
                println!("no longer an admin: {email}");
            }
            println!("done. The promoted account is the admin; setup stays closed.");
            0
        }
        Ok(demoted) if demoted.is_empty() => {
            println!("no account was an admin; setup will open at the server's next start");
            0
        }
        Ok(demoted) => {
            for email in &demoted {
                println!("no longer an admin: {email}");
            }
            println!(
                "done. Restart the server: it prints a new setup code in its log. Sessions that \
                 are open keep their tokens until they expire, but no longer reach the admin \
                 console."
            );
            0
        }
        Err(e) => {
            eprintln!("kemlock-cli: reset-admin failed: {e}");
            1
        }
    }
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
        Command::ResetAdmin { yes, promote } => {
            ExitCode::from(reset_admin(&config, yes, promote).await)
        }
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
            Ok(Command::ResetAdmin {
                yes: false,
                promote: None
            })
        );
        assert_eq!(
            parse(&args(&["reset-admin", "--yes"])),
            Ok(Command::ResetAdmin {
                yes: true,
                promote: None
            })
        );
    }

    #[test]
    fn reset_admin_parses_promote() {
        assert_eq!(
            parse(&args(&[
                "reset-admin",
                "--promote",
                "a@example.org",
                "--yes"
            ])),
            Ok(Command::ResetAdmin {
                yes: true,
                promote: Some("a@example.org".to_owned())
            })
        );
        assert!(parse(&args(&["reset-admin", "--promote"])).is_err());
        assert!(parse(&args(&["reset-admin", "--now"])).is_err());
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
}
