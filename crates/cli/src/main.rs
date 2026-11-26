//! `urk` — the urkey command-line interface and SSH agent launcher (R-SSH-4, ADR 0015).

mod api;
mod error;
mod output;
mod paths;
mod profile;
mod secrets;
mod store;

use sync_core::vault_core;

use std::process::ExitCode;

use clap::{Parser, Subcommand};
use sync_core::vault_core::account;
use sync_core::vault_core::b64::{self, B64};
use sync_core::vault_core::crypto_core::encoding;
use sync_core::vault_core::crypto_core::ids::{AccountId, DeviceId, KdfSalt};
use sync_core::vault_core::crypto_core::kdf::KdfParams;
use sync_core::vault_core::generator::{self, PasswordOptions};
use sync_core::vault_core::item::{Content, Item, LoginFields, LoginUrl};
use sync_core::vault_core::ssh::{self as vssh, AgentKey};
use sync_core::vault_core::totp::Totp;
use sync_core::vault_core::wire::{
    AccountResponse, LoginRequest, PreloginRequest, PreloginResponse, RevokeDevicePayload,
    SessionResponse,
};

use crate::error::{CliError, Result};
use crate::output::say;
use crate::profile::{Config, Profile, now_ms, read_password, short_id};

#[derive(Parser)]
#[command(
    name = "urk",
    version,
    about = "urkey password manager CLI and SSH agent"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Configure the server for this device.
    Init {
        /// API base URL, e.g. https://api.example.com
        #[arg(long)]
        server: String,
        /// Name shown in your device list.
        #[arg(long, default_value = "urk on this Mac")]
        name: String,
    },
    /// Create or manage the account.
    #[command(subcommand)]
    Account(AccountCmd),
    /// Sign in on this device with email, Secret Key and master password.
    Login {
        #[arg(long)]
        email: String,
        /// Read the password and then the Secret Key from stdin (one per line).
        #[arg(long)]
        password_stdin: bool,
    },
    /// Load SSH keys from the vault into the agent until the lifetime ends (like `ssh-add -t`).
    Unlock {
        /// Auto-lock after this many minutes.
        #[arg(long, default_value_t = 10)]
        minutes: u32,
        #[arg(long)]
        password_stdin: bool,
    },
    /// Remove all keys from the agent now.
    Lock,
    /// Show account, device, sync and agent state.
    Status,
    /// Synchronize with the server.
    Sync {
        #[arg(long)]
        password_stdin: bool,
    },
    /// Vault items.
    #[command(subcommand)]
    Item(ItemCmd),
    /// SSH keys stored in the vault.
    #[command(subcommand)]
    Ssh(SshCmd),
    /// Devices on the account.
    #[command(subcommand)]
    Device(DeviceCmd),
    /// The SSH agent.
    #[command(subcommand)]
    Agent(AgentCmd),
    /// Write an encrypted export of the vault (ADR 0017). It opens with the master password and
    /// Secret Key that are current now.
    Export {
        /// Output file (created with mode 0600; must not exist).
        #[arg(long)]
        out: std::path::PathBuf,
        #[arg(long)]
        password_stdin: bool,
    },
    /// Add the items of an encrypted export to this vault as new items (ADR 0017).
    Restore {
        /// Export file from `urk export`.
        file: std::path::PathBuf,
        /// Read, one per line: this vault's master password, then the export's master password
        /// and Secret Key.
        #[arg(long)]
        password_stdin: bool,
    },
    /// Sign out and remove all urkey data from this device.
    Forget {
        /// Required: confirms deleting local data.
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum AccountCmd {
    /// Create a new account. Prints your Emergency Kit.
    Create {
        #[arg(long)]
        email: String,
        #[arg(long)]
        password_stdin: bool,
    },
}

#[derive(Subcommand)]
enum ItemCmd {
    /// List items (optionally matching a search).
    List {
        query: Option<String>,
        #[arg(long)]
        password_stdin: bool,
    },
    /// Show one item. Concealed values stay masked unless --reveal or --field is used.
    Get {
        /// Short id or search text that matches exactly one item.
        query: String,
        /// Print only this field: username, password, totp, notes, url.
        #[arg(long)]
        field: Option<String>,
        #[arg(long)]
        reveal: bool,
        #[arg(long)]
        password_stdin: bool,
    },
    /// Add a login with a generated password.
    AddLogin {
        #[arg(long)]
        title: String,
        #[arg(long, default_value = "")]
        username: String,
        #[arg(long)]
        url: Option<String>,
        #[arg(long)]
        password_stdin: bool,
    },
}

#[derive(Subcommand)]
enum SshCmd {
    /// List SSH keys.
    List {
        #[arg(long)]
        password_stdin: bool,
    },
    /// Import an OpenSSH private key file.
    Import {
        file: std::path::PathBuf,
        #[arg(long)]
        title: Option<String>,
        #[arg(long)]
        password_stdin: bool,
    },
}

#[derive(Subcommand)]
enum DeviceCmd {
    /// List devices.
    List,
    /// Remove a device (needs your master password).
    Revoke {
        /// Device id prefix as shown by `urk device list`.
        id: String,
        #[arg(long)]
        password_stdin: bool,
    },
}

#[derive(Subcommand)]
enum AgentCmd {
    /// Run the agent in the foreground (launchd runs this).
    Run,
    /// Install a launchd agent (macOS) and show the SSH configuration to use.
    Install,
    /// Show the agent socket and loaded keys.
    Status,
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            output::err(&format!("urk: {e}"));
            ExitCode::from(e.code)
        }
    }
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Init { server, name } => init(&server, &name),
        Command::Account(AccountCmd::Create {
            email,
            password_stdin,
        }) => create(&email, password_stdin),
        Command::Login {
            email,
            password_stdin,
        } => login(&email, password_stdin),
        Command::Unlock {
            minutes,
            password_stdin,
        } => unlock(minutes, password_stdin),
        Command::Lock => lock(),
        Command::Status => status(),
        Command::Sync { password_stdin } => sync(password_stdin),
        Command::Item(ItemCmd::List {
            query,
            password_stdin,
        }) => item_list(query.as_deref(), password_stdin),
        Command::Item(ItemCmd::Get {
            query,
            field,
            reveal,
            password_stdin,
        }) => item_get(&query, field.as_deref(), reveal, password_stdin),
        Command::Item(ItemCmd::AddLogin {
            title,
            username,
            url,
            password_stdin,
        }) => add_login(&title, &username, url, password_stdin),
        Command::Ssh(SshCmd::List { password_stdin }) => ssh_list(password_stdin),
        Command::Ssh(SshCmd::Import {
            file,
            title,
            password_stdin,
        }) => ssh_import(&file, title, password_stdin),
        Command::Device(DeviceCmd::List) => device_list(),
        Command::Device(DeviceCmd::Revoke { id, password_stdin }) => {
            device_revoke(&id, password_stdin)
        }
        Command::Agent(AgentCmd::Run) => agent_run(),
        Command::Agent(AgentCmd::Install) => agent_install(),
        Command::Agent(AgentCmd::Status) => agent_status(),
        Command::Export {
            out,
            password_stdin,
        } => export(&out, password_stdin),
        Command::Restore {
            file,
            password_stdin,
        } => restore(&file, password_stdin),
        Command::Forget { yes } => forget(yes),
    }
}

fn init(server: &str, name: &str) -> Result<()> {
    let dir = paths::data_dir()?;
    let store = store::Store::open(&dir)?;
    let server = server.trim_end_matches('/');
    if !(server.starts_with("https://")
        || server.starts_with("http://localhost")
        || server.starts_with("http://127.0.0.1"))
    {
        return Err(CliError::new(
            "the server must use https:// (http is only allowed for localhost)",
        ));
    }
    store.put(
        "config",
        &Config {
            server: server.to_owned(),
            device_name: name.to_owned(),
        },
    )?;
    say(&format!(
        "Configured server {server}. Next: `urk account create --email …` or `urk login --email …`."
    ));
    Ok(())
}

fn create(email: &str, password_stdin: bool) -> Result<()> {
    let mut p = Profile::open()?;
    let password = read_password(password_stdin, "Choose a master password: ")?;
    if !password_stdin {
        let again = read_password(false, "Repeat it: ")?;
        if *again != *password {
            return Err(CliError::new("the passwords do not match"));
        }
    }
    if password.chars().count() < 10 {
        return Err(CliError::new(
            "use at least 10 characters for your master password",
        ));
    }
    let device_key = p.device_key()?;
    let info = p.device_info(&device_key)?;
    let new = account::create_account(email, &password, &info, KdfParams::DEFAULT)?;
    let signed = account::sign_create(&new, &device_key)?;
    let session: SessionResponse = p.api.post("/v1/accounts", &signed)?;
    p.save_session(&session)?;
    p.secrets
        .set(profile::SECRET_KEY, new.secret_key.expose_secret())?;
    p.refresh_account()?;
    let secret = encoding::format_account_secret_key(&new.secret_key);
    let recovery = encoding::format_recovery_key(&new.recovery_key);
    say("\n=== urkey Emergency Kit ===");
    say(&format!(
        "Sign-in address: {}\nEmail:           {}",
        p.config.server, new.payload.email
    ));
    say(&format!("Secret Key:      {}", secret.as_str()));
    say(&format!("Recovery Key:    {}", recovery.as_str()));
    say("\nPrint this or store it offline. Anyone with this kit can open your vault.");
    say("You need the Secret Key to sign in on a new device, and the Recovery Key if you forget");
    say(
        "your master password. urkey cannot recover them for you. Don't keep them in email or notes.",
    );
    Ok(())
}

fn login(email: &str, password_stdin: bool) -> Result<()> {
    let mut p = Profile::open()?;
    let password = read_password(password_stdin, "Master password: ")?;
    let secret_text = read_password(password_stdin, "Secret Key (UK1-…): ")?;
    let secret_key = encoding::parse_account_secret_key(&secret_text)?;
    let pre: PreloginResponse = p.api.post(
        "/v1/auth/prelogin",
        &PreloginRequest {
            email: email.to_owned(),
        },
    )?;
    let account_id = AccountId::from_slice(&pre.account_id.0)?;
    let salt = KdfSalt::from_slice(&pre.kdf_salt.0)?;
    let params = KdfParams::decode(&pre.kdf_params.0)?;
    let auth = account::derive_auth(&account_id, &salt, &params, &password, &secret_key)?;
    let device_key = p.device_key()?;
    let info = p.device_info(&device_key)?;
    let (cid, nonce) = p.challenge(&account_id, "login")?;
    let req: LoginRequest = account::login_request(
        &account_id,
        &cid,
        &nonce,
        &auth,
        &device_key,
        &info,
        p.api.origin(),
    )?;
    let session: SessionResponse = p.api.post("/v1/auth/login", &req)?;
    p.save_session(&session)?;
    p.secrets
        .set(profile::SECRET_KEY, secret_key.expose_secret())?;
    p.refresh_account()?;
    p.unlock(&password)?; // proves the envelope opens before we report success
    say("Signed in. Your other devices will see a notice about this device.");
    Ok(())
}

fn unlock_and_sync(
    p: &mut Profile,
    password_stdin: bool,
) -> Result<(account::Unlocked, zeroize::Zeroizing<String>)> {
    let password = read_password(password_stdin, "Master password: ")?;
    let mut unlocked = p.unlock(&password)?;
    match p.sync(&mut unlocked, &password) {
        Ok(s) if s.rollback => output::err(
            "Warning: the server returned older data than this device has seen. Syncing is paused.",
        ),
        Ok(s) if s.quarantined > 0 => {
            output::err("Warning: some records failed integrity checks and were not applied.")
        }
        Ok(_) => {}
        Err(e) => output::err(&format!("Offline: {e} Showing this device's copy.")),
    }
    Ok((unlocked, password))
}

fn export(out: &std::path::Path, password_stdin: bool) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut p = Profile::open()?;
    let (unlocked, _) = unlock_and_sync(&mut p, password_stdin)?;
    let material = account::material_from_wire(&p.account()?)?;
    if material.vmk_id != unlocked.vault.vmk_id {
        return Err(CliError::new(
            "the vault key is changing; sync and try again",
        ));
    }
    let records = p.records()?;
    let file = vault_core::export::build(&material, &records, now_ms())?;
    let json = serde_json::to_vec_pretty(&file)
        .map_err(|_| CliError::new("could not encode the export"))?;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(out)
        .map_err(|_| CliError::new("could not create the export file (does it already exist?)"))?;
    f.write_all(&json)?;
    f.sync_all()?;
    say(&format!(
        "Exported {} items. The file is encrypted: it opens with your current master password and \
         Secret Key, so keep it with your Emergency Kit.",
        file.items.len()
    ));
    Ok(())
}

fn restore(path: &std::path::Path, password_stdin: bool) -> Result<()> {
    let bytes = std::fs::read(path).map_err(|_| CliError::new("could not read the export file"))?;
    let file = vault_core::export::parse(&bytes)?;
    let mut p = Profile::open()?;
    let (mut unlocked, password) = unlock_and_sync(&mut p, password_stdin)?;
    let export_password = read_password(password_stdin, "Master password of the export: ")?;
    let secret_text = read_password(password_stdin, "Secret Key of the export (UK1-…): ")?;
    let secret_key = encoding::parse_account_secret_key(&secret_text)?;
    let items = vault_core::export::open(&file, &export_password, &secret_key)?;
    for item in &items {
        p.write(&unlocked.vault, sync_core::Write::Create(item))?;
    }
    say(&format!("Restored {} items as new items.", items.len()));
    match p.sync(&mut unlocked, &password) {
        Ok(s) if s.pending == 0 => say("Synced."),
        Ok(_) => say("Some changes are not synced yet; run `urk sync` later."),
        Err(e) => output::err(&format!("Offline: {e} The items will sync later.")),
    }
    Ok(())
}

fn agent_socket(p: &Profile) -> std::path::PathBuf {
    ssh_agent::server::default_socket(&p.dir)
}

fn unlock(minutes: u32, password_stdin: bool) -> Result<()> {
    let mut p = Profile::open()?;
    let (unlocked, _) = unlock_and_sync(&mut p, password_stdin)?;
    let sock = agent_socket(&p);
    let mut loaded = 0;
    for v in p.items(&unlocked.vault)? {
        if let Content::SshKey(k) = &v.item.content {
            if !k.agent.enabled {
                continue;
            }
            let Ok(key) = AgentKey::from_fields(k) else {
                output::err(&format!(
                    "Skipping \"{}\": key can't be used by the agent.",
                    v.item.title
                ));
                continue;
            };
            let req = ssh_agent::protocol::add_identity_request(
                key.private_key(),
                minutes.saturating_mul(60),
            )
            .map_err(|_| CliError::new("could not encode the key"))?;
            let resp = ssh_agent::server::request(&sock, &req).map_err(|_| CliError::new("The agent isn't running. Start it with `urk agent run` or `urk agent install`."))?;
            if resp != [ssh_agent::protocol::msg::SUCCESS] {
                return Err(CliError::new("the agent refused a key"));
            }
            loaded += 1;
        }
    }
    say(&format!(
        "Unlocked: {loaded} SSH key(s) loaded for {minutes} minutes."
    ));
    Ok(())
}

fn lock() -> Result<()> {
    let p = Profile::open()?;
    let resp = ssh_agent::server::request(
        &agent_socket(&p),
        &[ssh_agent::protocol::msg::REMOVE_ALL_IDENTITIES],
    )
    .map_err(|_| CliError::new("The agent isn't running."))?;
    if resp != [ssh_agent::protocol::msg::SUCCESS] {
        return Err(CliError::new("the agent refused to lock"));
    }
    say("Locked: all SSH keys removed from the agent.");
    Ok(())
}

fn agent_key_count(p: &Profile) -> Option<u32> {
    let resp = ssh_agent::server::request(
        &agent_socket(p),
        &[ssh_agent::protocol::msg::REQUEST_IDENTITIES],
    )
    .ok()?;
    (resp.first() == Some(&ssh_agent::protocol::msg::IDENTITIES_ANSWER))
        .then(|| u32::from_be_bytes([resp[1], resp[2], resp[3], resp[4]]))
}

fn status() -> Result<()> {
    let p = Profile::open()?;
    say(&format!("Server:     {}", p.config.server));
    match p.account() {
        Ok(a) => say(&format!("Account:    {}", a.email)),
        Err(_) => say("Account:    (none on this device)"),
    }
    say(&format!("Device:     {}", p.config.device_name));
    let s = p.sync_state()?;
    say(&format!(
        "Sync:       {} unsynced change(s), {} conflict(s){}",
        s.outbox.len(),
        s.conflicts.len(),
        if s.rollback_warning {
            ", PAUSED (server returned older data)"
        } else {
            ""
        }
    ));
    let unseen = s.events.iter().filter(|e| !e.acknowledged).count();
    if unseen > 0 {
        say(&format!(
            "Notices:    {unseen} security event(s), see the web app's Activity page"
        ));
    }
    match agent_key_count(&p) {
        Some(n) => say(&format!("Agent:      running, {n} key(s) loaded")),
        None => say("Agent:      not running"),
    }
    Ok(())
}

fn sync(password_stdin: bool) -> Result<()> {
    let mut p = Profile::open()?;
    let password = read_password(password_stdin, "Master password: ")?;
    let mut unlocked = p.unlock(&password)?;
    let s = p.sync(&mut unlocked, &password)?;
    say(&format!(
        "Synced: {} received, {} sent, {} pending, {} conflict(s).",
        s.pulled, s.pushed, s.pending, s.open_conflicts
    ));
    if s.rotated {
        say("Your vault key was changed on another device; this device has been updated.");
    }
    if s.rollback {
        return Err(CliError::new(
            "the server returned older data than this device has seen; syncing is paused",
        ));
    }
    Ok(())
}

fn kind_label(item: &Item) -> &str {
    match &item.content {
        Content::Login(_) => "login",
        Content::Note(_) => "note",
        Content::SshKey(_) => "ssh-key",
        Content::Unknown { kind, .. } => kind,
    }
}

fn item_list(query: Option<&str>, password_stdin: bool) -> Result<()> {
    let mut p = Profile::open()?;
    let (unlocked, _) = unlock_and_sync(&mut p, password_stdin)?;
    for v in p.items(&unlocked.vault)? {
        if query.is_some_and(|q| !sync_core::vault_core::search::matches(&v.item, q)) {
            continue;
        }
        let sub = match &v.item.content {
            Content::Login(l) => l.username.clone(),
            Content::SshKey(k) => k.fingerprint.clone(),
            _ => String::new(),
        };
        let flags = format!(
            "{}{}",
            if v.pending { " [unsynced]" } else { "" },
            if v.conflict { " [conflict]" } else { "" }
        );
        say(&format!(
            "{}  {:<8} {}  {}{}",
            short_id(&v.id),
            kind_label(&v.item),
            v.item.title,
            sub,
            flags
        ));
    }
    Ok(())
}

fn find<'a>(items: &'a [profile::ViewItem], query: &str) -> Result<&'a profile::ViewItem> {
    let by_id: Vec<_> = items
        .iter()
        .filter(|v| short_id(&v.id).starts_with(query))
        .collect();
    let matches = if by_id.len() == 1 {
        by_id
    } else {
        items
            .iter()
            .filter(|v| sync_core::vault_core::search::matches(&v.item, query))
            .collect()
    };
    match matches.len() {
        1 => Ok(matches[0]),
        0 => Err(CliError::new("no item matches")),
        _ => Err(CliError::new(
            "more than one item matches; use the short id from `urk item list`",
        )),
    }
}

fn item_get(query: &str, field: Option<&str>, reveal: bool, password_stdin: bool) -> Result<()> {
    let mut p = Profile::open()?;
    let (unlocked, _) = unlock_and_sync(&mut p, password_stdin)?;
    let items = p.items(&unlocked.vault)?;
    let v = find(&items, query)?;
    let mask = |s: &str| {
        if reveal || s.is_empty() {
            s.to_owned()
        } else {
            "••••••••".to_owned()
        }
    };
    let now = u64::try_from(now_ms() / 1000).unwrap_or(0);
    if let Some(f) = field {
        let value = match (&v.item.content, f) {
            (Content::Login(l), "username") => l.username.clone(),
            (Content::Login(l), "password") => l.password.clone(),
            (Content::Login(l), "url") => l.urls.first().map(|u| u.url.clone()).unwrap_or_default(),
            (Content::Login(l), "totp") => match &l.totp {
                Some(t) => Totp::from_config(t)?.code_at(now).code,
                None => return Err(CliError::new("this login has no one-time password")),
            },
            (_, "notes") => v.item.notes.clone(),
            (Content::SshKey(k), "public_key") => k.public_key.clone(),
            _ => return Err(CliError::new("unknown field for this item")),
        };
        say(&value);
        return Ok(());
    }
    say(&format!("{} ({})", v.item.title, kind_label(&v.item)));
    match &v.item.content {
        Content::Login(l) => {
            say(&format!("  username   {}", l.username));
            say(&format!("  password   {}", mask(&l.password)));
            for u in &l.urls {
                say(&format!("  website    {}", u.url));
            }
            if let Some(t) = &l.totp {
                let c = Totp::from_config(t)?.code_at(now);
                say(&format!(
                    "  one-time   {} ({}s left)",
                    c.code, c.seconds_remaining
                ));
            }
        }
        Content::SshKey(k) => {
            say(&format!(
                "  type       {}\n  fingerprint {}\n  public key {}",
                k.key_type, k.fingerprint, k.public_key
            ));
            say(&format!(
                "  agent      {}",
                if k.agent.enabled {
                    "enabled"
                } else {
                    "disabled"
                }
            ));
        }
        _ => {}
    }
    if !v.item.notes.is_empty() {
        say(&format!("  notes      {}", mask(&v.item.notes)));
    }
    Ok(())
}

fn add_login(title: &str, username: &str, url: Option<String>, password_stdin: bool) -> Result<()> {
    let mut p = Profile::open()?;
    let (mut unlocked, password) = unlock_and_sync(&mut p, password_stdin)?;
    let generated = generator::password(&PasswordOptions::default())?;
    let device = b64::encode(p.device_id()?.as_bytes());
    let now = now_ms().to_string();
    let item = Item::new(
        Content::Login(LoginFields {
            username: username.to_owned(),
            password: generated.value.to_string(),
            urls: url
                .map(|u| {
                    vec![LoginUrl {
                        url: u,
                        label: "website".into(),
                    }]
                })
                .unwrap_or_default(),
            ..Default::default()
        }),
        title,
        &now,
        &device,
    );
    let id = p.write(&unlocked.vault, sync_core::Write::Create(&item))?;
    let _ = p.sync(&mut unlocked, &password);
    say(&format!(
        "Added {} ({}). Password generated ({:.0} bits).",
        title,
        short_id(&id),
        generated.bits
    ));
    Ok(())
}

fn ssh_list(password_stdin: bool) -> Result<()> {
    let mut p = Profile::open()?;
    let (unlocked, _) = unlock_and_sync(&mut p, password_stdin)?;
    for v in p.items(&unlocked.vault)? {
        if let Content::SshKey(k) = &v.item.content {
            say(&format!(
                "{}  {:<11} {}  {}{}",
                short_id(&v.id),
                k.key_type,
                k.fingerprint,
                v.item.title,
                if k.agent.enabled { "" } else { " (agent off)" }
            ));
        }
    }
    Ok(())
}

fn ssh_import(file: &std::path::Path, title: Option<String>, password_stdin: bool) -> Result<()> {
    let mut p = Profile::open()?;
    let (mut unlocked, password) = unlock_and_sync(&mut p, password_stdin)?;
    let pem = zeroize::Zeroizing::new(
        std::fs::read_to_string(file).map_err(|_| CliError::new("can't read that key file"))?,
    );
    let fields = match vssh::import_openssh(&pem, None) {
        Ok(f) => f,
        Err(sync_core::vault_core::VaultError::Invalid("this key needs its passphrase")) => {
            let pass = read_password(false, "Key passphrase: ")?;
            vssh::import_openssh(&pem, Some(&pass))?
        }
        Err(e) => return Err(e.into()),
    };
    let title = title.unwrap_or_else(|| {
        if fields.comment.is_empty() {
            "SSH key".into()
        } else {
            fields.comment.clone()
        }
    });
    let device = b64::encode(p.device_id()?.as_bytes());
    let fingerprint = fields.fingerprint.clone();
    let note = if fields.key_type == "rsa" {
        " RSA keys are stored but not offered by the agent yet."
    } else {
        ""
    };
    let item = Item::new(
        Content::SshKey(fields),
        &title,
        &now_ms().to_string(),
        &device,
    );
    let id = p.write(&unlocked.vault, sync_core::Write::Create(&item))?;
    let _ = p.sync(&mut unlocked, &password);
    say(&format!(
        "Imported {title} ({}), {fingerprint}.{note}",
        short_id(&id)
    ));
    Ok(())
}

fn device_list() -> Result<()> {
    let mut p = Profile::open()?;
    let me = p.device_id()?;
    let r: AccountResponse = p.refresh_account()?;
    for d in r.devices {
        let id = b64::encode(&d.device_id.0);
        let this = if d.device_id.0 == me.as_bytes() {
            " (this device)"
        } else {
            ""
        };
        let revoked = if d.revoked_at.is_some() {
            " [removed]"
        } else {
            ""
        };
        say(&format!(
            "{}  {:<10} {}{}{}",
            &id[..8],
            d.platform,
            d.name,
            this,
            revoked
        ));
    }
    Ok(())
}

fn device_revoke(prefix: &str, password_stdin: bool) -> Result<()> {
    let mut p = Profile::open()?;
    let password = read_password(password_stdin, "Master password: ")?;
    let unlocked = p.unlock(&password)?;
    let r: AccountResponse = p.refresh_account()?;
    let matches: Vec<_> = r
        .devices
        .iter()
        .filter(|d| b64::encode(&d.device_id.0).starts_with(prefix) && d.revoked_at.is_none())
        .collect();
    let [target] = matches.as_slice() else {
        return Err(CliError::new("the id must match exactly one active device"));
    };
    let account_id = AccountId::from_slice(&r.account.account_id.0)?;
    let (cid, nonce) = p.challenge(&account_id, "stepup")?;
    let payload = RevokeDevicePayload {
        device_id: B64(DeviceId::from_slice(&target.device_id.0)?
            .as_bytes()
            .to_vec()),
    };
    let req = account::stepup_request(
        &account_id,
        &cid,
        &nonce,
        "revoke_device",
        &payload,
        &unlocked.auth,
        None,
    )?;
    let _: AccountResponse = p.api.post("/v1/devices/revoke", &req)?;
    say(&format!(
        "Removed \"{}\". Consider changing your vault key in the web app's Security settings.",
        target.name
    ));
    Ok(())
}

fn agent_run() -> Result<()> {
    let dir = paths::data_dir()?;
    let sock = ssh_agent::server::default_socket(&dir);
    let listener = ssh_agent::server::bind(&sock)?;
    output::err(&format!("urk agent listening on {}", sock.display()));
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    ssh_agent::server::serve(listener, std::sync::Arc::new(ssh_agent::Agent::new()), stop)?;
    Ok(())
}

fn agent_install() -> Result<()> {
    let dir = paths::data_dir()?;
    let sock = ssh_agent::server::default_socket(&dir);
    let exe = std::env::current_exe()?;
    if cfg!(target_os = "macos") {
        let home = std::env::var("HOME").map_err(|_| CliError::new("HOME is not set"))?;
        let plist_dir = std::path::Path::new(&home).join("Library/LaunchAgents");
        std::fs::create_dir_all(&plist_dir)?;
        let plist = plist_dir.join("dev.urkey.agent.plist");
        std::fs::write(
            &plist,
            output::launchd_plist(&exe.display().to_string(), &dir.display().to_string()),
        )?;
        say(&format!("Wrote {}.", plist.display()));
        say(&format!(
            "Start it now:\n  launchctl bootstrap gui/$(id -u) \"{}\"",
            plist.display()
        ));
    } else {
        say(&format!(
            "On this platform, run the agent with:\n  {} agent run",
            exe.display()
        ));
    }
    say(&format!(
        "\nThen point SSH at it in ~/.ssh/config:\n  Host *\n    IdentityAgent \"{}\"",
        sock.display()
    ));
    Ok(())
}

fn agent_status() -> Result<()> {
    let p = Profile::open()?;
    say(&format!("Socket: {}", agent_socket(&p).display()));
    match agent_key_count(&p) {
        Some(n) => say(&format!("Running, {n} key(s) loaded.")),
        None => say("Not running."),
    }
    Ok(())
}

fn forget(yes: bool) -> Result<()> {
    if !yes {
        return Err(CliError::new(
            "this deletes all urkey data on this device; run again with --yes",
        ));
    }
    let dir = paths::data_dir()?;
    if let Ok(mut p) = Profile::open() {
        let _: std::result::Result<serde_json::Value, _> =
            p.api.post("/v1/auth/logout", &serde_json::json!({}));
        let _ = p.secrets.delete(profile::SECRET_KEY);
        let _ = p.secrets.delete(profile::DEVICE_SEED);
        p.api.token = None;
    }
    for f in ["vault.db", "secrets.json", "secrets.tmp"] {
        let _ = std::fs::remove_file(dir.join(f));
    }
    say("Removed urkey data from this device.");
    Ok(())
}
