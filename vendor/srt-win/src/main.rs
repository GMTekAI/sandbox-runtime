//! `srt-win` — CLI for the sandbox-runtime Windows network fence.
//!
//! Subcommands:
//!   group  create | status | delete    — manage the discriminator local group
//!   wfp    install | status | uninstall — manage the persistent WFP filters
//!
//! `status` subcommands write one line of JSON to stdout and exit 0.
//! Mutating subcommands require elevation and write human-readable
//! progress to stderr.

use clap::{Args, Parser, Subcommand};

/// Default group name. Lives here (not in the `#[cfg(windows)]`
/// library crate) so the clap-derive CLI structs compile on
/// non-Windows hosts where the library is empty.
const DEFAULT_GROUP_NAME: &str = "sandbox-runtime-net";

#[derive(Parser)]
#[command(name = "srt-win", version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Manage the local discriminator group.
    Group {
        #[command(subcommand)]
        sub: GroupCmd,
    },
    /// Manage the persistent WFP filters.
    Wfp {
        #[command(subcommand)]
        sub: WfpCmd,
    },
}

/// Group resolution: either by name (looked up via
/// `LookupAccountNameW`) or directly by SID. If both are given the
/// SID wins; `group create`/`delete` always need a name.
#[derive(Args, Clone)]
struct GroupRef {
    /// Group name (local or `DOMAIN\name`). Default
    /// `sandbox-runtime-net`.
    #[arg(long, default_value = DEFAULT_GROUP_NAME)]
    name: String,
    /// Group SID (`S-1-…`). Overrides `--name` for SID resolution.
    /// Use when the group is provisioned by external tooling and name
    /// lookup may be unreliable.
    #[arg(long)]
    group_sid: Option<String>,
}

#[derive(Subcommand)]
enum GroupCmd {
    /// Create the local group and add the current (or `--user-sid`)
    /// user to it. Idempotent. Requires elevation.
    Create {
        #[command(flatten)]
        group: GroupRef,
        /// User SID to add (default: current user).
        #[arg(long)]
        user_sid: Option<String>,
    },
    /// Print group state as JSON: `{state, sid?, warning?}`.
    Status {
        #[command(flatten)]
        group: GroupRef,
    },
    /// Delete the local group. Idempotent. Requires elevation.
    Delete {
        #[command(flatten)]
        group: GroupRef,
    },
}

#[derive(Subcommand)]
enum WfpCmd {
    /// Install (or refresh) the machine-wide persistent WFP filters
    /// keyed on the group SID. Idempotent. Requires elevation.
    Install {
        #[command(flatten)]
        group: GroupRef,
        /// Sublayer GUID. Default is the compile-time constant; pass
        /// when integrating with externally-managed WFP state.
        #[arg(long)]
        sublayer_guid: Option<String>,
    },
    /// Print WFP fence state as JSON: `{state, filters}`. Filters
    /// are identified by their `providerData` tag, so only
    /// `--sublayer-guid` is relevant.
    Status {
        #[arg(long)]
        sublayer_guid: Option<String>,
    },
    /// Remove every srt-win-tagged WFP filter under the sublayer.
    /// Requires elevation.
    Uninstall {
        #[arg(long)]
        sublayer_guid: Option<String>,
    },
}

#[cfg(windows)]
fn main() {
    if let Err(e) = run() {
        eprintln!("srt-win: error: {e:#}");
        std::process::exit(1);
    }
}

#[cfg(windows)]
fn run() -> anyhow::Result<()> {
    use anyhow::{anyhow, Context};
    use serde_json::json;
    use srt_win::{sid, wfp};

    let cli = Cli::parse();

    // Validate a caller-supplied SID string up front so a typo
    // surfaces as "invalid --<flag>" rather than an SDDL parse error
    // three calls deep.
    let validate_sid = |flag: &str, s: &str| -> anyhow::Result<()> {
        sid::LocalPsid::from_string(s)
            .map(|_| ())
            .with_context(|| format!("invalid --{flag} '{s}'"))
    };
    let resolve_group_sid = |g: &GroupRef| -> anyhow::Result<String> {
        if let Some(s) = &g.group_sid {
            validate_sid("group-sid", s)?;
            return Ok(s.clone());
        }
        sid::lookup_account_sid(&g.name)
            .with_context(|| format!("resolve group '{}'", g.name))
    };
    let resolve_sublayer = |s: &Option<String>| -> anyhow::Result<windows::core::GUID> {
        match s {
            Some(g) => wfp::parse_guid(g),
            None => Ok(wfp::DEFAULT_SUBLAYER_GUID),
        }
    };

    match cli.cmd {
        // ─── group ─────────────────────────────────────────────────
        Cmd::Group { sub: GroupCmd::Create { group, user_sid } } => {
            require_elevated()?;
            if group.group_sid.is_some() {
                return Err(anyhow!(
                    "`group create` needs --name; --group-sid is for \
                     referencing an existing group"
                ));
            }
            let user = match &user_sid {
                Some(s) => {
                    validate_sid("user-sid", s)?;
                    s.clone()
                }
                None => sid::current_user_sid()
                    .context("resolve current user")?,
            };
            wfp::ensure_group(&group.name, &user)?;
            let gsid = sid::lookup_account_sid(&group.name)?;
            eprintln!(
                "srt-win: group '{}' present (sid={gsid}); user {user} added",
                group.name
            );
            eprintln!(
                "srt-win: NOTE — the group SID enters TokenGroups at logon. \
                 Log out and back in before running `wfp install`."
            );
        }
        Cmd::Group { sub: GroupCmd::Status { group } } => {
            // Resolve SID first; if that fails the group is absent.
            let gsid = match &group.group_sid {
                Some(s) => {
                    // --group-sid bypasses the name lookup, so do a
                    // reverse lookup to distinguish "exists but not on
                    // this token yet" from "no such account at all".
                    // Tolerate transient lookup failure (domain
                    // unreachable) by falling through to the token
                    // check.
                    match sid::sid_account_exists(s) {
                        Ok(sid::SidExistence::Unmapped) => {
                            println!("{}", json!({"state": "absent"}));
                            return Ok(());
                        }
                        Ok(_) => {}
                        Err(e) => {
                            // Malformed SID string.
                            println!(
                                "{}",
                                json!({"state": "absent", "error": e.to_string()})
                            );
                            return Ok(());
                        }
                    }
                    s.clone()
                }
                None => match sid::lookup_account_sid(&group.name) {
                    Ok(s) => s,
                    Err(_) => {
                        println!("{}", json!({"state": "absent"}));
                        return Ok(());
                    }
                },
            };
            let out = match sid::group_state_for_self(&gsid)? {
                sid::GroupState::Enabled => {
                    json!({"state": "ready", "sid": gsid})
                }
                sid::GroupState::Absent => {
                    json!({"state": "created-not-on-token", "sid": gsid})
                }
                sid::GroupState::DenyOnly => json!({
                    "state": "created-not-on-token",
                    "sid": gsid,
                    "warning": "group is deny-only in this token — running \
                                inside a sandbox child?"
                }),
                sid::GroupState::Present => json!({
                    "state": "created-not-on-token",
                    "sid": gsid,
                    "warning": "group present but neither enabled nor \
                                deny-only (unexpected)"
                }),
            };
            println!("{out}");
        }
        Cmd::Group { sub: GroupCmd::Delete { group } } => {
            require_elevated()?;
            if group.group_sid.is_some() {
                return Err(anyhow!(
                    "`group delete` needs --name; cannot delete by SID"
                ));
            }
            wfp::delete_group(&group.name)?;
            eprintln!("srt-win: group '{}' deleted (if it existed)", group.name);
        }

        // ─── wfp ───────────────────────────────────────────────────
        Cmd::Wfp {
            sub: WfpCmd::Install { group, sublayer_guid },
        } => {
            require_elevated()?;
            let gsid = resolve_group_sid(&group)?;
            let sl = resolve_sublayer(&sublayer_guid)?;
            wfp::install_filters(&sl, &gsid)?;
            eprintln!(
                "srt-win: WFP filters installed (group_sid={gsid}, \
                 sublayer={sl:?})"
            );
        }
        Cmd::Wfp { sub: WfpCmd::Status { sublayer_guid } } => {
            let sl = resolve_sublayer(&sublayer_guid)?;
            let st = wfp::filter_status(&sl)?;
            println!("{}", serde_json::to_string(&st)?);
        }
        Cmd::Wfp { sub: WfpCmd::Uninstall { sublayer_guid } } => {
            require_elevated()?;
            let sl = resolve_sublayer(&sublayer_guid)?;
            let n = wfp::uninstall_filters(&sl)?;
            eprintln!("srt-win: removed {n} WFP filter(s)");
        }
    }
    Ok(())
}

#[cfg(windows)]
fn require_elevated() -> anyhow::Result<()> {
    use anyhow::{anyhow, Context};
    use std::ffi::c_void;
    use std::mem::size_of;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{
        GetCurrentProcess, OpenProcessToken,
    };
    unsafe {
        let mut tok = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut tok)
            .context("OpenProcessToken")?;
        let mut elev = TOKEN_ELEVATION::default();
        let mut ret = 0u32;
        let r = GetTokenInformation(
            tok,
            TokenElevation,
            Some(&mut elev as *mut _ as *mut c_void),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret,
        );
        let _ = CloseHandle(tok);
        r.context("GetTokenInformation(TokenElevation)")?;
        if elev.TokenIsElevated == 0 {
            return Err(anyhow!(
                "this command requires elevation — run from an \
                 administrator prompt"
            ));
        }
    }
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    // The clap-derived structs above keep `clap` referenced; just
    // print the platform error.
    let _ = <Cli as clap::CommandFactory>::command();
    eprintln!("srt-win: Windows only");
    std::process::exit(2);
}
