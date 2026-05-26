//! `srt-win` — CLI for the sandbox-runtime Windows network fence.
//!
//! Subcommands:
//!   group  create | status | delete    — manage the discriminator local group
//!   wfp    install | status | uninstall — manage the persistent WFP filters
//!   exec   -- <target> [args...]       — spawn under the deny-only-group
//!                                         token + job + hardening stack
//!
//! `status` subcommands write one line of JSON to stdout and exit 0.
//! Mutating subcommands require elevation and write human-readable
//! progress to stderr. `exec` propagates the child's exit code.

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
    /// Spawn a process under the deny-only-group sandbox.
    ///
    /// Builds a restricted token (group + Admins flipped deny-only,
    /// LUA, Medium IL, all privs stripped except SeChangeNotify),
    /// self-protects the broker, assigns the child to a
    /// kill-on-close job with full UI lockdown, places it on a
    /// non-interactive desktop, applies process-mitigation
    /// policies + an explicit handle whitelist, and waits for it
    /// to exit. Propagates the child's exit code.
    Exec {
        #[command(flatten)]
        group: GroupRef,
        /// JS-side HTTP proxy port. Sets `HTTP_PROXY` /
        /// `HTTPS_PROXY` (both cases) on the child.
        #[arg(long)]
        http_proxy: Option<u16>,
        /// JS-side SOCKS proxy port. Sets `ALL_PROXY=socks5h://…`
        /// (both cases) on the child.
        #[arg(long)]
        socks_proxy: Option<u16>,
        /// Skip the "is the group enabled in the broker's token"
        /// pre-flight. **Fail-open** — the WFP fence depends on
        /// that membership; with this set the child may run with
        /// weaker isolation if the install was incomplete.
        /// Surfaced as a flag (not an env var) so the bypass is
        /// intentional and not accidentally inherited. Use ONLY
        /// in ephemeral CI runners that create the group in-job
        /// and cannot logout/login mid-run.
        #[arg(long)]
        skip_group_check: bool,
        /// Target executable followed by its arguments. Use `--`
        /// to terminate srt-win's own option parsing.
        #[arg(
            trailing_var_arg = true,
            allow_hyphen_values = true,
            required = true,
            num_args = 1..,
        )]
        target: Vec<String>,
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
        /// Loopback port range the sandboxed child may reach
        /// (`LOW-HIGH`, inclusive; default 60080-60089). The host
        /// http/socks proxies bind inside this range on Windows.
        #[arg(long, value_name = "LOW-HIGH")]
        proxy_port_range: Option<String>,
    },
    /// Print WFP fence state as JSON: `{state, filters,
    /// port_range?}`. Filters are identified by their
    /// `providerData` tag, so only `--sublayer-guid` is relevant.
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
    // surfaces as "invalid --<flag>" rather than an SDDL parse
    // error three calls deep. Returns the CANONICAL `S-1-…` form
    // (round-tripped through ConvertSidToStringSidW) so SDDL
    // shorthands like `BA` or lower-case `s-1-…` collapse to a
    // single comparable representation; downstream
    // `eq_ignore_ascii_case("S-1-5-32-544")` dedup checks rely on
    // that.
    let canonicalize_sid =
        |flag: &str, s: &str| -> anyhow::Result<String> {
            let p = sid::LocalPsid::from_string(s)
                .with_context(|| format!("invalid --{flag} '{s}'"))?;
            sid::psid_to_string(p.as_psid())
                .with_context(|| format!("canonicalize --{flag} '{s}'"))
        };
    let resolve_group_sid = |g: &GroupRef| -> anyhow::Result<String> {
        if let Some(s) = &g.group_sid {
            return canonicalize_sid("group-sid", s);
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
                Some(s) => canonicalize_sid("user-sid", s)?,
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
            sub:
                WfpCmd::Install {
                    group,
                    sublayer_guid,
                    proxy_port_range,
                },
        } => {
            require_elevated()?;
            let gsid = resolve_group_sid(&group)?;
            let sl = resolve_sublayer(&sublayer_guid)?;
            let range = match &proxy_port_range {
                Some(s) => wfp::parse_port_range(s)
                    .with_context(|| format!("invalid --proxy-port-range '{s}'"))?,
                None => wfp::DEFAULT_PROXY_PORT_RANGE,
            };
            wfp::install_filters(&sl, &gsid, range)?;
            eprintln!(
                "srt-win: WFP filters installed (group_sid={gsid}, \
                 sublayer={sl:?}, proxy_port_range={}-{})",
                range.0, range.1,
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

        // ─── exec ──────────────────────────────────────────────────
        Cmd::Exec {
            group,
            http_proxy,
            socks_proxy,
            skip_group_check,
            target,
        } => {
            use srt_win::launch;
            let gsid = resolve_group_sid(&group)?;
            // `target` is `required, num_args=1..` so non-empty.
            let exe = std::path::PathBuf::from(&target[0]);
            let args = &target[1..];
            let spec = launch::ExecSpec {
                group_sid: &gsid,
                http_proxy,
                socks_proxy,
                skip_group_check,
                target_exe: &exe,
                target_args: args,
            };
            let code = launch::run(&spec)?;
            // Propagate the child's exit code verbatim.
            std::process::exit(code as i32);
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
