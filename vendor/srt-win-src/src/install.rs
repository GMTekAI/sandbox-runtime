//! Install-time state in the `sandbox_user` table of
//! `%LOCALAPPDATA%\sandbox-runtime\state.db`: the sandbox-user
//! **credential** (DPAPI ciphertext) and the **setup marker**.
//!
//! Written by the elevated `srt-win install` step (after
//! [`crate::user::provision`]) and read by the non-elevated broker
//! at `srt-win exec` / `srt-win user read-cred` time.
//!
//! No separate JSON files: [`state_db::open_db`] already creates
//! and DACL-stamps the directory (broker-only `PROTECTED` allow set
//! plus the explicit [`user::SANDBOX_GROUP`] DENY), so `state.db`
//! inherits the same gate the credential needs. The DPAPI blob is
//! stored directly in a BLOB column — no base64 layer.

use anyhow::{anyhow, Context, Result};

use crate::state_db::SetupInfo;
use crate::{dpapi, state_db, user};

/// Bumped on schema-incompatible changes to the `sandbox_user`
/// row. The broker compares this to the on-disk marker and
/// refuses with a "re-run `srt-win install`" message on mismatch.
pub const SETUP_VERSION: u32 = 1;

/// DPAPI-encrypt `u.password` and write the credential + setup
/// marker to the `sandbox_user` table. [`state_db::open_db`] creates and
/// stamps the directory (broker-only `PROTECTED` allow set plus
/// the explicit [`user::SANDBOX_GROUP`] DENY) — the file DACL is
/// the **only** gate on the credential, since machine-scope DPAPI
/// lets any local account decrypt a readable blob.
///
/// `broker_group_sid` is the discriminator group SID — the
/// directory stamp keys on it (not `current_user_sid()`) so the
/// non-elevated broker can read what an over-the-shoulder-elevated
/// install wrote.
pub fn write_setup(
    u: &user::ProvisionedUser,
    broker_group_sid: &str,
) -> Result<()> {
    let conn = state_db::open_db(broker_group_sid)
        .context("open state DB for setup write")?;
    state_db::write_setup_info(&conn, &SetupInfo {
        cred: dpapi::protect_machine(u.password.as_bytes())?,
        marker_version: SETUP_VERSION,
        sandbox_user: u.username.clone(),
        sandbox_user_sid: u.sid.clone(),
        sandbox_group_sid: u.group_sid.clone(),
        created_at_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    })
}

/// Read the install-time setup record (if any) without taking the
/// init mutex. `Ok(None)` when no install has run (state DB
/// absent or no marker row).
pub fn read_setup() -> Result<Option<SetupInfo>> {
    match state_db::open_db_ro()? {
        Some(c) => state_db::read_setup_info(&c),
        None => Ok(None),
    }
}

/// Decrypt and return the sandbox user's `(username, password)`.
/// Fails if the caller cannot read `state.db` — by design, the
/// sandbox user is DENY'd on the directory and so cannot call this
/// to learn its own password.
pub fn read_cred() -> Result<(String, String)> {
    let info = read_setup()?.ok_or_else(|| {
        anyhow!(
            "no sandbox-user credential in state DB — run \
             `srt-win install`"
        )
    })?;
    if info.marker_version != SETUP_VERSION {
        return Err(anyhow!(
            "setup marker version mismatch (have {}, expected {}); \
             re-run `srt-win install`",
            info.marker_version, SETUP_VERSION,
        ));
    }
    let pw = String::from_utf8(dpapi::unprotect(&info.cred)?)
        .context("password is not UTF-8")?;
    Ok((info.sandbox_user, pw))
}

/// Clear the credential and marker rows. Idempotent — no-op when
/// `state.db` is absent (no install ever ran). Unlike
/// [`write_setup`] this doesn't re-stamp the directory: uninstall
/// deletes rows, it doesn't need to assert the DACL.
pub fn clear_setup() -> Result<()> {
    let path = state_db::state_dir()?.join("state.db");
    if !path.try_exists().unwrap_or(true) {
        return Ok(());
    }
    let conn = state_db::open_db_at(&path)
        .context("open state DB for setup clear")?;
    state_db::clear_setup_info(&conn)
}
