//! Install-time artifacts under `%LOCALAPPDATA%\sandbox-runtime\`:
//! the sandbox-user **credential file**, the **setup marker**, and
//! the directory DACL that fences both from the sandbox account.
//!
//! These are written by the elevated `srt-win install` step (after
//! [`crate::user::provision`]) and read by the non-elevated broker
//! at `srt-win exec` / `srt-win user read-cred` time.

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::{acl, dpapi, sid, state_db, user};

/// Bumped on schema-incompatible changes to [`SetupMarker`] or
/// [`CredFile`]. The broker compares this to the on-disk marker and
/// refuses with a "re-run `srt-win install`" message on mismatch.
pub const SETUP_VERSION: u32 = 1;

const CRED_FILE: &str = "sandbox-user.json";
const MARKER_FILE: &str = "setup_marker.json";

#[derive(Serialize, Deserialize)]
struct CredFile {
    version: u32,
    username: String,
    /// `base64(CryptProtectData(password, CRYPTPROTECT_LOCAL_MACHINE))`.
    /// Machine-scope DPAPI is **not** a confidentiality boundary —
    /// see [`crate::dpapi`]; the directory DACL is.
    password_dpapi_b64: String,
}

/// Persisted by `srt-win install`; read by the broker to learn the
/// sandbox user's SID without a SAM lookup, and to detect a
/// stale/partial install.
#[derive(Debug, Serialize, Deserialize)]
pub struct SetupMarker {
    pub version: u32,
    pub sandbox_user: String,
    pub sandbox_user_sid: String,
    pub sandbox_group_sid: String,
    /// Seconds since the Unix epoch. A human-readable timestamp
    /// would need a date-formatting dependency; the marker is
    /// machine-read, so epoch seconds are sufficient.
    pub created_at_unix: u64,
}

pub fn cred_file_path() -> Result<PathBuf> {
    Ok(state_db::state_dir()?.join(CRED_FILE))
}

pub fn marker_path() -> Result<PathBuf> {
    Ok(state_db::state_dir()?.join(MARKER_FILE))
}

/// DPAPI-encrypt `u.password`, write [`CredFile`] JSON, and stamp
/// the **state directory** with the broker-only DACL plus an
/// explicit `(D;OICI;FA;;;<sandbox-runtime-users>)` DENY. The DENY
/// is the load-bearing gate: machine-scope DPAPI lets any local
/// account decrypt the blob if it can read it, so the sandbox
/// user MUST be unable to open the file.
///
/// The same directory hosts `state.db`; [`crate::state_db`]'s
/// `open_db` re-stamps it on every open and includes the same DENY
/// when [`user::SANDBOX_GROUP`] resolves, so the DENY persists
/// across `acl stamp` runs.
pub fn write_cred_file(
    u: &user::ProvisionedUser,
    broker_group_sid: &str,
) -> Result<()> {
    let dir = state_db::state_dir()?;
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("create_dir_all {}", dir.display()))?;
    let dir_str = dir.to_str().ok_or_else(|| {
        anyhow!(
            "state directory path '{}' is not representable as UTF-8",
            dir.display()
        )
    })?;
    acl::stamp_dir_inheriting(
        dir_str, broker_group_sid, Some(&u.group_sid),
    )
    .context("stamp state dir broker-only + sandbox-group DENY")?;

    let blob = dpapi::protect_machine(u.password.as_bytes())?;
    let body = serde_json::to_string_pretty(&CredFile {
        version: SETUP_VERSION,
        username: u.username.clone(),
        password_dpapi_b64: b64_encode(&blob),
    })?;
    let path = dir.join(CRED_FILE);
    std::fs::write(&path, body)
        .with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

/// Decrypt and return the sandbox user's password. Fails if the
/// caller cannot read the credential file — by design, the
/// sandbox user is DENY'd on the directory and so cannot call
/// this to learn its own password.
pub fn read_cred() -> Result<(String, String)> {
    let path = cred_file_path()?;
    let body = std::fs::read_to_string(&path).with_context(|| {
        format!(
            "read {} (run `srt-win install` if it does not exist)",
            path.display()
        )
    })?;
    let cf: CredFile = serde_json::from_str(&body)
        .with_context(|| format!("parse {}", path.display()))?;
    if cf.version != SETUP_VERSION {
        return Err(anyhow!(
            "credential file at {} is version {} (expected {}); \
             re-run `srt-win install`",
            path.display(),
            cf.version,
            SETUP_VERSION,
        ));
    }
    let blob = b64_decode(&cf.password_dpapi_b64)
        .context("base64-decode credential blob")?;
    let pw = dpapi::unprotect(&blob)?;
    let pw = String::from_utf8(pw).context("password is not UTF-8")?;
    Ok((cf.username, pw))
}

/// Write [`SetupMarker`] and ACL it `D:P (A;;FA;;;SY)(A;;FA;;;BA)
/// (A;;FA;;;<real-user>)` so the sandbox user cannot tamper with
/// the broker's view of the install.
pub fn write_setup_marker(u: &user::ProvisionedUser) -> Result<()> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let body = serde_json::to_string_pretty(&SetupMarker {
        version: SETUP_VERSION,
        sandbox_user: u.username.clone(),
        sandbox_user_sid: u.sid.clone(),
        sandbox_group_sid: u.group_sid.clone(),
        created_at_unix: now,
    })?;
    let path = marker_path()?;
    std::fs::write(&path, body)
        .with_context(|| format!("write {}", path.display()))?;

    // ACL the marker itself: SYSTEM/Admins/<real-user> only,
    // PROTECTED. The directory's `(OI)(CI)` broker-only stamp
    // already covers this, but the marker is the broker's source
    // of truth for "is the install valid", so an explicit
    // non-inheriting DACL means a future change to the directory
    // stamp can't accidentally widen it.
    let real_user = sid::current_user_sid()?;
    let path_str = path.to_str().ok_or_else(|| {
        anyhow!("marker path '{}' not UTF-8", path.display())
    })?;
    let dacl = acl::build_allow_dacl(&[
        acl::Allow("S-1-5-18", acl::Mask::FILE_ALL, acl::NO_INHERIT),
        acl::Allow("S-1-5-32-544", acl::Mask::FILE_ALL, acl::NO_INHERIT),
        acl::Allow(&real_user, acl::Mask::FILE_ALL, acl::NO_INHERIT),
        acl::Allow::OWNER_RIGHTS,
    ])?;
    acl::set_file_dacl_protected(path_str, &dacl, "setup marker")?;
    Ok(())
}

/// Read the on-disk marker. `Ok(None)` when no install has run.
pub fn read_setup_marker() -> Result<Option<SetupMarker>> {
    let path = marker_path()?;
    match std::fs::read_to_string(&path) {
        Ok(body) => {
            let m: SetupMarker = serde_json::from_str(&body)
                .with_context(|| format!("parse {}", path.display()))?;
            Ok(Some(m))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(anyhow!("read {}: {e}", path.display())),
    }
}

/// Delete the credential file and setup marker. Idempotent.
pub fn remove_artifacts() -> Result<()> {
    for p in [cred_file_path()?, marker_path()?] {
        match std::fs::remove_file(&p) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(anyhow!("remove {}: {e}", p.display()));
            }
        }
    }
    Ok(())
}

// ─── minimal base64 (standard alphabet, with padding) ───────────────
//
// Avoids a crate dependency for the one ~200-byte blob this module
// encodes. Not constant-time — the blob is ciphertext, not a secret
// the encoding leaks.

const B64_ALPHA: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(B64_ALPHA[(n >> 18) as usize & 63] as char);
        out.push(B64_ALPHA[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            B64_ALPHA[(n >> 6) as usize & 63] as char
        } else { '=' });
        out.push(if chunk.len() > 2 {
            B64_ALPHA[n as usize & 63] as char
        } else { '=' });
    }
    out
}

fn b64_decode(s: &str) -> Result<Vec<u8>> {
    fn val(c: u8) -> Result<u32> {
        Ok(match c {
            b'A'..=b'Z' => (c - b'A') as u32,
            b'a'..=b'z' => (c - b'a' + 26) as u32,
            b'0'..=b'9' => (c - b'0' + 52) as u32,
            b'+' => 62,
            b'/' => 63,
            _ => return Err(anyhow!("invalid base64 char 0x{c:02x}")),
        })
    }
    let s = s.trim().as_bytes();
    if !s.len().is_multiple_of(4) {
        return Err(anyhow!("base64 length {} not a multiple of 4", s.len()));
    }
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    for q in s.chunks_exact(4) {
        let pad = q.iter().rev().take_while(|&&c| c == b'=').count();
        if pad > 2 {
            return Err(anyhow!("invalid base64 padding"));
        }
        let n = (val(q[0])? << 18)
            | (val(q[1])? << 12)
            | (if pad < 2 { val(q[2])? } else { 0 } << 6)
            | (if pad < 1 { val(q[3])? } else { 0 });
        out.push((n >> 16) as u8);
        if pad < 2 { out.push((n >> 8) as u8); }
        if pad < 1 { out.push(n as u8); }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64_round_trip() {
        for v in [
            &b""[..], b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar",
            &[0u8, 255, 1, 254, 127, 128][..],
        ] {
            let enc = b64_encode(v);
            assert_eq!(b64_decode(&enc).unwrap(), v, "round-trip {v:?}");
        }
        // RFC 4648 test vector.
        assert_eq!(b64_encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(b64_encode(b"foob"), "Zm9vYg==");
    }

    #[test]
    fn b64_rejects_garbage() {
        assert!(b64_decode("Zm9v!mFy").is_err());
        assert!(b64_decode("Zm9").is_err()); // bad length
    }
}
