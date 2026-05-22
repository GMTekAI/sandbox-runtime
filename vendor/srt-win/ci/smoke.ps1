<#
  srt-win end-to-end smoke test.

  Exercises the full group + WFP lifecycle against a built srt-win.exe.
  Throws on any assertion failure. Requires elevation (NetLocalGroup*
  and Fwpm* both need admin).

  Usage (local dev machine):
    pwsh vendor/srt-win/ci/smoke.ps1 .\target\release\srt-win.exe

  Usage (CI — workflow passes the path):
    pwsh vendor/srt-win/ci/smoke.ps1 vendor\srt-win\target\release\srt-win.exe

  All WFP operations target $TestSublayer (a fixed test GUID), NOT
  the production default sublayer — safe to run on a dev machine
  that has real sandbox-runtime filters installed; the idempotent
  install's purge-then-re-add only touches the test sublayer.

  When running under GitHub Actions, the random alt-sublayer GUID is
  also written to $env:GITHUB_ENV so the always()-gated cleanup step
  can remove those filters even if this script throws midway.
#>
param(
  [Parameter(Mandatory = $true)]
  [string]$Exe,
  [string]$GroupName = 'srt-ci-test',
  # Distinct from wfp::DEFAULT_SUBLAYER_GUID so local runs never
  # touch a production install.
  [string]$TestSublayer = 'a91b6f12-4c0e-4e30-b1f7-3d52890ce117'
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path $Exe)) {
  throw "srt-win.exe not found at '$Exe'"
}

# user_sid logged for debug context only (whose TokenGroups the
# group-status / fence assertions are evaluating against).
$me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
Write-Host "srt-win smoke: exe=$Exe group=$GroupName sublayer=$TestSublayer user_sid=$me"
$sl = @('--sublayer-guid', $TestSublayer)

function Run([string[]]$argv) {
  & $Exe @argv
  if ($LASTEXITCODE -ne 0) {
    throw "srt-win $($argv -join ' ') exited $LASTEXITCODE"
  }
}
function J([string[]]$argv) { Run $argv | ConvertFrom-Json }
function MustFail([string[]]$argv, [string]$why) {
  & $Exe @argv 2>$null
  if ($LASTEXITCODE -eq 0) {
    throw "expected non-zero ($why): srt-win $($argv -join ' ')"
  }
}

# ── group create (idempotent) ────────────────────────────────────────
Run @('group', 'create', '--name', $GroupName)
Run @('group', 'create', '--name', $GroupName)   # second call must succeed

$gs = J @('group', 'status', '--name', $GroupName)
Write-Host "group status (--name): $($gs | ConvertTo-Json -Compress)"
# In CI there's no logout, so the new group SID is not yet on the
# runner's token: `created-not-on-token` is expected. On a dev box
# that already has the group from a prior run, `ready` is fine too.
if ($gs.state -notin 'created-not-on-token', 'ready') {
  throw "unexpected group state: $($gs.state)"
}
if (-not $gs.sid -or -not $gs.sid.StartsWith('S-1-')) {
  throw "group status did not return a SID"
}

# --group-sid path returns the same SID.
$gs2 = J @('group', 'status', '--group-sid', $gs.sid)
if ($gs2.sid -ne $gs.sid) {
  throw "--group-sid status sid mismatch: $($gs2.sid) vs $($gs.sid)"
}
# Unmapped SID via --group-sid reports absent (not created-not-on-token).
$gsBad = J @('group', 'status', '--group-sid', 'S-1-5-21-1-2-3-9999999')
if ($gsBad.state -ne 'absent') {
  throw "unmapped --group-sid expected absent, got $($gsBad.state)"
}

# ── negative input: invalid SID fails fast with a clear error ───────
MustFail @('wfp', 'install', '--group-sid', 'not-a-sid') 'invalid --group-sid'

# ═════════════════════════════════════════════════════════════════════
# WFP lifecycle test — uses $GroupName.
#
# The WFP filters are machine-wide and keyed on the group SID. We
# can install/enumerate/uninstall them regardless of whether the
# group is on the current token, so $GroupName works fine for the
# *lifecycle* assertions below. It does NOT work for asserting
# "the broker gets through" — that needs a group already enabled
# on this token, which $GroupName isn't (no logout in CI). The
# fence-behaviour section further down uses BUILTIN\Administrators
# instead.
# ═════════════════════════════════════════════════════════════════════

# ── pre-install absent ───────────────────────────────────────────────
$pre = J (@('wfp', 'status') + $sl)
if ($pre.state -ne 'absent') {
  throw "pre-install wfp status expected absent, got $($pre.state)"
}

# First install via --name.
Run (@('wfp', 'install', '--name', $GroupName) + $sl)
$ws = J (@('wfp', 'status') + $sl)
Write-Host "wfp status: $($ws | ConvertTo-Json -Compress)"
if ($ws.state -ne 'installed') { throw "expected installed, got $($ws.state)" }
if ($ws.filters -lt 8)         { throw "expected >=8 filters, got $($ws.filters)" }

# Idempotency: second install via --group-sid path leaves the same
# filter count.
Run (@('wfp', 'install', '--group-sid', $gs.sid) + $sl)
$ws2 = J (@('wfp', 'status') + $sl)
if ($ws2.filters -ne $ws.filters) {
  throw "idempotency: filter count changed $($ws.filters) -> $($ws2.filters)"
}

# ── --sublayer-guid isolation ────────────────────────────────────────
# Persist the alt GUID so an always()-gated cleanup step can remove
# its filters even if this script throws midway.
$altGuid = [guid]::NewGuid().ToString()
if ($env:GITHUB_ENV) {
  Add-Content $env:GITHUB_ENV "SRT_ALT_GUID=$altGuid"
}
Run @('wfp', 'install', '--name', $GroupName, '--sublayer-guid', $altGuid)
$alt = J @('wfp', 'status', '--sublayer-guid', $altGuid)
if ($alt.state -ne 'installed') {
  throw "alt sublayer expected installed, got $($alt.state)"
}
# Test sublayer is still its own thing.
$stillTest = J (@('wfp', 'status') + $sl)
if ($stillTest.filters -ne $ws.filters) {
  throw "test sublayer perturbed by alt install"
}
Run @('wfp', 'uninstall', '--sublayer-guid', $altGuid)
$altGone = J @('wfp', 'status', '--sublayer-guid', $altGuid)
if ($altGone.state -ne 'absent') {
  throw "alt sublayer expected absent after uninstall, got $($altGone.state)"
}

# ── teardown: uninstall on test sublayer ────────────────────────────
Run (@('wfp', 'uninstall') + $sl)
$post = J (@('wfp', 'status') + $sl)
if ($post.state -ne 'absent') {
  throw "post-uninstall expected absent, got $($post.state)"
}
# Idempotent no-op: second uninstall must also exit 0.
Run (@('wfp', 'uninstall') + $sl)

# ═════════════════════════════════════════════════════════════════════
# WFP fence-behaviour test — uses BUILTIN\Administrators (S-1-5-32-544).
#
# Why a different group: the fence relies on AccessCheck against the
# connecting token, so to assert "broker passes filter 1" we need a
# group that's *already enabled* on this token. $GroupName was just
# created and won't be in TokenGroups until a fresh logon. Admins is
# reliably enabled on the GHA runner.
# ═════════════════════════════════════════════════════════════════════

$adminsSid = 'S-1-5-32-544'
Run (@('wfp', 'install', '--group-sid', $adminsSid) + $sl)
try {
  # Broker-side: this process has Admins enabled, so filter 1
  # (PERMIT group-enabled) should let the connect through.
  $r = curl.exe -s -m 10 -o NUL -w "%{http_code}" https://example.com
  if ($LASTEXITCODE -ne 0 -or $r -ne '200') {
    throw "broker egress through filter 1 expected 200, got exit=$LASTEXITCODE code='$r'"
  }
  Write-Host "fence: broker egress OK ($r)"

  # Child-side (group deny-only) assertion lands in batch 02 once
  # `srt-win exec` exists; that batch's smoke-exec.ps1 will run
  #   srt-win exec --group-sid S-1-5-32-544 -- curl https://example.com
  # and assert it is BLOCKED.
}
finally {
  Run (@('wfp', 'uninstall') + $sl)
}

# ── group teardown ───────────────────────────────────────────────────
Run @('group', 'delete', '--name', $GroupName)
$gd = J @('group', 'status', '--name', $GroupName)
if ($gd.state -ne 'absent') {
  throw "post-delete group expected absent, got $($gd.state)"
}
# Idempotent no-op: second delete must also exit 0.
Run @('group', 'delete', '--name', $GroupName)

Write-Host 'srt-win smoke: OK'
