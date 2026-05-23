<#
  Best-effort teardown of any state smoke.ps1 may have left behind.
  Intended for `if: always()` in CI; safe to run locally too.

  Targets the same fixed test sublayer as smoke.ps1 (NOT the
  production default), plus the per-run random alt sublayer if
  smoke.ps1 wrote one to $env:SRT_ALT_GUID.

  Usage:
    pwsh vendor/srt-win/ci/cleanup.ps1 <path-to-srt-win.exe> [group-name]
#>
param(
  [Parameter(Mandatory = $true)]
  [string]$Exe,
  [string]$GroupName = 'srt-ci-test',
  # Must match smoke.ps1's default.
  [string]$TestSublayer = 'a91b6f12-4c0e-4e30-b1f7-3d52890ce117',
  # Must match smoke-exec.ps1's default.
  [string]$ExecSublayer = '5b0e64f4-09f1-4c2e-8c97-4d2c0f4e9b7d'
)

$ErrorActionPreference = 'SilentlyContinue'

if (-not (Test-Path $Exe)) {
  Write-Host "cleanup: $Exe not found; nothing to do"
  exit 0
}

if ($env:SRT_ALT_GUID) {
  & $Exe wfp uninstall --sublayer-guid $env:SRT_ALT_GUID
}
& $Exe wfp uninstall --sublayer-guid $TestSublayer
& $Exe wfp uninstall --sublayer-guid $ExecSublayer
& $Exe group delete --name $GroupName
exit 0
