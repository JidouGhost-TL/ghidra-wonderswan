# SPDX-License-Identifier: MIT OR Apache-2.0
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $Output,
    [string] $Python = 'python',
    [string] $CandidateCheckout
)

$ErrorActionPreference = 'Stop'
if (-not $IsWindows -or [System.Diagnostics.Process]::GetCurrentProcess().SessionId -eq 0) {
    Write-Output 'PUBLIC_GHIDRA_GUI_STAGE {"platform":"Windows-x64","stage":"console_session","status":"failed","reason":"interactive_session_required"}'
    exit 1
}

# The Python launcher creates a new Windows console and uses Ghidra's foreground
# mode. This PowerShell step can have redirected standard streams.
$driver = Join-Path $PSScriptRoot 'run_windows.py'
$driverArgs = @($Output)
if ($CandidateCheckout) {
    $driverArgs += @('--candidate-checkout', $CandidateCheckout)
}
& $Python -B $driver @driverArgs
exit $LASTEXITCODE
