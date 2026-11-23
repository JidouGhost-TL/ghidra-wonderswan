# SPDX-License-Identifier: MIT OR Apache-2.0
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $Output,
    [string] $Cache,
    [string] $Python = 'python'
)

$ErrorActionPreference = 'Stop'
$arguments = @('-B', (Join-Path $PSScriptRoot 'run_windows.py'), $Output)
if ($Cache) {
    $arguments += @('--cache', $Cache)
}
& $Python @arguments
if ($LASTEXITCODE -ne 0) {
    throw "The native GUI rehearsal did not pass. Its private stage logs remain in the job directory."
}
