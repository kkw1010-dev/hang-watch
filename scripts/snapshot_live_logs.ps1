<#
hang-watch 1.0.0 - Snapshot log copies only; never opens a process handle or writes a dump.
Use after the capture completed, before the next game launch overwrites the live logs.
#>
param(
    [Parameter(Mandatory)][string]$OutDir,
    [ValidateRange(1,43200)][int]$SinceMinutes = 30,
    [string]$GameDocs,
    [ValidateSet('SE','GOG','VR')][string]$GameVariant = 'SE'
)
. (Join-Path $PSScriptRoot 'common.ps1')
$docs = Resolve-GameDocuments $GameDocs $GameVariant
$d = Join-Path $OutDir ('live-snapshot-' + (Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
Copy-SessionLogs $docs $d (Get-Date).AddMinutes(-$SinceMinutes)
Write-Host "snapshot: $d"
