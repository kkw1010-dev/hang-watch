<#
hang-watch 1.0.0 - One-shot watcher for an agent-managed launch, or -IncludeExisting for a frozen game.
Does not launch, stop or attach to anything. Uses the same window AND heartbeat trigger as user-play mode.
#>
param(
    [Parameter(Mandatory)][string]$OutDir,
    [ValidateRange(1,86400)][int]$QuietSeconds = 45,
    [ValidateRange(1,10)][int]$Dumps = 2,
    [ValidateRange(0,3600)][int]$GapSeconds = 5,
    [ValidateRange(1,43200)][int]$MaxMinutes = 60,
    [ValidateRange(0,86400)][int]$StartAfterSeconds = 330,
    [switch]$FullMemory,
    [string]$GameDocs,
    [ValidateSet('SE','GOG','VR')][string]$GameVariant = 'SE',
    [string[]]$HeartbeatFiles,
    [string]$ProcessName,
    [ValidateRange(0,2147483647)][int]$ProcessId = 0,
    [switch]$IncludeExisting
)
$start = Get-Date
if ($StartAfterSeconds -ge $MaxMinutes*60) { throw '-StartAfterSeconds must be shorter than -MaxMinutes.' }
Start-Sleep -Seconds $StartAfterSeconds
$after = if ($IncludeExisting -or $ProcessId) { [datetime]::MinValue } else { $start.ToUniversalTime().AddMinutes(-2) }
$remaining = $MaxMinutes/60.0 - ((Get-Date)-$start).TotalHours
& (Join-Path $PSScriptRoot 'play_hang_watch.ps1') -OutDir $OutDir -Hours $remaining -QuietSeconds $QuietSeconds `
    -Dumps $Dumps -GapSeconds $GapSeconds -FullMemory:$FullMemory -GameDocs $GameDocs -GameVariant $GameVariant `
    -HeartbeatFiles $HeartbeatFiles -ProcessName $ProcessName -ProcessId $ProcessId -StartedAfterUtc $after -Once
