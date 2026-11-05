<#
hang-watch 1.0.0 - User-play watcher. Requires an unresponsive game window AND still heartbeat logs.
Writes dump sets without killing, suspending, injecting or attaching a debugger to the game.
Long loading screens can satisfy both conditions: increase -QuietSeconds for your installation.
#>
param(
    [Parameter(Mandatory)][string]$OutDir,
    [ValidateRange(0.001,720)][double]$Hours = 6,
    [ValidateRange(1,86400)][int]$QuietSeconds = 45,
    [ValidateRange(1,10)][int]$Dumps = 2,
    [ValidateRange(0,3600)][int]$GapSeconds = 5,
    [switch]$FullMemory,
    [string]$GameDocs,
    [ValidateSet('SE','GOG','VR')][string]$GameVariant = 'SE',
    [string[]]$HeartbeatFiles,
    [string]$ProcessName,
    [ValidateRange(0,2147483647)][int]$ProcessId = 0,
    [datetime]$StartedAfterUtc = [datetime]::MinValue,
    [switch]$Once,
    [string]$StopFile
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
$docs = Resolve-GameDocuments $GameDocs $GameVariant
if (-not $ProcessName) { $ProcessName = if ($GameVariant -eq 'VR') { 'SkyrimVR' } else { 'SkyrimSE' } }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$log = Join-Path $OutDir 'watch.log'
function Say($Message) { $line = '{0:yyyy-MM-dd HH:mm:ss} {1}' -f (Get-Date),$Message; Add-Content -LiteralPath $log -Value $line -Encoding utf8; Write-Host $line }
$deadline = (Get-Date).AddHours($Hours)
Say "hang-watch 1.0.0; docs=$docs; process=$ProcessName; quiet=$QuietSeconds seconds; deadline=$deadline"
$seen = $null; $dumped = @{}; $last = $null; $lastChange = Get-Date; $notResponding = $null; $missingWarned = $false
while ((Get-Date) -lt $deadline) {
    if ($StopFile -and (Test-Path -LiteralPath $StopFile)) { Say 'collector requested clean stop'; break }
    $game = Get-GameProcess $ProcessName $ProcessId $StartedAfterUtc
    if (-not $game) {
        if ($seen) { Say "game $seen gone"; if ($Once) { break } }
        $seen = $null; $notResponding = $null; Start-Sleep -Seconds 3; continue
    }
    $key = '{0}-{1}' -f $game.Id,$game.StartTime.ToUniversalTime().Ticks
    if ($key -ne $seen) { $seen = $key; $last = $null; $lastChange = Get-Date; $notResponding = $null; $missingWarned = $false; Say "game $key seen" }
    if ($dumped.ContainsKey($key)) { Start-Sleep -Seconds 3; continue }
    $beat = Get-HeartbeatSnapshot $docs $HeartbeatFiles
    if ($beat.Signature -ne $last) { $last = $beat.Signature; $lastChange = Get-Date }
    if ($beat.Present -eq 0) {
        if (-not $missingWarned) { Say 'No readable heartbeat files: automatic capture is disabled until a log appears. Check -GameDocs / -HeartbeatFiles.'; $missingWarned = $true }
        $notResponding = $null; Start-Sleep -Seconds 3; continue
    }
    $game.Refresh()
    if ($game.MainWindowHandle -eq [IntPtr]::Zero -or $game.Responding) { $notResponding = $null }
    elseif (-not $notResponding) { $notResponding = Get-Date; Say "game $key window not responding" }
    if ($notResponding -and ((Get-Date)-$notResponding).TotalSeconds -ge $QuietSeconds -and ((Get-Date)-$lastChange).TotalSeconds -ge $QuietSeconds) {
        Say 'both conditions met; writing dumps (game will be left running)'
        $count = Write-HangDumpSet -Game $game -OutDir $OutDir -Dumps $Dumps -GapSeconds $GapSeconds -FullMemory:$FullMemory
        Set-Content -LiteralPath (Join-Path $OutDir ('heartbeats-{0}.txt' -f $key)) -Value $beat.Paths -Encoding utf8
        $events = @(Get-WinEvent -FilterHashtable @{LogName='System';ProviderName='nvlddmkm';StartTime=$game.StartTime} -ErrorAction SilentlyContinue)
        Say ("nvlddmkm events since game start: {0}; correlate timestamps, not a diagnosis by itself" -f $events.Count)
        Say "dumps done; successful=$count/$Dumps; the game is left as it is"
        $dumped[$key] = $true
        if ($Once) { break }
    }
    Start-Sleep -Seconds 3
}
Say 'watch ended'
