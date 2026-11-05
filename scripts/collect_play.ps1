<#
hang-watch 1.0.0 - Session collector; outputs only. Starts its own hidden watcher, never the game/manager.
Collects Papyrus.0-3 and ALL SKSE *.log files written during each observed session, including crash logs.
#>
param(
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9][A-Za-z0-9_.-]*$')][string]$RunName,
    [string]$OutRoot,
    [ValidateRange(0.001,720)][double]$Hours = 5,
    [ValidateRange(1,1440)][int]$IdleMinutes = 20,
    [switch]$FullMemory,
    [ValidateRange(1,10)][int]$Dumps = 2,
    [ValidateRange(1,86400)][int]$QuietSeconds = 45,
    [string]$GameDocs,
    [ValidateSet('SE','GOG','VR')][string]$GameVariant = 'SE',
    [string[]]$HeartbeatFiles,
    [string]$ProcessName
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
$docs = Resolve-GameDocuments $GameDocs $GameVariant
if (-not $ProcessName) { $ProcessName = if ($GameVariant -eq 'VR') { 'SkyrimVR' } else { 'SkyrimSE' } }
if (-not $OutRoot) { $OutRoot = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'hang-watch-runs' }
$o = Join-Path ([IO.Path]::GetFullPath($OutRoot)) $RunName
$hangDir = Join-Path $o 'hang'
New-Item -ItemType Directory -Force -Path $hangDir | Out-Null
# A unique token avoids stale stop requests from an earlier collector run.
$stopFile = Join-Path $hangDir ('stop-' + [guid]::NewGuid().ToString('N') + '.request')
$runLock = [IO.File]::Open((Join-Path $o 'collector.lock'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
try {
    $start = Get-Date; $deadline = $start.AddHours($Hours)
    Add-Content -LiteralPath (Join-Path $o '.start') -Value $start.ToString('o')
    $options = @{OutDir=$hangDir;Hours=$Hours;Dumps=$Dumps;QuietSeconds=$QuietSeconds;FullMemory=[bool]$FullMemory;GameDocs=$docs;GameVariant=$GameVariant;ProcessName=$ProcessName;StopFile=$stopFile}
    if ($HeartbeatFiles) { $options.HeartbeatFiles = $HeartbeatFiles }
    $watcher = Start-HangWatchChild (Join-Path $PSScriptRoot 'play_hang_watch.ps1') $options $hangDir
    Write-Host "collector armed; watcher PID $($watcher.Id); output $o"
    $n = 0
    Get-ChildItem -LiteralPath $o -Directory | ForEach-Object { if ($_.Name -match '^session(\d+)$') { $n = [math]::Max($n,[int]$Matches[1]) } }
    $idleSince = $null
    while ((Get-Date) -lt $deadline) {
        $game = Get-GameProcess $ProcessName 0
        if ($game) {
            $idleSince = $null; $n++; $gs = $game.StartTime; $key = $game.Id
            Write-Host "session ${n}: PID $key start $gs"
            do {
                Start-Sleep -Seconds 3
                $current = Get-GameProcess $ProcessName $key
            } while ($current -and $current.StartTime -eq $gs -and (Get-Date) -lt $deadline)
            if (-not $current) { Start-Sleep -Seconds 3 }
            $dest = Join-Path $o "session$n"
            Copy-SessionLogs $docs $dest $gs
            Write-Host "session ${n}: snapshot collected into $dest (a still-running game is never stopped)"
            continue
        }
        # Either supported manager keeps the collector armed; it is never controlled by this script.
        if (-not (Get-Process -Name ModOrganizer,Vortex -ErrorAction SilentlyContinue)) {
            if (-not $idleSince) { $idleSince = Get-Date }
            elseif (((Get-Date)-$idleSince).TotalMinutes -ge $IdleMinutes) { break }
        } else { $idleSince = $null }
        Start-Sleep -Seconds 3
    }
} finally {
    # Cooperative stop, checked only between captures; never terminate a dump writer or the game.
    Set-Content -LiteralPath $stopFile -Value 'collector finished' -Encoding ascii
    $runLock.Dispose()
    Move-Item -LiteralPath (Join-Path $o 'collector.lock') -Destination (Join-Path $o ('collector-' + (Get-Date -Format 'yyyyMMdd-HHmmss-fff') + '.done'))
}
Write-Host "COLLECT DONE $RunName"
