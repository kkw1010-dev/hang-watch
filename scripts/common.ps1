# hang-watch 1.0.0 - Shared read-only path, heartbeat and dump helpers.
function Resolve-GameDocuments {
    param([string]$GameDocs, [ValidateSet('SE','GOG','VR')][string]$GameVariant = 'SE')
    if ($GameDocs) { return [IO.Path]::GetFullPath($GameDocs) }
    $documents = [Environment]::GetFolderPath('MyDocuments')
    if (-not $documents) { throw 'Documents folder unavailable; supply -GameDocs explicitly.' }
    $names = @{ SE = 'Skyrim Special Edition'; GOG = 'Skyrim Special Edition GOG'; VR = 'Skyrim VR' }
    return Join-Path $documents ('My Games\' + $names[$GameVariant])
}
function Get-HeartbeatSnapshot {
    param([string]$GameDocs, [string[]]$HeartbeatFiles)
    $paths = @()
    if ($HeartbeatFiles -and $HeartbeatFiles.Count) {
        foreach ($p in $HeartbeatFiles) {
            if ([IO.Path]::IsPathRooted($p)) { $paths += $p } else { $paths += Join-Path $GameDocs $p }
        }
    } else {
        $paths += Join-Path $GameDocs 'Logs\Script\Papyrus.0.log'
        $paths += @(Get-ChildItem -LiteralPath (Join-Path $GameDocs 'SKSE') -Filter '*.log' -File -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
    }
    $present = 0
    $state = @($paths | Sort-Object -Unique | ForEach-Object {
        $item = Get-Item -LiteralPath $_ -ErrorAction SilentlyContinue
        if ($item -and -not $item.PSIsContainer) {
            $present++; '{0}|{1}|{2}' -f $item.FullName, $item.Length, $item.LastWriteTimeUtc.Ticks
        } else { '{0}|missing' -f $_ }
    })
    [pscustomobject]@{ Signature = ($state -join "`n"); Present = $present; Paths = $paths }
}
function Get-GameProcess {
    param([string]$ProcessName, [int]$ProcessId, [datetime]$StartedAfterUtc = [datetime]::MinValue)
    $games = @(Get-Process -Name $ProcessName -ErrorAction SilentlyContinue)
    foreach ($game in $games) {
        try {
            if (($ProcessId -eq 0 -or $game.Id -eq $ProcessId) -and $game.StartTime.ToUniversalTime() -ge $StartedAfterUtc) { return $game }
        } catch { Write-Warning 'Cannot read game start time; run with the same permissions as the game.' }
    }
}
function Copy-SessionLogs {
    param([string]$GameDocs, [string]$Destination, [datetime]$Since)
    New-Item -ItemType Directory -Force -Path $Destination | Out-Null
    $skseOut = Join-Path $Destination 'skse'
    New-Item -ItemType Directory -Force -Path $skseOut | Out-Null
    foreach ($i in 0..3) {
        $p = Join-Path $GameDocs "Logs\Script\Papyrus.$i.log"
        if (Test-Path -LiteralPath $p) { Copy-Item -LiteralPath $p -Destination $Destination -ErrorAction Continue }
    }
    Get-ChildItem -LiteralPath (Join-Path $GameDocs 'SKSE') -Filter '*.log' -File -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -ge $Since } |
        ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination $skseOut -ErrorAction Continue }
}
function Start-HangWatchChild {
    param([string]$Script, [hashtable]$Options, [string]$OutputDir)
    # Encoded JSON preserves spaces, quotes, Unicode and array-valued heartbeat arguments.
    $json64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($Options | ConvertTo-Json -Depth 5 -Compress)))
    $quotedScript = $Script.Replace("'", "''")
    $command = "`$v = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$json64')) | ConvertFrom-Json; `$opts = @{}; `$v.PSObject.Properties | ForEach-Object { `$opts[`$_.Name] = `$_.Value }; & '$quotedScript' @opts"
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -WindowStyle Hidden -PassThru `
        -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-EncodedCommand',$encoded) `
        -RedirectStandardOutput (Join-Path $OutputDir 'watch.out.txt') -RedirectStandardError (Join-Path $OutputDir 'watch.err.txt')
}
function Write-HangDumpSet {
    param($Game, [string]$OutDir, [int]$Dumps, [int]$GapSeconds, [switch]$FullMemory)
    # Full dumps can exceed PrivateMemorySize64. The check is a conservative estimate, not a guarantee.
    $drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot([IO.Path]::GetFullPath($OutDir)))
    $estimate = 1GB + $Dumps * 256MB
    if ($FullMemory) { $estimate = 1GB + $Dumps * [math]::Max(256MB, $Game.PrivateMemorySize64 * 1.5) }
    if ($drive.AvailableFreeSpace -lt $estimate) { throw 'Insufficient estimated dump space. Free space or choose another -OutDir; nothing was captured.' }
    if (-not ('HangWatchNative' -as [type])) {
        Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class HangWatchNative {
    [DllImport("dbghelp.dll", SetLastError=true)]
    public static extern bool MiniDumpWriteDump(IntPtr process, uint pid, SafeFileHandle file, uint flags,
        IntPtr exception, IntPtr streams, IntPtr callback);
}
"@
    }
    $lockPath = Join-Path $OutDir 'dumping.lock'
    # CreateNew prevents concurrent writers using this same output directory.
    $lockStream = [IO.File]::Open($lockPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    $successful = 0
    try {
        $flags = [uint32](0x4 -bor 0x20 -bor 0x40 -bor 0x100 -bor 0x1000)
        if ($FullMemory) { $flags = [uint32]($flags -bor 0x2) }
        for ($n=1; $n -le $Dumps; $n++) {
            $path = Join-Path $OutDir ('{0}_hang_{1}_{2}_{3}.dmp' -f $Game.ProcessName,$Game.Id,(Get-Date -Format 'yyyyMMdd-HHmmss-fff'),$n)
            $stream = [IO.File]::Create($path)
            try {
                $ok = [HangWatchNative]::MiniDumpWriteDump($Game.Handle,[uint32]$Game.Id,$stream.SafeFileHandle,$flags,[IntPtr]::Zero,[IntPtr]::Zero,[IntPtr]::Zero)
                $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            } finally { $stream.Close() }
            if ($ok) { $successful++; Write-Host "dump written: $path" } else { Write-Warning "dump FAILED ($errorCode), keep partial evidence: $path" }
            if ($n -lt $Dumps) { Start-Sleep -Seconds $GapSeconds }
        }
    } finally {
        $lockStream.Dispose()
        Move-Item -LiteralPath $lockPath -Destination (Join-Path $OutDir ('dumping-{0}-{1}.done' -f $Game.Id,(Get-Date -Format 'yyyyMMdd-HHmmss-fff'))) -ErrorAction Stop
    }
    return $successful
}
