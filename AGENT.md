# hang-watch 1.0.0 — Windows Skyrim freeze evidence for agents

This is a standalone evidence collector and offline dump-reading kit for an AI agent assisting a
Skyrim SE 1.5.97 / AE 1.6.x player. It supports MO2 and Vortex without controlling either manager.
VR paths and the SkyrimVR process can be selected explicitly. No particular mod is required.
README.md is the downloader's short entry point; this file is the agent's operating guide.

## Requirements and boundaries

- Windows, **64-bit Windows PowerShell 5.1**, Python **3.10+** for the readers, and `python -m pip install pefile`.
  The collectors use Windows' built-in dbghelp.dll. Python is not needed to capture evidence.
- Operate with the same permissions as the game. Prefer an ordinary unelevated session; permission failures
  should be reported, not worked around by stopping the game or disabling security software.
- The kit writes only to the chosen evidence directory. It does not launch/kill/suspend the game, inject code,
  attach a debugger, change mods/profiles, or change a mod manager. Dump capture reads the game through a
  process handle; this is distinct from attaching a debugger. An agent must obtain the user's authorization
  before arming capture or creating a dump. Reading this guide is not authorization to launch the game.
- **Full dumps are approximately the process's committed memory, potentially tens of GB each.** Check the
  destination's free space first: `[IO.DriveInfo]::new('D:\').AvailableFreeSpace / 1GB` (choose your actual drive).
  Leave ample margin for every requested dump and logs. The script estimates space again before capturing;
  memory growth or dump overhead can still exhaust it. Partial dumps must be preserved and identified.
- Dumps and logs can contain personal paths, loaded assets, private text and credentials. Keep them local
  until the owner reviews and explicitly approves sharing. Do not upload or fetch symbol files automatically.
- Do not delete evidence, stop an existing collector, or restart a frozen game without the owner's instruction.
  Editing this kit does not update a script already running; use a new version on a later authorized session.

## Files

| File | Purpose |
|---|---|
| scripts/collect_play.ps1 | Hidden child watcher plus per-process session log collection |
| scripts/play_hang_watch.ps1 | Watch user launches until a deadline, one capture set per process instance |
| scripts/hang_dump.ps1 | One-shot watcher scoped to a recent authorized launch, or an explicitly selected existing game |
| scripts/snapshot_live_logs.ps1 | Copy logs without process capture; safe independently of a watcher |
| scripts/common.ps1 | Shared path, heartbeat, log-copy and capture functions; not an entry-point command |
| readers/dump_triage.py | Exception/register summary and stack scan; --threads for freeze dumps |
| readers/dump_unwind.py | Attempted x64 unwind for one thread, with uncertainty and gaps shown |
| readers/address_library.py | Optional matching AE database discovery and ID decoding |

Run example commands **from the kit's root**, replacing the sample output paths and run names.
Do not run every example automatically. Pick the flow the user authorized.

## Paths, processes and heartbeats

All capture scripts accept `-GameDocs` and `-GameVariant SE|GOG|VR`. Default SE documents are
`[Environment]::GetFolderPath('MyDocuments')` plus `My Games\Skyrim Special Edition`.
Windows Known Folders resolve OneDrive redirection automatically; a literal OneDrive path is not assumed.
GOG and VR select `My Games\Skyrim Special Edition GOG` and `My Games\Skyrim VR` respectively.
Check the actual installation: distributions with another folder name must use `-GameDocs`.
`-GameDocs` is the **game-specific directory containing SKSE and Logs**, not its parent Documents folder.

`SkyrimSE` is the default process, `SkyrimVR` for VR. Watchers/collector accept `-ProcessName` to override
(no .exe suffix); direct watchers also accept `-ProcessId` to avoid choosing between multiple instances.

By default a heartbeat is **Papyrus.0.log OR any SKSE/*.log changing in size or LastWriteTime**.
Every matching log is tracked, and new or removed logs also change the fingerprint. No specific mod is needed.
Papyrus logging need not be enabled if an SKSE log already exists. Missing/unreadable heartbeat files disable
capture until at least one file appears; absence alone is not freeze evidence.

Both watchers require a visible game window to be **not responding AND all readable heartbeat logs to
remain unchanged** for `-QuietSeconds` (45 seconds by default). Menus and normally responding windows do not
trigger. This is a heuristic: a slow loading screen can satisfy both conditions, and an unrelated periodic
SKSE log can hide a real freeze. Increase the quiet time for long loads, or supply known meaningful logs:

```powershell
# In PowerShell, array syntax preserves individual file paths.
.\scripts\play_hang_watch.ps1 -OutDir 'D:\Evidence\manual' -HeartbeatFiles @('Logs\Script\Papyrus.0.log','SKSE\MyHeartbeat.log')
```

`-HeartbeatFiles` replaces the default list. Paths are literal, not wildcards; relative paths are relative
to GameDocs. Do not assume every mod writes every frame. A still log is evidence of inactivity, not proof of
an engine deadlock. No capture is possible if the process has no visible main window.

## Flow 1: user is about to play

After the owner authorizes evidence capture, arm the collector before they launch normally:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File .\scripts\collect_play.ps1 -RunName play-01 -OutRoot 'D:\Evidence' -Hours 5 -Dumps 2
```

Add `-FullMemory` only with permission and adequate free space. Without `-OutRoot`, outputs go to a
`hang-watch-runs` directory next to the kit. A custom path is recommended on a roomy local drive.
For a redirected or unusual installation add `-GameDocs 'D:\Documents\My Games\Skyrim Special Edition'`.

The collector starts only its own hidden watcher. It observes sessions, copies Papyrus.0–3 and **all SKSE
.log files written since session start** (including crash logs), and stops after Hours or when both the game
and either manager have been absent for IdleMinutes. Existing session numbers are continued. A game still
running at the deadline is left untouched; a current log snapshot is collected. Cooperative stop requests
are observed between capture sets, so a dump writer is not forcibly terminated.

`collector.lock` prevents two collectors from using the same run directory. If a collector itself crashes,
that sentinel can remain: verify that no collector or dump writer owns that run before the owner archives
it or selects a fresh run name. Never remove a live lock. `dumping.lock` means a set is being written;
`dumping-*.done` means the write attempt finished, not that every dump succeeded. Read watch.log.
Log copies can race a rapid restart and may fail while a file is exclusively locked: preserve warnings and
use snapshot_live_logs before restarting. Copying live files cannot guarantee a perfectly atomic session archive.

## Flow 2: agent-managed launch

When the owner separately authorizes a game launch, start this one-shot observer in a hidden background
PowerShell process first. The kit does **not** start the game or the manager:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File .\scripts\hang_dump.ps1 -OutDir 'D:\Evidence\launch-01' -StartAfterSeconds 330 -MaxMinutes 60 -Dumps 2
```

It accepts a process started no earlier than two minutes before the observer started, waits the startup
grace interval, and exits after one dump set, the process exits, or the deadline. It has the same two-condition
trigger as user-play mode. Ensure StartAfterSeconds is shorter than MaxMinutes. Use the agent host's background
execution facility to keep the observer alive; do not launch it in a foreground terminal that the host will time out.

## Flow 3: game is already frozen

1. Ask the owner to leave it running until evidence completes. If a watcher exists, read its watch.log first.
   Do not start a competing writer in the same folder while dumping.lock exists. Wait for **dumps done** and
   check successful=N/N plus the dump file sizes; failed writes are not valid full captures.
2. If no suitable capture is armed, and the owner authorizes it, observe the existing process explicitly:

   ```powershell
   powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File .\scripts\hang_dump.ps1 -OutDir 'D:\Evidence\frozen-01' -IncludeExisting -StartAfterSeconds 0 -QuietSeconds 45 -Dumps 2
   ```

   Add `-ProcessId 1234` with the actual PID if there is more than one game process. IncludeExisting bypasses
   only the recent-launch filter; it does **not** bypass the unresponsive-window/quiet-heartbeat requirement.
   Background heartbeat spam may prevent capture; select appropriate HeartbeatFiles rather than claiming no hang.
3. Once writes finish, copy live logs before any restart:

   ```powershell
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\snapshot_live_logs.ps1 -OutDir 'D:\Evidence\frozen-01' -SinceMinutes 60
   ```

   Only then report completion to the owner. This kit never closes the game; the owner decides what to do next.

## Reading dumps offline

```powershell
python .\readers\dump_triage.py 'D:\Evidence\frozen-01\sample.dmp' --threads
python .\readers\dump_unwind.py 'D:\Evidence\frozen-01\sample.dmp' --thread 1234 --regs
# Optional location hints, for example when a dump was moved from another installation:
python .\readers\dump_triage.py 'D:\Evidence\frozen-01\sample.dmp' --threads --game-dir 'D:\Games\Skyrim' --mo2-root 'D:\Modding\MO2'
```

SkyrimSE.exe/SkyrimVR.exe module version and module addresses come from the dump, never a hard-coded runtime.
`--addrlib <BIN>` selects an explicit database. Otherwise the readers search the game's Data/SKSE/Plugins,
MO2 mods/*/SKSE/Plugins under `--mo2-root`, and locations inferred from dump module paths/current directory.
For AE the expected name is `versionlib-<four-version-components>.bin`; SE 1.5.97 uses
`version-1-5-97-0.bin`. **This release decodes only AE 1.6.x format-2 IDs. SE/VR frames remain module+RVA,**
with a clear notice; the capture and stack readers still operate. No database is downloaded. Missing, invalid
or mismatched databases produce an explicit message and RVA-only output. IDs labelled nearest are approximate.

The scanner may include stale stack pointers; an unwind is more informative but can be incomplete. Module
files must match the dump's build. Without local DLL/EXE/PDB files, symbol names and reliable unwind checks
are limited. On a different PC provide matching module copies at the recorded paths (or restore the original
layout); --game-dir/--mo2-root are **Address Library search hints**, not a complete arbitrary module-path mapper.
The oldest thread is labelled a main-thread **candidate**, not definitive proof of ownership.

`dump_unwind.py --exe-image IMAGE.bin` is optional. It expects an offline **PE memory-layout** image: PE headers
at offset zero and sections at their RVAs, not a raw EXE file. An owner-provided offline debugger export, or
reconstruction from captured full-dump memory ranges using PE section RVAs, can supply one. This kit does not
include that reconstruction tool. No live debugger attachment is required or authorized by this guide.
Without it, on-disk unwind metadata may work even if code is encrypted/patched, but instruction-based call-site
checks are uncertain. Images from another launch can contain different detours and must not be treated as exact.

Small dumps usually contain thread stacks and selected referenced memory, not every heap object. Missing
memory is a limit on evidence, not proof of a null pointer. Full dumps permit deeper object/lock analysis but
can also omit unreadable regions. Neither reader fully automates C++ heap ownership or validates every unwind
opcode, exception epilogue or dynamically generated-code frame; treat gaps and uncertain frames accordingly.

## Generic freeze shapes — hypotheses to test

- **Worker spinning in an allocator:** a worker stays in an allocation/free-list routine while its CPU time
  grows across captures. A self-referential list can loop. Stack scans alone do not prove corruption or its source.
- **GPU driver fault:** nvlddmkm/Display events near freeze onset can accompany endless GPU waits. Correlate
  event timestamps and multiple thread stacks; a nonzero event count alone is not a diagnosis.
- **Main thread waiting on a spin lock owned by an idle worker:** repeated main-thread frames and a captured
  lock word may identify a blocked object while the alleged owner is idle. For example, a runtime face build
  can leak a BSDynamicTriShape lock if FaceGen is missing. Verify the actual lock/object/owner, inspect that
  actor's assets and test the hypothesis; the shape is not proof that every similar freeze has that cause.

Compare multiple captures: unchanged stacks suggest a wait, changing stacks suggest work or a loop; use CPU
times and available object memory to discriminate. Do not name a mod as the cause from a single nearest-ID
frame. Save an evidence summary with timestamps, dump hashes, matching runtime/module versions, uncertainty,
and reproducible next checks in the owner's chosen case directory. There is no required repository or session.
