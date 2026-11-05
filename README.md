# hang-watch 1.0.0

A Windows freeze-capture and offline dump-reading kit for Skyrim SE/AE players. When the game freezes (the window stops
responding and the logs go quiet), it writes memory dumps of the still-running game and keeps the session's Papyrus and
SKSE logs, so the freeze can be read afterwards. Works with MO2 or Vortex; no specific mod is required.

It is written to be run by an AI agent assisting you: give your agent [AGENT.md](AGENT.md) and tell it what evidence you
allow it to collect. You can also run the scripts yourself; AGENT.md has the commands.

## Real cases

Freezes the author solved from hang-watch dumps:

- **Freeze a few seconds after leaving a busy cell.** The dumps showed the main thread waiting for its frame's job
  list, and one worker thread spinning forever inside the memory allocator on a free-list entry that pointed to
  itself: heap corruption (a double free), not a deadlock. A follow-up run with an allocation-checking tool caught the
  writer: a third-party plugin rewriting one shared string from several worker threads at once. Fix: a small patch
  that removes those two unsafe writes; that freeze has not come back.
- **Freeze on the first frame after loading into an inn.** Small dumps showed the main thread sleeping on a mesh's
  spin lock held by an idle worker thread: a job had leaked the lock. A full-memory dump then named the mesh: a head
  part of one NPC whose face was being built at runtime, because an NPC appearance mod had been installed under a
  renamed plugin, so its prebuilt face archive no longer loaded. Fix: make the archive load with the plugin; the faces
  are no longer built at runtime.

## Requirements

- Windows with **Windows PowerShell 5.1** (built in) for capturing.
- **Python 3.10+** and `python -m pip install pefile` for the offline readers only.

## What it does not do

- It never launches, closes, suspends or injects into the game, and changes no game, mod or mod manager settings.
- It writes only to the output folder you choose (by default `hang-watch-runs` next to this folder).

## Privacy

- **Nothing is uploaded automatically.** Logs and dumps stay on your PC until you decide to share them.
- Dumps and logs can contain personal data: folder paths with your user name, text you typed, account names, and in a
  full dump anything the game had in memory. Review them before sharing, and share small dumps rather than full ones
  when that is enough.
- Full dumps (`-FullMemory`) can be tens of GB each. The scripts check free space first.

## Antivirus note

Writing a memory dump from PowerShell (dbghelp MiniDumpWriteDump) from a hidden watcher can look like credential
dumping to antivirus heuristics. hang-watch only ever dumps the game process it is watching (SkyrimSE, or SkyrimVR;
another name only if you pass `-ProcessName`) and uploads nothing. If Defender flags it, read the scripts first (they
are plain text in `scripts\`); if you trust them, allow this one folder.

## License

MIT License - see [LICENSE](LICENSE).
