"""hang-watch 1.0.0 - Optional AE Address Library lookup, never a requirement for RVA output."""
import pathlib
import struct
import sys

ENGINE_NAMES = {"skyrimse.exe", "skyrimvr.exe"}

def engine_module(dump):
    return next((m for m in dump.modules if pathlib.Path(m[2]).name.lower() in ENGINE_NAMES), None)

def add_arguments(parser):
    parser.add_argument("--addrlib", metavar="BIN", help="matching Address Library database (AE IDs only; SE/VR keep RVAs)")
    parser.add_argument("--game-dir", metavar="DIR", help="local game folder; search Data/SKSE/Plugins and locate module copies")
    parser.add_argument("--mo2-root", metavar="DIR", help="optional MO2 instance; search mods/*/SKSE/Plugins for the matching database")

def expected_name(version):
    if version[:3] == (1, 5, 97):
        return "version-" + "-".join(map(str, version)) + ".bin"
    if version[:2] == (1, 6):
        return "versionlib-" + "-".join(map(str, version)) + ".bin"
    return None

def read_ae(path, version):
    data = pathlib.Path(path).read_bytes()
    pos = 0
    def rd(fmt):
        nonlocal pos
        value = struct.unpack_from(fmt, data, pos)[0]
        pos += struct.calcsize(fmt)
        return value
    if rd("<i") != 2:
        raise ValueError("unsupported database format; only AE format 2 IDs are decoded")
    actual = tuple(rd("<i") for _ in range(4))
    if actual != tuple(version):
        raise ValueError("database version %s does not match dump module %s" % (actual, version))
    name_len = rd("<i")
    if not 0 <= name_len <= 4096 or pos + name_len + 8 > len(data):
        raise ValueError("invalid executable-name length")
    pos += name_len
    pointer_size, count = rd("<i"), rd("<i")
    if pointer_size != 8 or not 0 <= count <= len(data) - pos:
        raise ValueError("invalid pointer size or entry count")
    previous_id = previous_offset = 0
    ids = {}
    def delta(kind, previous):
        if kind == 0: return rd("<Q")
        if kind == 1: return previous + 1
        if kind == 2: return previous + rd("<B")
        if kind == 3: return previous - rd("<B")
        if kind == 4: return previous + rd("<H")
        if kind == 5: return previous - rd("<H")
        if kind == 6: return rd("<H")
        if kind == 7: return rd("<I")
        raise ValueError("invalid ID encoding")
    for _ in range(count):
        tag = rd("<B")
        key = delta(tag & 15, previous_id)
        high = tag >> 4
        offset = delta(high & 7, previous_offset // pointer_size if high & 8 else previous_offset)
        if high & 8: offset *= pointer_size
        if key < 0 or offset < 0: raise ValueError("negative ID or offset")
        ids.setdefault(offset, key)
        previous_id, previous_offset = key, offset
    if pos != len(data):
        raise ValueError("database has unexpected trailing bytes")
    return ids

def load_ids(dump, explicit=None, game_dir=None, mo2_root=None):
    mod = engine_module(dump)
    def note(message): print("Address Library: " + message, file=sys.stderr)
    if mod is None:
        note("no SkyrimSE.exe/SkyrimVR.exe module; using module+RVA only")
        return {}
    try: version = tuple(int(x) for x in mod[3].split("."))
    except ValueError:
        note("unknown game module version; using module+RVA only")
        return {}
    if len(version) != 4:
        note("game module version is not four components; using module+RVA only")
        return {}
    filename = expected_name(version)
    if version[:2] != (1, 6) or pathlib.Path(mod[2]).name.lower() == "skyrimvr.exe":
        note("dump game version %s; only AE 1.6.x format-2 IDs are supported. SE 1.5.97 uses %s; SE/VR frames remain module+RVA." % (mod[3], filename or "a different database format"))
        return {}
    games = [pathlib.Path(game_dir)] if game_dir else []
    games.append(pathlib.Path(mod[2]).parent)
    roots = [pathlib.Path(mo2_root)] if mo2_root else []
    roots += [pathlib.Path.cwd(), pathlib.Path(dump.f.name).resolve().parent]
    for _, _, path, *_ in dump.modules:
        for parent in pathlib.Path(path).parents:
            if parent.name.lower() == "mods": roots.append(parent.parent)
    for game in games: roots.extend([game, game.parent])
    candidates = [pathlib.Path(explicit)] if explicit else []
    if not explicit:
        candidates += [g / "Data/SKSE/Plugins" / filename for g in games]
        for root in dict.fromkeys(roots):
            candidates += sorted((root / "mods").glob("*/SKSE/Plugins/" + filename))
    available = [p for p in dict.fromkeys(candidates) if p.is_file()]
    if not available:
        note("matching %s not found; use --addrlib, --game-dir or --mo2-root. Continuing with module+RVA." % filename)
        return {}
    for path in available:
        try:
            ids = read_ae(path, version)
            note("loaded %d offsets from %s (game %s)" % (len(ids), path, mod[3]))
            return ids
        except (OSError, ValueError, struct.error) as exc:
            note("%s: %s" % (path, exc))
    note("no usable matching database; continuing with module+RVA")
    return {}
