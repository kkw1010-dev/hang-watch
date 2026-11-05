"""hang-watch 1.0.0 - Read-only Windows x64 minidump triage for Skyrim SE/AE/VR.

Requires Python 3.10+ and pefile. Stack scanning may include stale return addresses;
use dump_unwind.py for an attempted unwind. Symbols are optional: matching local PDBs
and local exports only, no symbol downloads. AE Address Library IDs are optional;
SE 1.5.97 and VR use module+RVA output. Game version is read from the dump module.
"""
import argparse
import bisect
import collections
import ctypes
import ctypes.wintypes as W
import datetime as dt
import mmap
import os
import struct
import sys

import pefile
from address_library import load_ids, add_arguments, ENGINE_NAMES

VERSION = "1.0.0"
CODES = {0xC0000005: "ACCESS_VIOLATION", 0xC00000FD: "STACK_OVERFLOW", 0xE06D7363: "C++ exception",
         0xC0000409: "STACK_BUFFER_OVERRUN / fail-fast", 0x80000003: "BREAKPOINT", 0xC0000374: "HEAP_CORRUPTION"}


class Dump:
    def __init__(self, path):
        self.f = open(path, "rb")
        self.m = mmap.mmap(self.f.fileno(), 0, access=mmap.ACCESS_READ)
        sig, _ver, n, rva, _cks, self.time, self.flags = struct.unpack_from("<IIIIIIQ", self.m, 0)
        if sig != 0x504D444D:
            sys.exit("not a minidump")
        self.streams = {}
        for i in range(n):
            t, sz, r = struct.unpack_from("<III", self.m, rva + 12 * i)
            self.streams.setdefault(t, []).append((sz, r))
        self.mem = []
        if 9 in self.streams:  # Memory64ListStream
            _sz, r = self.streams[9][0]
            cnt, off = struct.unpack_from("<QQ", self.m, r)
            for i in range(cnt):
                va, dsz = struct.unpack_from("<QQ", self.m, r + 16 + 16 * i)
                self.mem.append((va, dsz, off))
                off += dsz
        if 5 in self.streams:  # MemoryListStream
            _sz, r = self.streams[5][0]
            cnt, = struct.unpack_from("<I", self.m, r)
            for i in range(cnt):
                va, dsz, drva = struct.unpack_from("<QII", self.m, r + 4 + 16 * i)
                self.mem.append((va, dsz, drva))
        self.mem.sort()
        self.memkeys = [b for b, _, _ in self.mem]
        self.modules = []
        _sz, r = self.streams[4][0]
        cnt, = struct.unpack_from("<I", self.m, r)
        for i in range(cnt):
            o = r + 4 + 108 * i
            base, size, _cks, ts, namerva = struct.unpack_from("<QIIII", self.m, o)
            nlen, = struct.unpack_from("<I", self.m, namerva)
            path = self.m[namerva + 4: namerva + 4 + nlen].decode("utf-16le")
            fv = struct.unpack_from("<IIIIII", self.m, o + 24)
            ver = "%d.%d.%d.%d" % (fv[2] >> 16, fv[2] & 0xFFFF, fv[3] >> 16, fv[3] & 0xFFFF)
            self.modules.append((base, size, path, ver, ts))
        self.modules.sort()
        self.modkeys = [b for b, *_ in self.modules]

    def read(self, va, n):
        i = bisect.bisect_right(self.memkeys, va) - 1
        if i < 0:
            return None
        base, size, off = self.mem[i]
        if not base <= va < base + size:
            return None
        k = min(n, base + size - va)
        return bytes(self.m[off + va - base: off + va - base + k])

    def q(self, va):
        b = self.read(va, 8)
        return struct.unpack("<Q", b)[0] if b and len(b) == 8 else None

    def module(self, va):
        i = bisect.bisect_right(self.modkeys, va) - 1
        if i >= 0 and self.modules[i][0] <= va < self.modules[i][0] + self.modules[i][1]:
            return self.modules[i]
        return None

    def threads(self):
        _sz, r = self.streams[3][0]
        cnt, = struct.unpack_from("<I", self.m, r)
        for i in range(cnt):
            tid, _s, _p, _c, teb, sstart, ssz, _srva, _csz, crva = struct.unpack_from("<IIIIQQIIII", self.m, r + 4 + 48 * i)
            yield dict(tid=tid, teb=teb, stack=sstart, stacksize=ssz, ctx=crva)

    def context(self, rva):
        names = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip"]
        return dict(zip(names, struct.unpack_from("<17Q", self.m, rva + 0x78)))

    def process_start(self):
        if 15 not in self.streams:
            return None
        _sz, r = self.streams[15][0]
        flags, _pid, create = struct.unpack_from("<III", self.m, r + 4)
        return create if flags & 2 else None


class Symbols:
    """Names for addresses: Address Library IDs for SkyrimSE.exe, PDBs next to DLLs, exports otherwise."""

    def __init__(self, dump, addrlib=None, game_dir=None, mo2_root=None):
        self.d = dump
        self.addrlib, self.game_dir, self.mo2_root = addrlib, game_dir, mo2_root
        self.pe = {}
        self.ids = None
        self.dbg = None
        self.loaded = set()

    def _pe(self, path):
        if path not in self.pe:
            try:
                p = pefile.PE(path, fast_load=True)
                p.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXCEPTION"],
                                                      pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
                funcs = sorted((e.struct.BeginAddress, e.struct.EndAddress) for e in getattr(p, "DIRECTORY_ENTRY_EXCEPTION", []))
                exports = []
                if hasattr(p, "DIRECTORY_ENTRY_EXPORT"):
                    exports = sorted((e.address, (e.name or b"?").decode()) for e in p.DIRECTORY_ENTRY_EXPORT.symbols)
                text = [(s.VirtualAddress, s.VirtualAddress + s.Misc_VirtualSize) for s in p.sections if s.Characteristics & 0x20000000]
                self.pe[path] = dict(funcs=funcs, fstarts=[a for a, _ in funcs], exports=exports, text=text,
                                     ts=p.FILE_HEADER.TimeDateStamp)
                p.close()
            except (OSError, pefile.PEFormatError):
                self.pe[path] = None
        return self.pe[path]

    def is_code(self, va):
        mod = self.d.module(va)
        if not mod:
            return False
        info = self._pe(mod[2])
        if info is None:
            return True
        rva = va - mod[0]
        return any(a <= rva < b for a, b in info["text"])

    def _addrlib(self):
        if self.ids is None:
            self.ids = {}
            self.ids = load_ids(self.d, self.addrlib, self.game_dir, self.mo2_root)
            self.idoffs = sorted(self.ids)
        return self.ids

    def _dbghelp(self, mod):
        if self.dbg is None:
            self.dbg = ctypes.WinDLL("dbghelp.dll", winmode=0x00000800)
            self.h = ctypes.c_void_p(0x5EED)
            self.dbg.SymSetOptions(0x2 | 0x4 | 0x10)
            self.dbg.SymInitializeW.argtypes = [ctypes.c_void_p, W.LPCWSTR, W.BOOL]
            self.dbg.SymInitializeW(self.h, None, False)
            self.dbg.SymLoadModuleExW.restype = ctypes.c_uint64
            self.dbg.SymLoadModuleExW.argtypes = [ctypes.c_void_p, W.HANDLE, W.LPCWSTR, W.LPCWSTR, ctypes.c_uint64, W.DWORD, ctypes.c_void_p, W.DWORD]
            self.dbg.SymSetSearchPathW.argtypes = [ctypes.c_void_p, W.LPCWSTR]
        base, size, path = mod[0], mod[1], mod[2]
        if base not in self.loaded:
            self.loaded.add(base)
            pdb = os.path.splitext(path)[0] + ".pdb"
            if not os.path.isfile(pdb):
                return False
            self.dbg.SymSetSearchPathW(self.h, os.path.dirname(path))
            self.dbg.SymLoadModuleExW(self.h, None, path, None, base, size, None, 0)
            self.pdb = getattr(self, "pdb", set()) | {base}
        return base in getattr(self, "pdb", set())

    def _pdbname(self, va):
        class SYMBOL_INFOW(ctypes.Structure):
            _fields_ = [("SizeOfStruct", W.ULONG), ("TypeIndex", W.ULONG), ("Reserved", ctypes.c_uint64 * 2), ("Index", W.ULONG),
                        ("Size", W.ULONG), ("ModBase", ctypes.c_uint64), ("Flags", W.ULONG), ("Value", ctypes.c_uint64),
                        ("Address", ctypes.c_uint64), ("Register", W.ULONG), ("Scope", W.ULONG), ("Tag", W.ULONG),
                        ("NameLen", W.ULONG), ("MaxNameLen", W.ULONG), ("Name", ctypes.c_wchar * 1024)]

        class LINE(ctypes.Structure):
            _fields_ = [("SizeOfStruct", W.DWORD), ("Key", ctypes.c_void_p), ("LineNumber", W.DWORD), ("FileName", W.LPWSTR), ("Address", ctypes.c_uint64)]
        si = SYMBOL_INFOW()
        si.SizeOfStruct = 88
        si.MaxNameLen = 1024
        disp = ctypes.c_uint64()
        out = ""
        # va - 1: a return address belongs to the call instruction before it
        if self.dbg.SymFromAddrW(self.h, ctypes.c_uint64(va - 1), ctypes.byref(disp), ctypes.byref(si)):
            out = "%s+0x%X" % (si.Name, disp.value + 1)
        ln = LINE()
        ln.SizeOfStruct = ctypes.sizeof(LINE)
        d2 = W.DWORD()
        if self.dbg.SymGetLineFromAddrW64(self.h, ctypes.c_uint64(va - 1), ctypes.byref(d2), ctypes.byref(ln)) and ln.FileName:
            out += "  [%s:%d]" % (os.path.basename(ln.FileName), ln.LineNumber)
        return out

    def name(self, va):
        mod = self.d.module(va)
        if not mod:
            return "0x%X" % va
        base, _size, path = mod[0], mod[1], mod[2]
        short = os.path.basename(path)
        rva = va - base
        head = "%s+0x%X" % (short, rva)
        info = self._pe(path)
        if short.lower() in ENGINE_NAMES:
            ids = self._addrlib()
            if ids and info:
                k = bisect.bisect_right(info["fstarts"], rva) - 1
                if k >= 0 and info["funcs"][k][0] <= rva < info["funcs"][k][1] and info["funcs"][k][0] in ids:
                    fs = info["funcs"][k][0]
                    return "%s  -> %d+0x%X" % (head, ids[fs], rva - fs)
                j = bisect.bisect_right(self.idoffs, rva) - 1
                if j >= 0:
                    return "%s  ~> %d+0x%X (nearest ID)" % (head, ids[self.idoffs[j]], rva - self.idoffs[j])
            return head
        if self._dbghelp(mod):
            n = self._pdbname(va)
            if n:
                return "%s  %s" % (head, n)
        if info and info["exports"]:
            k = bisect.bisect_right([a for a, _ in info["exports"]], rva) - 1
            if k >= 0:
                a, n = info["exports"][k]
                return "%s  (%s+0x%X, nearest export)" % (head, n, rva - a)
        return head


def thread_infos(d):
    """ThreadInfoListStream (17): create time, user / kernel time, start address per thread id"""
    out = {}
    if 17 not in d.streams:
        return out
    _sz, r = d.streams[17][0]
    hsz, esz, cnt = struct.unpack_from("<III", d.m, r)
    for i in range(cnt):
        o = r + hsz + esz * i
        tid, _fl, _err, _ex, create, _exit, kern, user, start = struct.unpack_from("<IIIIQQQQQ", d.m, o)
        out[tid] = dict(create=create, kernel=kern / 1e7, user=user / 1e7, start=start)
    return out


def thread_names(d):
    """ThreadNamesStream (24), when the dump writer stored it"""
    out = {}
    if 24 not in d.streams:
        return out
    _sz, r = d.streams[24][0]
    cnt, = struct.unpack_from("<I", d.m, r)
    for i in range(cnt):
        tid, nrva = struct.unpack_from("<IQ", d.m, r + 4 + 12 * i)
        n, = struct.unpack_from("<I", d.m, nrva)
        out[tid] = d.m[nrva + 4:nrva + 4 + n].decode("utf-16le", "replace")
    return out


def all_threads(d, s, depth, only=None):
    """A freeze dump has no exception: show every thread's rip and the code pointers on its stack, oldest
    thread first (the oldest is a main-thread candidate; confirm with its frames)."""
    infos = thread_infos(d)
    names = thread_names(d)
    ths = sorted(d.threads(), key=lambda t: infos.get(t["tid"], {}).get("create", 0))
    print("\n%d THREADS (oldest first; user/kernel = CPU seconds used so far)" % len(ths))
    for n, th in enumerate(ths):
        if only and th["tid"] not in only:
            continue
        ctx = d.context(th["ctx"])
        info = infos.get(th["tid"], {})
        label = names.get(th["tid"], "")
        if n == 0:
            label = (label + " " if label else "") + "<- main-thread candidate (oldest)"
        print("\n== thread %d %s  user %.1f s kernel %.1f s  start %s" % (
            th["tid"], label, info.get("user", 0), info.get("kernel", 0), s.name(info["start"]) if info.get("start") else "?"))
        print("   rip %s" % s.name(ctx["rip"]))
        if "rml::internal" in s.name(ctx["rip"]):
            # A thread whose instruction pointer is inside tbbmalloc in a hang dump is almost always walking a corrupt
            # free list: repeated dumps and CPU-time deltas are needed to distinguish a loop from a transient allocation.
            print("   !! ALLOCATOR LOOP? rip is inside an allocator; compare this thread's CPU time across the"
                  " dumps (rising = spinning) and its registers (a free-list link equal to its own address = self-loop)")
        rsp = ctx["rsp"]
        top = th["stack"] + th["stacksize"]
        data = d.read(rsp, max(0, min(0x8000, top - rsp))) if top > rsp else None
        if not data:
            print("   (stack memory not in the dump)")
            continue
        shown = 0
        for i in range(0, len(data) - 7, 8):
            v = struct.unpack_from("<Q", data, i)[0]
            if v > 0x10000 and d.module(v) and s.is_code(v):
                print("   %X  %s" % (rsp + i, s.name(v)))
                shown += 1
                if shown >= depth:
                    break


def gpu_events(start, end):
    """Display-driver events in the System log between two epoch times. A GPU fault (nvlddmkm Xid 13 "Graphics SM
    Warp Exception ... MMU NACK") or a TDR stops every D3D11 query from completing, and the engine's own GPU waits
    then sleep and retry forever: the process freezes with nothing in any game log. Correlation is not proof of the cause."""
    import subprocess
    iso = lambda t: dt.datetime.fromtimestamp(t, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    q = ("*[System[(Provider[@Name='nvlddmkm'] or Provider[@Name='Display'] or Provider[@Name='amdkmdag'])"
         " and TimeCreated[@SystemTime>='%s' and @SystemTime<='%s']]]" % (iso(start), iso(end)))
    try:
        out = subprocess.run(["wevtutil", "qe", "System", "/q:" + q, "/f:xml", "/c:2000"], capture_output=True,
                             timeout=60).stdout.decode("utf-8", "replace")
    except (OSError, subprocess.TimeoutExpired) as e:
        return ["(System log not read: %s)" % e]
    import re
    events = re.findall(r"<Event .*?</Event>", out, re.S)
    texts = collections.Counter()
    first = None
    for e in events:
        t = re.search(r"SystemTime='([^']+)'", e)
        if t and first is None:
            first = t.group(1)
        datas = re.findall(r"<Data>(.*?)</Data>", e, re.S)
        msg = datas[1] if len(datas) > 1 else (datas[0] if datas else "?")
        texts[re.sub(r"\(GPC \d+, TPC \d+, SM \d+\)|0x[0-9a-fA-F]+=0x[0-9a-fA-F]+", "", msg).strip()] += 1
    if not events:
        return ["none between process start and the dump (no GPU fault or TDR logged by the driver)"]
    lines = ["%d events, first at %s (UTC):" % (len(events), first)]
    lines += ["  %4dx %s" % (c, m[:140]) for m, c in texts.most_common(8)]
    return lines


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dump")
    ap.add_argument("--frames", type=int, default=40)
    ap.add_argument("--threads", action="store_true", help="every thread (freeze dumps, which have no exception)")
    ap.add_argument("--tid", type=int, action="append", help="with --threads: only these thread ids")
    add_arguments(ap)
    args = ap.parse_args()
    d = Dump(args.dump)
    s = Symbols(d, args.addrlib, args.game_dir, args.mo2_root)
    print("dump written: %s" % dt.datetime.fromtimestamp(d.time))
    start = d.process_start()
    if start:
        up = d.time - start
        print("process start: %s (uptime %d:%02d)" % (dt.datetime.fromtimestamp(start), up // 60, up % 60))
    if args.threads or 6 not in d.streams:
        if 6 not in d.streams:
            print("no exception stream: a freeze / hang dump; listing every thread")
            print("GPU DRIVER EVENTS (System log, this process's lifetime):")
            for ln in gpu_events(start or d.time - 3600, d.time):
                print("  " + ln)
            print("the stacks below are a scan; for the main thread's real call chain run")
            print("  python readers/dump_unwind.py <dump> --thread <main tid> --exe-image <SkyrimSE memory image>")
        all_threads(d, s, min(args.frames, 24), set(args.tid) if args.tid else None)
        return
    _sz, r = d.streams[6][0]
    tid, = struct.unpack_from("<I", d.m, r)
    code, _fl, _rec, addr, np_ = struct.unpack_from("<IIQQI", d.m, r + 8)
    params = struct.unpack_from("<15Q", d.m, r + 8 + 32)[:np_]
    _csz, crva = struct.unpack_from("<II", d.m, r + 8 + 152)
    ctx = d.context(crva)
    print("\nEXCEPTION 0x%08X %s on thread %d at %s" % (code, CODES.get(code, ""), tid, s.name(addr)))
    if code == 0xC0000005 and len(params) >= 2:
        print("  %s of 0x%X" % ({0: "read", 1: "write", 8: "execute"}.get(params[0], "access"), params[1]))
    print("  " + " ".join("%s=%X" % kv for kv in ctx.items()))
    th = next(t for t in d.threads() if t["tid"] == tid)
    base, limit, dealloc = d.q(th["teb"] + 8), d.q(th["teb"] + 0x10), d.q(th["teb"] + 0x1478)
    rsp = ctx["rsp"]
    print("\nSTACK base %X, limit %X, reserve bottom %X; rsp %X" % (base, limit, dealloc, rsp))
    exhausted = limit is not None and dealloc is not None and rsp < limit + 0x2000
    if exhausted:
        print("  STACK EXHAUSTED: rsp is %d bytes above the reserve bottom. An earlier STATUS_STACK_OVERFLOW happened on"
              " this thread;\n  the dump's exception is likely a crash handler faulting on the same stack." % (rsp - dealloc))
    lo = min(rsp, limit or rsp)
    data = d.read(lo, base - lo) or d.read(limit, base - limit)
    for ln in (0x10000, 0x4000, 0x1000):  # partial dumps: take what is mapped just above rsp
        if data is None and base > rsp:
            data = d.read(rsp, min(ln, base - rsp))
    if data is None:
        print("\nSTACK MEMORY NOT IN THIS DUMP (no frames can be scanned); exception and registers above are all it holds.")
        return
    lo = base - len(data)
    print("\nEARLIER EXCEPTION RECORDS ON THIS STACK")
    for c in CODES:
        needle = struct.pack("<I", c)
        i = data.find(needle)
        while i >= 0:
            if i + 24 <= len(data):
                fl, nrec, eaddr = struct.unpack_from("<IQQ", data, i + 4)
                if fl in (0, 1) and d.module(eaddr) and eaddr != addr:
                    print("  0x%08X %s at %s (record at %X)" % (c, CODES[c], s.name(eaddr), lo + i))
            i = data.find(needle, i + 4)
    frames = []
    for i in range(0, len(data) - 7, 8):
        v = struct.unpack_from("<Q", data, i)[0]
        if v > 0x10000 and d.module(v) and s.is_code(v):
            frames.append((lo + i, v))
    cnt = collections.Counter(v for _, v in frames)
    print("\nMOST REPEATED CODE POINTERS (%d candidates)" % len(frames))
    for v, c in cnt.most_common(20):
        if c < 3:
            break
        print("  %5d  %s" % (c, s.name(v)))
    print("\nINNERMOST %d (top of stack first; a scan, may include stale values)" % args.frames)
    for a, v in frames[:args.frames]:
        print("  %X  %s" % (a, s.name(v)))
    print("\nOUTERMOST %d" % args.frames)
    for a, v in frames[-args.frames:]:
        print("  %X  %s" % (a, s.name(v)))


if __name__ == "__main__":
    main()
