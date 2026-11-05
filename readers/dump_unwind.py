r"""hang-watch 1.0.0 - Attempted call chain of the faulting thread of a Windows crash dump, by x64 unwind data (.pdata / UNWIND_INFO).

Usage:
  python readers/dump_unwind.py <SkyrimSE.exe.NNNN.dmp> [--exe-image IMAGE.bin] [--thread TID] [--frames 60] [--slots N]

dump_triage.py scans the stack for anything that looks like a code pointer, so it also lists stale values left by
calls that already returned. This tool walks the frames the way the OS unwinder does: for the function that
contains the instruction pointer it reads the unwind codes (pushes, stack allocation, frame pointer, saved
registers), undoes them, and takes the return address from where the stack pointer then is. Every frame it prints
is therefore a function that was really waiting for the one below it to return, provided the unwind data of each
module was found; a frame where it was not is marked.

Each return address is also checked against the code: the bytes before it must be a call instruction, and for a
direct call (E8) the target is named, so "frame N was called by the call at this address" can be read off.

Unwind data comes from matching module files on disk. An encrypted or patched executable
may not expose the original runtime call instructions. --exe-image is OPTIONAL: it accepts
a PE memory-layout image (headers at zero, sections at their RVAs), obtained from an offline
full-dump extraction or an owner-provided debugger export. A raw executable file is not a
memory image. Do not attach to a running game to obtain one as part of this kit. An image
from a different run may have different detours; uncertain frames must remain labelled.
Without an image, unwind metadata may still work, but call-site checks can be inconclusive.

--slots N prints N stack slots (8 bytes each) above every frame's stack pointer, with a name for values that
point into a module: the saved registers, home space and locals the frame holds.
--regs prints, for every frame, the callee-saved registers as that function had them when it made its call
(rbx rbp rsi rdi r12-r15, restored from where the functions below saved them): the function's own long-lived
variables, e.g. its `this` or a loop index, readable from the function's disassembly.

When a return address is not inside any module (code generated at run time, or a module the dump does not
list), the frame of that code cannot be undone. The walk then looks further up the stack for the next return
address from which the walk holds for three more frames, prints how many bytes it skipped, and goes on; the
callee-saved registers are no longer exact after such a gap.
"""
import argparse
import bisect
import os
import struct
import sys

import pefile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dump_triage as dt

REG = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
RSP = 4
EXTRA = [0, 1, 0, 0, 1, 2, 1, 2, 1, 2, 0, 2]  # extra slots per unwind op (ALLOC_LARGE: 1 or 2, see below)


class Image:
    """Bytes of one module laid out by RVA, and its RUNTIME_FUNCTION table."""

    def __init__(self, path, raw=None):
        self.path, self.ok, self.note = path, False, ""
        try:
            if raw is not None:
                self.img = raw
                pe = pefile.PE(data=bytes(raw[:0x1000]), fast_load=True)
                self.note = "memory image"
            else:
                pe = pefile.PE(path, fast_load=True)
                self.img = pe.get_memory_mapped_image()
            d = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXCEPTION"]]
            self.ts = pe.FILE_HEADER.TimeDateStamp
            self.funcs = []
            for off in range(d.VirtualAddress, d.VirtualAddress + d.Size - 11, 12):
                b, e, u = struct.unpack_from("<III", self.img, off)
                if b or e:
                    self.funcs.append((b, e, u))
            self.funcs.sort()
            self.starts = [f[0] for f in self.funcs]
            self.ok = True
        except (OSError, pefile.PEFormatError, struct.error) as ex:
            self.note = "unwind data not readable: %s" % ex

    def func(self, rva):
        i = bisect.bisect_right(self.starts, rva) - 1
        if i >= 0 and self.funcs[i][0] <= rva < self.funcs[i][1]:
            return self.funcs[i]
        return None

    def u8(self, rva):
        return self.img[rva]

    def u16(self, rva):
        return struct.unpack_from("<H", self.img, rva)[0]

    def u32(self, rva):
        return struct.unpack_from("<I", self.img, rva)[0]


def unwind_one(img, func, rva, regs, readq, log, unknown=None):
    """Undo one function's prologue. regs is changed in place; returns False when memory was missing.

    unknown: numbers of callee-saved registers whose value was lost (after a gap). A frame register that is
    unknown is not used: the frame is then assumed to have no dynamic stack allocation, which is the usual case.
    """
    unknown = unknown if unknown is not None else set()
    begin, _end, ui = func
    first = True
    while True:
        while ui & 1:                       # the entry points at another RUNTIME_FUNCTION
            begin, _end, ui = struct.unpack_from("<III", img.img, ui & ~1)
        vf = img.u8(ui)
        version, flags = vf & 7, vf >> 3
        prolog, count, fr = img.u8(ui + 1), img.u8(ui + 2), img.u8(ui + 3)
        freg, foff = fr & 15, fr >> 4
        off = rva - begin if first else 1 << 30
        in_prolog = first and 0 <= off < prolog
        codes = ui + 4
        # frame base: where the fixed part of the frame starts (offsets of saved registers count from it)
        base = regs[RSP]
        if freg:
            use_fp = not in_prolog
            if in_prolog:                   # the frame register counts only once its own instruction has run
                i = 0
                while i < count:
                    co, op = img.u8(codes + 2 * i), img.u8(codes + 2 * i + 1)
                    if op & 15 == 3 and off >= co:
                        use_fp = True
                    i += 1 + slots(img, codes, i, version)
            if use_fp and freg not in unknown:
                base = regs[freg] - foff * 16
        i = 0
        while i < count:
            co, opb = img.u8(codes + 2 * i), img.u8(codes + 2 * i + 1)
            op, info = opb & 15, opb >> 4
            n = slots(img, codes, i, version)
            if off >= co:
                if op == 0:                                         # PUSH_NONVOL
                    v = readq(regs[RSP])
                    if v is None:
                        return False
                    regs[info] = v
                    unknown.discard(info)
                    regs[RSP] += 8
                elif op == 1:                                       # ALLOC_LARGE
                    size = img.u16(codes + 2 * i + 2) * 8 if info == 0 else img.u32(codes + 2 * i + 2)
                    regs[RSP] += size
                elif op == 2:                                       # ALLOC_SMALL
                    regs[RSP] += info * 8 + 8
                elif op == 3:                                       # SET_FPREG
                    if freg in unknown:
                        log.append("frame register %s unknown: assumed no dynamic stack allocation" % REG[freg])
                    else:
                        regs[RSP] = regs[freg] - foff * 16
                elif op in (4, 5):                                  # SAVE_NONVOL(_FAR)
                    o = img.u16(codes + 2 * i + 2) * 8 if op == 4 else img.u32(codes + 2 * i + 2)
                    v = readq(base + o)
                    if v is None:
                        return False
                    regs[info] = v
                    unknown.discard(info)
                elif op in (8, 9):                                  # SAVE_XMM128(_FAR): not tracked
                    pass
                elif op == 10:                                      # PUSH_MACHFRAME
                    a = regs[RSP] + (8 if info else 0)
                    rip, rsp = readq(a), readq(a + 0x18)
                    if rip is None or rsp is None:
                        return False
                    regs["rip"] = rip
                    regs[RSP] = rsp
                    log.append("machine frame")
                    return True
                elif op in (6, 7) and version == 1:                 # SAVE_XMM (old): not tracked
                    pass
            i += 1 + n
        if flags & 4:                                               # chained: the parent's codes all apply
            j = codes + 2 * ((count + 1) & ~1)
            begin, _end, ui = struct.unpack_from("<III", img.img, j)
            first = False
            log.append("chained")
            continue
        break
    ret = readq(regs[RSP])
    if ret is None:
        return False
    regs["rip"] = ret
    regs[RSP] += 8
    return True


def slots(img, codes, i, version):
    opb = img.u8(codes + 2 * i + 1)
    op, info = opb & 15, opb >> 4
    if op == 1:
        return 1 if info == 0 else 2
    if op == 6:
        return 1
    if op == 7:
        return 2
    return EXTRA[op] if op < len(EXTRA) else 0


def call_before(img, rva, name_of, base):
    """The call instruction that ends at rva, as text; None when the bytes before rva are no call."""
    if img is None or not img.ok or rva < 8 or rva > len(img.img):
        return "?"
    b = img.img
    if b[rva - 5] == 0xE8:
        target = rva + struct.unpack_from("<i", b, rva - 4)[0]
        return "call %s" % name_of(base + target)
    if b[rva - 6] == 0xFF and b[rva - 5] == 0x15:
        slot = rva + struct.unpack_from("<i", b, rva - 4)[0]
        return "call [rip slot +0x%X]" % slot
    for n in (2, 3, 4, 6, 7):
        if b[rva - n] == 0xFF and (b[rva - n + 1] >> 3) & 7 == 2:
            return "call (indirect, %d bytes)" % n
        if n >= 3 and b[rva - n] in (0x41, 0x48, 0x49) and b[rva - n + 1] == 0xFF and (b[rva - n + 2] >> 3) & 7 == 2:
            return "call (indirect, %d bytes)" % n
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dump")
    ap.add_argument("--exe-image", help="optional offline PE memory-layout image, not a raw executable file")
    ap.add_argument("--thread", type=int)
    ap.add_argument("--frames", type=int, default=60)
    ap.add_argument("--slots", type=int, default=0)
    ap.add_argument("--regs", action="store_true")
    dt.add_arguments(ap)
    args = ap.parse_args()
    d = dt.Dump(args.dump)
    s = dt.Symbols(d, args.addrlib, args.game_dir, args.mo2_root)
    images = {}

    def image(mod):
        if mod[0] not in images:
            raw = None
            if args.exe_image and os.path.basename(mod[2]).lower() in dt.ENGINE_NAMES:
                raw = open(args.exe_image, "rb").read()
            images[mod[0]] = Image(mod[2], raw)
        return images[mod[0]]

    etid = None
    if 6 in d.streams:   # a hang dump (hang_dump.ps1) has no exception stream: --thread is then required
        _sz, r = d.streams[6][0]
        etid, = struct.unpack_from("<I", d.m, r)
        code, _fl, _rec, addr, np_ = struct.unpack_from("<IIQQI", d.m, r + 8)
        params = struct.unpack_from("<15Q", d.m, r + 8 + 32)[:np_]
        _csz, crva = struct.unpack_from("<II", d.m, r + 8 + 152)
    elif not args.thread:
        sys.exit("no exception stream (a hang dump): pass --thread TID")
    tid = args.thread or etid
    if tid == etid:
        ctx = d.context(crva)
        print("EXCEPTION 0x%08X on thread %d at %s%s" % (code, tid, s.name(addr), "  (%s of 0x%X)" % (
            {0: "read", 1: "write", 8: "execute"}.get(params[0], "access"), params[1]) if code == 0xC0000005 and len(params) > 1 else ""))
    else:
        th = next(t for t in d.threads() if t["tid"] == tid)
        ctx = d.context(th["ctx"])
        print("thread %d (not the faulting thread)" % tid)
    print("  " + " ".join("%s=%X" % kv for kv in ctx.items()))
    regs = {i: ctx[n] for i, n in enumerate(REG)}
    regs["rip"] = ctx["rip"]

    def name(va):
        return s.name(va)

    unknown = set()

    def step(rg, unk, first):
        """One frame up from rg (changed in place). Returns (ok, notes, return address is call-preceded)."""
        rip_, rsp_ = rg["rip"], rg[RSP]
        mod_ = d.module(rip_)
        log_ = []
        if not mod_:
            return False, ["not in a module"], False
        img_ = image(mod_)
        rva_ = rip_ - mod_[0]
        look_ = rva_ if first else rva_ - 1
        f_ = img_.func(look_) if img_.ok else None
        if f_ is None:
            ret_ = d.q(rsp_)
            if ret_ is None:
                return False, ["stack memory missing"], False
            rg["rip"], rg[RSP] = ret_, rsp_ + 8
            log_.append("no unwind entry" if img_.ok else img_.note)
        elif not unwind_one(img_, f_, look_, rg, d.q, log_, unk):
            return False, ["stack memory missing"], False
        rm = d.module(rg["rip"])
        c_ = call_before(image(rm), rg["rip"] - rm[0], name, rm[0]) if rm else None
        return True, log_, bool(rm and c_)

    def resync(rsp_from, base):
        """Lowest stack slot holding a return address from which the walk reaches the thread's start routine with
        every return address preceded by a call. Stale return addresses left by finished calls do not pass that."""
        a = rsp_from
        while a < base:
            v = d.q(a)
            if v is None:
                return None
            rm = d.module(v)
            if rm and s.is_code(v) and call_before(image(rm), v - rm[0], name, rm[0]):
                trial, unk = dict(regs), {3, 5, 6, 7, 12, 13, 14, 15}
                trial["rip"], trial[RSP] = v, a + 8
                for _ in range(120):
                    if "RtlUserThreadStart" in name(trial["rip"]):
                        return a
                    ok_, _l, pre = step(trial, unk, False)
                    if not ok_ or not pre:
                        break
            a += 8
        return None

    def fixed_frame(img_, f_):
        """Bytes between a function's body stack pointer and its return address slot (pushes and allocations)."""
        ui = f_[2]
        if ui & 1:
            return None
        vf, count = img_.u8(ui), img_.u8(ui + 2)
        if (vf >> 3) & 4:
            return None
        total, i = 0, 0
        while i < count:
            opb = img_.u8(ui + 4 + 2 * i + 1)
            op, info = opb & 15, opb >> 4
            if op == 0:
                total += 8
            elif op == 1:
                total += img_.u16(ui + 4 + 2 * i + 2) * 8 if info == 0 else img_.u32(ui + 4 + 2 * i + 2)
            elif op == 2:
                total += info * 8 + 8
            i += 1 + slots(img_, ui + 4, i, vf & 7)
        return total

    def detour_host(rsp_gap, base):
        """A function whose frame the generated code ran in: a return address above, preceded by a direct call to a
        function F whose fixed frame reaches from that slot down to exactly rsp_gap."""
        a = rsp_gap
        while a < base:
            v = d.q(a)
            if v is None:
                return None
            rm = d.module(v)
            if rm and s.is_code(v):
                im = image(rm)
                rv = v - rm[0]
                if im.ok and 5 <= rv <= len(im.img) and im.img[rv - 5] == 0xE8:
                    t = rv + struct.unpack_from("<i", im.img, rv - 4)[0]
                    f_ = im.func(t)
                    if f_ and f_[0] == t:
                        size = fixed_frame(im, f_)
                        if size is not None and a - size == rsp_gap:
                            return rm, f_, a
            a += 8
        return None

    th0 = next(t for t in d.threads() if t["tid"] == tid)
    stack_base = d.q(th0["teb"] + 8) or (regs[RSP] + 0x10000)
    print("\nFRAMES (innermost first). rsp = stack pointer inside that function; 'called by' = the call instruction")
    print("that the return address follows.\n")
    for n in range(args.frames):
        rip, rsp = regs["rip"], regs[RSP]
        mod = d.module(rip)
        label = name(rip) if n == 0 else name(rip)
        print("#%-2d rsp %X  %s" % (n, rsp, label))
        if args.regs:
            print("       " + " ".join("%s=%s" % (REG[i], "?" if i in unknown else "%X" % regs[i]) for i in (3, 5, 6, 7, 12, 13, 14, 15)))
        if args.slots:
            for k in range(args.slots):
                v = d.q(rsp + 8 * k)
                if v is None:
                    break
                m = d.module(v)
                print("       [rsp+%03X] %016X%s" % (8 * k, v, "  " + name(v) if m else ""))
        log = []
        if not mod:
            host = detour_host(rsp, stack_base)
            if host:
                hmod, hf, slot = host
                himg = image(hmod)
                print("    NOT INSIDE A MODULE: code generated at run time. It ran inside the frame of %s:" % name(hmod[0] + hf[0]))
                print("    the return address stored at %X follows a direct call to that function, and that function's fixed frame"
                      % slot)
                print("    (0x%X bytes) ends exactly at this stack pointer. So a plugin's detour inside that function made the call"
                      % (slot - rsp))
                print("    below; where in the function the detour sits is not known from the stack.")
                regs["rip"] = hmod[0] + hf[0] + himg.u8(hf[2] + 1)     # just past the prologue: unwinds like the body
                print("#%-2d rsp %X  %s  (the function the detour is in; instruction pointer not known)" % (n, rsp, name(hmod[0] + hf[0])))
                if not unwind_one(himg, hf, hf[0] + himg.u8(hf[2] + 1), regs, d.q, log, unknown):
                    print("    stack memory missing: stop")
                    break
                ret = regs["rip"]
                rmod = d.module(ret)
                c = call_before(image(rmod), ret - rmod[0], name, rmod[0]) if rmod else None
                print("    frame size 0x%X; called by: %s" % (regs[RSP] - rsp, c))
                continue
            a = resync(rsp, stack_base)
            if a is None:
                print("    not inside a module, and no further return address found up to the stack base: stop")
                break
            print("    NOT INSIDE A MODULE (code generated at run time, or an unlisted module): its frame cannot be undone.")
            print("    GAP: skipped 0x%X bytes of stack; the walk resumes at the return address stored at %X, the lowest one"
                  " from which it reaches the thread's start routine." % (a - rsp, a))
            print("    Frames inside the gap are missing; callee-saved registers are unknown until restored.")
            regs["rip"], regs[RSP] = d.q(a), a + 8
            unknown.update({3, 5, 6, 7, 12, 13, 14, 15})
            continue
        else:
            img = image(mod)
            rva = rip - mod[0]
            lookup = rva if n == 0 else rva - 1      # a return address belongs to the call before it
            f = img.func(lookup) if img.ok else None
            if not img.ok:
                print("    %s: %s; treated as a leaf" % (os.path.basename(mod[2]), img.note))
            if f is None:
                ret = d.q(rsp)
                if ret is None:
                    print("    stack memory missing: stop")
                    break
                if img.ok:
                    print("    no unwind entry (leaf function): return address at [rsp]")
                regs["rip"], regs[RSP] = ret, rsp + 8
            else:
                if not unwind_one(img, f, lookup if n else rva, regs, d.q, log, unknown):
                    print("    stack memory missing while undoing the prologue: stop")
                    break
        ret = regs["rip"]
        rmod = d.module(ret)
        if ret == 0 or (rmod is None and ret < 0x10000):
            print("    end of the stack (return address %X)" % ret)
            break
        if rmod:
            rimg = image(rmod)
            c = call_before(rimg, ret - rmod[0], name, rmod[0])
            print("    frame size 0x%X%s; called by: %s" % (regs[RSP] - rsp, (" (" + ", ".join(log) + ")") if log else "",
                                                           c if c else "NOT A CALL before the return address: the chain is doubtful from here"))
        else:
            print("    frame size 0x%X; return address %X is not inside a module" % (regs[RSP] - rsp, ret))


if __name__ == "__main__":
    main()
