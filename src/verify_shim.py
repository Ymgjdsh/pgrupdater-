# -*- coding: utf-8 -*-
"""Independent verification of the objc_opt_* shim.

Usage: python verify_shim.py [pristine.bin] [shimmed.bin]

Checks, without trusting chained2dyld.convert():
  1. the four objc_opt_* __got slots from the ORIGINAL chained-fixups binary exist;
  2. in the converted binary they are emitted as classic *rebases* (not binds), and
     their file content is a plain unslid vmaddr (no chained bits);
  3. every objc_opt_* bind is gone from the classic bind stream, and the rebase/bind
     totals moved by exactly +4 / -4;
  4. each thunk really loads the right selector out of __objc_selrefs and tail-calls
     the objc_msgSend stub, with the argument shuffle the real fast path needs.
"""
import sys
from chained2dyld import (MachO, decode_fixups, verify_classic, find_objc_msgSend_stub,
                          rd, OBJC_OPT_SHIMS, _dec_adrp)

PRISTINE = sys.argv[1] if len(sys.argv) > 1 else r"work\UnityFramework"
SHIMMED = sys.argv[2] if len(sys.argv) > 2 else r"work\UnityFramework.v2"

EXPECT_REBASE = 514483 + 4
EXPECT_BIND = 7648 - 4

ok = True
def chk(cond, msg):
    global ok
    print(("  OK   " if cond else "  FAIL ") + msg)
    if not cond:
        ok = False

mp = MachO(open(PRISTINE, "rb").read())
ms = MachO(open(SHIMMED, "rb").read())
dp = decode_fixups(mp)
res = verify_classic(SHIMMED, verbose=False)

print(f"pristine {PRISTINE}: chained fixups, {len(dp['fixups'])} total")
print(f"shimmed  {SHIMMED}: classic rebases={len(res['rebase'])} binds={len(res['bind'])}")

# ---- 0. segment layout must be untouched (the shim only fills zero padding; convert()
#         is allowed to grow __LINKEDIT for the appended streams)
pv = [(s["name"], s["vmaddr"], s["fileoff"]) for s in mp.segments]
sv = [(s["name"], s["vmaddr"], s["fileoff"]) for s in ms.segments]
sv_vm = [s["vmaddr"] for s in ms.segments]
chk(pv == sv, "segment addresses/offsets identical before/after")
for a, b in zip(mp.segments, ms.segments):
    if a["name"] == "__LINKEDIT":
        chk(b["filesize"] >= a["filesize"],
            f"__LINKEDIT grew for the classic streams: {a['filesize']} -> {b['filesize']}")

# ---- 1. locate the original objc_opt_* got slots
want = {s for s, _sel, _a in OBJC_OPT_SHIMS}
pris = {}
for f in dp["fixups"]:
    if f["kind"] == "bind" and f["name"] in want:
        pris.setdefault(f["name"], []).append(f)
chk(len(pris) == 4 and all(len(v) == 1 for v in pris.values()),
    "pristine binary has exactly 4 objc_opt_* import slots: "
    + ", ".join(f"{k}@0x{pris[k][0]['vmaddr']:X}" if pris.get(k) else k + "@MISSING"
                for k in sorted(want)))

# ---- 2. those slots are now classic rebases holding a plain unslid address
reb = {(sv_vm[i], off) for i, off in res["rebase"]}
thunk_of = {}
for sym, _sel, _a in OBJC_OPT_SHIMS:
    f = pris.get(sym)
    if not f:
        continue
    f = f[0]
    vm = f["vmaddr"]
    chk((sv_vm[f["seg"]], vm - sv_vm[f["seg"]]) in reb,
        f"{sym}: slot 0x{vm:X} emitted in the classic rebase stream")
    val = rd(ms.buf, f["foff"], "Q")[0]
    chk(val < (1 << 36), f"{sym}: slot 0x{vm:X} holds plain unslid value 0x{val:X}")
    thunk_of[sym] = val

binds = {}
for b in res["bind"]:
    binds.setdefault(b[3], 0)
    binds[b[3]] += 1
for sym, _sel, _a in OBJC_OPT_SHIMS:
    chk(sym not in binds, f"{sym}: no classic bind emitted any more")

chk(len(res["rebase"]) == EXPECT_REBASE,
    f"rebase total {len(res['rebase'])} == {EXPECT_REBASE} (514483 + 4)")
chk(len(res["bind"]) == EXPECT_BIND,
    f"bind total   {len(res['bind'])} == {EXPECT_BIND} (7648 - 4)")

# ---- 3. disassemble the four thunks
msg_stub = find_objc_msgSend_stub(mp, mp.buf, dp["fixups"])
chk(msg_stub is not None, f"objc_msgSend stub found in the pristine binary "
                          f"({hex(msg_stub) if msg_stub else 'MISSING'})")

sects = [s for s in ms.sections if s["seg"] == "__TEXT" and s["size"]]
va2sect = {}
for s in sects:
    for v in range(s["addr"], s["addr"] + s["size"], 0x1000):
        va2sect[v] = s["name"]

ta = sorted(thunk_of.values())
chk(len(ta) == 4 and len(set(ta)) == 4, f"4 distinct thunk addresses: {[hex(x) for x in ta]}")
chk(all((b - a) == 0x20 for a, b in zip(ta, ta[1:])),
    "thunks are 0x20 bytes apart (room for 4 instructions + argument shuffle)")
chk(all(t not in va2sect for t in ta), "thunks live outside every __TEXT section (pure padding)")
txt = ms.seg_by_name["__TEXT"]
chk(all(txt["vmaddr"] <= t < txt["vmaddr"] + txt["vmsize"] for t in ta),
    "thunks inside __TEXT (r-x, no mprotect needed)")

for sym, sel, has_arg in OBJC_OPT_SHIMS:
    t = thunk_of.get(sym)
    if t is None:
        continue
    fo = ms.foff(t)
    ins = [rd(ms.buf, fo + 4 * i, "I")[0] for i in range(6)]
    p = 0
    if has_arg:
        chk(ins[0] == 0xAA0103E2, f"{sym}: mov x2, x1 (fast-path arg kept) "
                                  f"[0x{ins[0]:08X}]")
        p = 1
    chk(ins[p] & 0x9F000000 == 0x90000000 and (ins[p] & 0x1F) == 16,
        f"{sym}: adrp x16, ... [0x{ins[p]:08X}]")
    page = _dec_adrp(ins[p], t + 4 * p)
    chk(ins[p + 1] & 0xFFC00000 == 0xF9400000 and (ins[p + 1] & 0x1F) == 16
        and ((ins[p + 1] >> 5) & 0x1F) == 16,
        f"{sym}: ldr x16, [x16, #...] [0x{ins[p + 1]:08X}]")
    slot = page + ((ins[p + 1] >> 10) & 0xFFF) * 8
    chk(ins[p + 2] == 0xAA1003E1, f"{sym}: mov x1, x16 (selector in place) "
                                  f"[0x{ins[p + 2]:08X}]")
    chk(ins[p + 3] & 0xFC000000 == 0x14000000, f"{sym}: b <objc_msgSend> "
                                               f"[0x{ins[p + 3]:08X}]")
    d = (ins[p + 3] & 0x3FFFFFF)
    if d & (1 << 25):
        d -= (1 << 26)
    tgt = t + 4 * (p + 3) + d * 4
    chk(tgt == msg_stub, f"{sym}: branch target 0x{tgt:X} == objc_msgSend stub 0x{msg_stub:X}")
    chk(t == rd(ms.buf, pris[sym][0]["foff"], "Q")[0],
        f"{sym}: __got slot points at its own thunk 0x{t:X}")
    # the selector really has to be that string
    sfo = ms.foff(slot)
    sva = rd(ms.buf, sfo, "Q")[0] if sfo is not None else None
    cfo = ms.foff(sva) if sva is not None else None
    name = None
    if cfo is not None:
        z = ms.buf.find(b"\0", cfo, cfo + 128)
        name = bytes(ms.buf[cfo:z])
    chk(name == sel, f"{sym}: thunk loads selector {sel.decode()!r} "
                     f"(found {name.decode(errors='replace')!r} at 0x{sva:X})")

print("\nRESULT:", "ALL CHECKS PASSED" if ok else "FAILURES PRESENT")
sys.exit(0 if ok else 1)
