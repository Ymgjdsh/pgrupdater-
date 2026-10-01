# -*- coding: utf-8 -*-
"""Cross-check the "missing on iOS 12" import list against the stock 3.19.0 binary.

3.19.0 is the last Phigros build that Apple shipped for iOS 12 and it launches fine on
the user's iPad, so every symbol IT imports is guaranteed to exist on iOS 12.  If the
miss-list contains one of those, the miss-list has a false positive.
"""
import sys
from chained2dyld import MachO, rd, read_uleb, read_sleb, decode_fixups

OLD = sys.argv[1] if len(sys.argv) > 1 else r"work319graft\Frameworks\UnityFramework.framework\UnityFramework"
NEW = sys.argv[2] if len(sys.argv) > 2 else r"work\UnityFramework"
WEAK = sys.argv[3] if len(sys.argv) > 3 else r"weak.txt"

LC_DYLD_INFO_ONLY = 0x80000022
LC_DYLD_INFO = 0x22


def classic_streams(path):
    """(strong, weak, lazy) symbol sets from the three classic bind streams"""
    m = MachO(open(path, "rb").read())
    b = m.buf
    di = m.lc(LC_DYLD_INFO_ONLY) or m.lc(LC_DYLD_INFO)
    if not di:
        return None
    co = di[0]["off"]
    rb_off, rb_sz, bd_off, bd_sz, wb_off, wb_sz, lb_off, lb_sz, ex_off, ex_sz = rd(b, co + 8, "IIIIIIIIII")
    out = []
    for off, sz, lazy in ((bd_off, bd_sz, False), (wb_off, wb_sz, False), (lb_off, lb_sz, True)):
        names = {}
        i, p = 0, b[off:off + sz]
        while i < len(p) and sz:
            op, imm = p[i] & 0xF0, p[i] & 0x0F
            i += 1
            if op == 0x00:                       # DONE
                if lazy and p[i:i + 1] == b"\x00":
                    break
                if not lazy:
                    break
            elif op == 0x10: pass                # SET_DYLIB_ORDINAL_IMM
            elif op == 0x20: _, i = read_uleb(p, i)
            elif op == 0x30: pass                # SET_DYLIB_SPECIAL_IMM
            elif op == 0x40:
                e = p.index(b"\0", i); names[p[i:e].decode()] = imm; i = e + 1
            elif op == 0x50: pass
            elif op == 0x60: _, i = read_sleb(p, i)
            elif op == 0x70: _, i = read_uleb(p, i)
            elif op == 0x80: _, i = read_uleb(p, i)
            elif op == 0x90: pass                # DO_BIND
            elif op == 0xA0: _, i = read_uleb(p, i)
            elif op == 0xB0: pass
            elif op == 0xC0:
                _, i = read_uleb(p, i); _, i = read_uleb(p, i)
        out.append(names)
    reg, wb, lz = out
    # BIND_SYMBOL_FLAGS_WEAK_IMPORT (0x1) can appear in the *regular* stream as well, so a
    # symbol is only "strong" when it never carries the weak flag anywhere.
    weak = {k for k, f in reg.items() if f & 1} | set(wb)
    strong = {k for k, f in reg.items() if not f & 1}
    return strong, weak, set(lz)


streams = classic_streams(OLD)
if streams is None:
    sys.exit("the old binary has no classic dyld info stream")
old_strong, old_weak, old_lazy = streams
old = old_strong | old_weak | old_lazy
new_chained = decode_fixups(MachO(open(NEW, "rb").read()))
new_names = {f["name"] for f in new_chained["fixups"] if f["kind"] == "bind"}
new_weak = {f["name"] for f in new_chained["fixups"] if f["kind"] == "bind" and f.get("weak")}
weak = {l.strip() for l in open(WEAK, encoding="utf-8") if l.strip()}
nonswift = sorted(s for s in weak if not s.startswith("_$s") and "swift" not in s.lower())

print(f"3.19.0 binary   : {len(old_strong)} strong + {len(old_weak)} weak + "
      f"{len(old_lazy)} lazy binds = {len(old)} symbols")
print(f"4.0.0 binary    : {len(new_names)} bound symbols, {len(new_weak)} of them weak as shipped")
print(f"weak.txt        : {len(weak)} symbols forced weak ({len(nonswift)} non-Swift)\n")

print(f"[A] symbols in both builds: {len(old & new_names)}")
print(f"[B] TRUE false positives -- strong in the stock 3.19.0 build yet we weaken them: "
      f"{len(old_strong & weak)}")
for s in sorted(old_strong & weak):
    print(f"      {s}")
print(f"[C] already weak in the stock 3.19.0 build -> our weakening matches Apple's own "
      f"iOS-12 build: {len(old_weak & weak)}")
print(f"[D] imported by 4.0.0 but not at all by the stock 3.19.0 build: "
      f"{len(new_names - old)}")
for s in sorted(new_names - old):
    print(f"      {s}   (weak in 4.0.0: {'yes' if s in new_weak else 'no/'} "
          f"weakened by us: {'yes' if s in weak else 'no'})")
print(f"[E] 3.19.0-only symbols (dropped in 4.0.0): {len(old - new_names)}\n")

print("[F] target objc_opt_* symbols:")
for s in ("_objc_opt_class", "_objc_opt_isKindOfClass", "_objc_opt_new",
          "_objc_opt_respondsToSelector"):
    print(f"      {s:30s} 3.19.0 strong: {'YES' if s in old_strong else 'no':3s}"
          f" 3.19.0 weak: {'yes' if s in old_weak else 'no':3s}"
          f" 4.0.0: {'YES' if s in new_names else 'no':3s}"
          f" shimmed: yes")

print("\n[G] the 10 non-Swift entries of weak.txt:")
for s in nonswift:
    if s not in old:
        verdict = "absent from the stock 3.19.0 build entirely -> weakening is right"
    elif s in old_weak:
        verdict = "already weak in the stock 3.19.0 build -> exactly what Apple did"
    elif s in old_lazy:
        verdict = ("lazy (function) bind there -- resolved only if called, so its presence "
                   "does not prove iOS 12 has it")
    else:
        verdict = "non-lazy bind in the stock 3.19.0 build -> exists on iOS 12"
    print(f"      {s:45s} {verdict}")
