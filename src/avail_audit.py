#!/usr/bin/env python3
"""Audit availability guards in a Mach-O built for an older iOS.

A binary built with IPHONEOS_DEPLOYMENT_TARGET 12 keeps every
`if (@available(iOS N, *))` check as a runtime call to a compiler-rt helper
(__isPlatformVersionAtLeast, statically linked, e.g. 0x12E3690 in 3.19.0); a
binary built with a deployment target >= the checked version has those checks
constant-folded away.  This tool finds every such check in the old binary and
reports which ObjC selectors live inside the guarded block, i.e. the API
surface that must not run on an older OS.

Usage:
    python avail_audit.py <macho> [--json out.json] [--min-major N] [--quiet]
"""
import argparse
import collections
import json
import sys

import capstone

from clsprobe import Img

MD = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
MD.detail = True
COND = ("b.eq", "b.ne", "b.hs", "b.lo", "b.hi", "b.ls", "b.ge", "b.gt", "b.le",
        "b.lt", "b.mi", "b.pl", "b.vs", "b.vc", "cbz", "cbnz", "tbz", "tbnz")


def iter_range(im, lo, hi):
    va = lo
    while va < hi:
        fo = im.foff(va)
        if fo is None:
            return
        n = min(0x400000, hi - va)
        chunk = im.buf[fo:fo + n]
        if not chunk:
            return
        for i in MD.disasm(chunk, va):
            yield i
        va += len(chunk)


def objc_stub_selectors(im):
    """{stub_va: selector} for __objc_stubs (adrp xN,page ; ldr xN,[xN,#off] ; b msgSend)."""
    secs = [s for s in im.sects if s["name"] == "__objc_stubs"]
    res = {}
    for s in secs:
        adrp = {}
        for i in iter_range(im, s["addr"], s["addr"] + s["size"]):
            if i.mnemonic == "adrp" and len(i.operands) == 2:
                try:
                    page = int(i.op_str.split(",")[-1].strip().lstrip("#"), 16)
                except ValueError:
                    continue
                adrp.setdefault(i.reg_name(i.operands[0].reg), []).append((i.address, page))
            elif i.mnemonic in ("ldr", "ldrsw") and len(i.operands) == 2:
                try:
                    dst = i.reg_name(i.operands[0].reg)
                    base = i.reg_name(i.operands[1].mem.base)
                    disp = i.operands[1].mem.disp
                except capstone.CsError:
                    continue
                if dst != base or base not in adrp:
                    continue
                for addr, page in adrp[base]:
                    if addr + 4 != i.address:
                        continue
                    p = im.u64(page + disp)
                    sel = im.cstr(p) if p else None
                    if sel and all(0x20 <= ord(c) < 0x7F for c in sel):
                        res[addr] = sel
                    break
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("macho")
    ap.add_argument("--json")
    ap.add_argument("--min-major", type=int, default=13)
    ap.add_argument("--quiet", action="store_true")
    a = ap.parse_args()
    im = Img(a.macho)
    txt = next(s for s in im.segs if s["name"] == "__TEXT")
    lo, hi = txt["vmaddr"], txt["vmaddr"] + txt["filesize"]
    stubsels = objc_stub_selectors(im)
    print(f"# {len(stubsels)} ObjC stubs (__objc_stubs)")

    insns = list(iter_range(im, lo, hi))
    print(f"# {len(insns)} instructions decoded from __TEXT")

    # availability check site = 4 consecutive movs w0..w3 immediately before bl
    sites = []
    for k in range(4, len(insns)):
        i = insns[k]
        if i.mnemonic != "bl" or not i.op_str.startswith("#0x"):
            continue
        args = []
        ok = True
        for j in insns[k - 4:k]:
            if not j.op_str.startswith("w") or "," not in j.op_str:
                ok = False
                break
            parts = [x.strip() for x in j.op_str.split(",")]
            if not (j.mnemonic.startswith("mov") and parts[0][0] == "w" and parts[-1].startswith("#")):
                ok = False
                break
            try:
                args.append((parts[0], int(parts[-1].lstrip("#"), 0)))
            except ValueError:
                ok = False
                break
        if not ok or [x[0] for x in args] != ["w0", "w1", "w2", "w3"]:
            continue
        sites.append((i.address, int(i.op_str[1:], 16), tuple(x[1] for x in args[1:])))
    helpers = collections.Counter(t for _, t, _ in sites)
    print(f"# availability call sites: {len(sites)}; helpers: "
          f"{[(hex(k), v) for k, v in helpers.most_common(6)]}")

    rows = []
    for site, tgt, ver in sites:
        rows.append(dict(site=site, helper=tgt, version=ver))
    # cluster per site: find the guarded block = until the first conditional branch
    addr2idx = {i.address: k for k, i in enumerate(insns)}
    for r in rows:
        k = addr2idx[r["site"]]
        end = r["site"] + 4 * 60
        for j in insns[k + 1:k + 16]:
            if j.mnemonic in COND:
                t = j.op_str.split(",")[-1].strip()
                if t.startswith("#0x"):
                    end = int(t[1:], 16)
                break
        sels = []
        for j in insns[k + 1:]:
            if j.address >= end:
                break
            if j.mnemonic == "bl" and j.op_str.startswith("#0x"):
                t = int(j.op_str[1:], 16)
                if t in stubsels:
                    sels.append((stubsels[t], t, j.address))
        r["block_end"] = end
        r["calls"] = sels
        r["selectors"] = sorted({s[0] for s in sels})

    per_sel = collections.defaultdict(set)
    for r in rows:
        for s in r["selectors"]:
            per_sel[s].add(r["version"][0])
    want = sorted((s, sorted(v)) for s, v in per_sel.items() if max(v) >= a.min_major)
    if not a.quiet:
        for r in rows:
            if max(r["version"][0], 0) < a.min_major:
                continue
            print(f"\n# iOS >= {r['version'][0]}.{r['version'][1]} guard at 0x{r['site']:X} "
                  f"(block ->0x{r['block_end']:X})")
            for s, st, cs in r["calls"]:
                print(f"    {s!r:56s} stub=0x{st:X} call=0x{cs:X}")
    print(f"\n# {len(want)} distinct selectors guarded at >= iOS {a.min_major}:")
    for s, v in want:
        print(f"#   {s:58s} >= {v}")
    if a.json:
        json.dump(dict(rows=rows, selectors={s: v for s, v in want}), open(a.json, "w"), indent=1)
        print(f"# wrote {a.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
