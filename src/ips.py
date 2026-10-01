#!/usr/bin/env python3
"""Read an Apple `.ips` (or legacy `.crash`) report and resolve the crash site.

Usage:
    python ips.py <report.ips> [--all-threads] [--regs]
                  [--dump tools\\Il2CppDumper\\dump.cs] [--uuid work\\UnityFramework ...]

Modern `.ips` files have a one-line JSON header, then a JSON body. Older
iOS reports have a JSON header followed by a plain-text crash report.
Both are genuine Apple crash reports. Frames in modern `UnityFramework` reports use
`imageOffset`, which equals the file offset inside `__TEXT` of that Mach-O
(`__TEXT` has vmaddr 0 / fileoff 0), so the offset maps 1:1 onto the il2cpp
`RVA` values printed by Il2CppDumper -- `--dump` turns a crash into a method
name.  `--uuid` prints the LC_UUID of a local binary so it can be matched
against the report's `slice_uuid` / `usedImages[].uuid`.
"""
import argparse
import bisect
import json
import os
import re
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


# ---------------------------------------------------------------- Mach-O UUID
def lc_uuid(path):
    with open(path, "rb") as fh:
        head = fh.read(32)
        if len(head) < 32 or struct.unpack_from("<I", head)[0] != 0xFEEDFACF:
            return None
        ncmds, = struct.unpack_from("<I", head, 16)
        off = 32
        fh.seek(0)
        buf = fh.read()
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack_from("<II", buf, off)
            if cmd == 0x1B:  # LC_UUID
                raw = buf[off + 8: off + 24]
                return "-".join([raw[0:4].hex(), raw[4:6].hex(), raw[6:8].hex(),
                                 raw[8:10].hex(), raw[10:16].hex()]).upper()
            off += cmdsize
        return None


# ------------------------------------------------------------------- RVA index
def load_index(dump):
    cache = os.path.splitext(dump)[0] + ".rvamap.json"
    if os.path.exists(cache) and os.path.getmtime(cache) > os.path.getmtime(dump):
        return [(e[0], e[1]) for e in json.load(open(cache, encoding="utf-8"))]
    sys.path.insert(0, HERE)
    import rvamap
    ent = rvamap.build(dump)
    json.dump(ent, open(cache, "w", encoding="utf-8"))
    return ent


def resolve(entries, addr):
    i = bisect.bisect_right(entries, (addr, "\uffff"))
    if i == 0:
        return None
    return entries[i - 1]


# ------------------------------------------------------------------ .ips parse
def parse_ips(path):
    with open(path, "r", encoding="utf-8", errors="replace") as source:
        raw = source.read()
    lines = raw.splitlines()
    header = None
    body = raw
    if lines:
        try:
            header = json.loads(lines[0])
            body = "\n".join(lines[1:])
        except Exception:
            header = None
    data = json.loads(body)
    return header, data


def parse_any(path):
    """Return (header, body).  Accepts .ips and legacy text .crash."""
    with open(path, "r", encoding="utf-8", errors="replace") as source:
        raw = source.read()
    try:
        return parse_ips(path)
    except json.JSONDecodeError:
        # iOS 12/14 commonly use Report Version 104 text after a JSON header.
        # Do not misidentify these genuine crash reports as device syslogs.
        if re.search(r"^Incident Identifier:", raw, re.M) and re.search(r"^Exception Type:", raw, re.M):
            first, _, rest = raw.partition("\n")
            try:
                header = json.loads(first)
                body = rest
            except json.JSONDecodeError:
                header, body = None, raw
            return header, {"_legacy_text": body}
        raise SystemExit(f"{path}: not an Apple JSON .ips report (this looks like a plain device log).\n"
                         "On the device: Settings -> Privacy -> Analytics & Improvements -> Analytics Data, "
                         "pick the 'Phigros-YYYY-MM-DD-HHMMSS.ips' entry; or use i4Tools/3uTools "
                         "'Crash logs' export.")


def print_legacy_report(raw, all_threads=False, regs=False):
    """Keep multiline termination/exception details and requested legacy threads."""
    print("== legacy Apple crash report ==")
    anchors = ("Incident Identifier:", "Date/Time:", "Exception Type:",
               "Termination Reason:", "Termination Description:",
               "Application Specific Information:", "Dyld Error Message:",
               "Backtrace not available", "Binary images description not available",
               "Error Formulating Crash Report:")
    for block in re.split(r"\n\s*\n", raw.strip()):
        lines = block.splitlines()
        wanted = any(line.startswith(anchors) for line in lines)
        if re.search(r"^Thread \d+ Crashed:", block, re.M):
            wanted = True
        if all_threads and re.search(r"^Thread \d+", block, re.M):
            wanted = True
        if regs and "Thread State" in block:
            wanted = True
        if wanted:
            print(block + "\n")
        elif block.startswith("Binary Images:"):
            print("== relevant binary images ==")
            for line in lines:
                if "Phigros" in line or "UnityFramework" in line:
                    print(line)


def frame_addr(img, frame):
    base = img.get("base", 0)
    return base + frame.get("imageOffset", 0)


def fmt_frame(idx, frame, images, entries, prefix=""):
    ii = frame.get("imageIndex")
    name = "?"
    if ii is not None and 0 <= ii < len(images):
        im = images[ii]
        name = im.get("name") or os.path.basename(im.get("path", "?"))
    off = frame.get("imageOffset")
    sym = frame.get("symbol") or ""
    sloc = frame.get("symbolLocation")
    extra = ""
    if name in ("UnityFramework", "Phigros") and off is not None and entries:
        hit = resolve(entries, off)
        if hit:
            rva, meth = hit
            extra = f"   ->  {meth} + 0x{off - rva:X}  (il2cpp RVA 0x{rva:X})"
        else:
            extra = "   ->  (below the lowest il2cpp RVA: engine code)"
    symtxt = ""
    if sym:
        symtxt = f"  {sym}" + (f" + {sloc}" if sloc else "")
    print(f"{prefix}{idx:>2} {name:<20} 0x{off:08X}{symtxt}{extra}" if off is not None
          else f"{prefix}{idx:>2} {name:<20} -{symtxt}")


def main():
    # Some Apple reports contain non-GBK characters in diagnostics.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="backslashreplace")
    ap = argparse.ArgumentParser()
    ap.add_argument("report")
    ap.add_argument("--all-threads", action="store_true")
    ap.add_argument("--regs", action="store_true")
    ap.add_argument("--dump", default=os.path.join(HERE, "tools", "Il2CppDumper", "dump.cs"))
    ap.add_argument("--uuid", nargs="*", default=[])
    a = ap.parse_args()

    for p in a.uuid:
        u = lc_uuid(p)
        print(f"LC_UUID {p} = {u}")
    if a.uuid:
        print()

    header, d = parse_any(a.report)
    if header:
        print("== header ==")
        for k in ("app_name", "app_version", "bundleID", "bug_type", "os_version", "timestamp",
                  "incident_id", "name", "platform"):
            if k in header:
                print(f"  {k}: {header[k]}")
    if "_legacy_text" in d:
        print_legacy_report(d["_legacy_text"], a.all_threads, a.regs)
        return 0
    print("== body ==")
    for k in ("procName", "procPath", "pid", "translated", "modelCode", "osVersion",
              "captureTime", "procLaunch", "exceptionReason"):
        if k in d:
            print(f"  {k}: {d[k]}")
    exc = d.get("exception") or {}
    if exc:
        print(f"  exception: type={exc.get('type')} signal={exc.get('signal')} "
              f"codes={exc.get('codes')} rawCodes={exc.get('rawCodes')} subtype={exc.get('subtype')}")
    for k in ("termination", "asi", "lastExceptionBacktrace", "vmregioninfo", "isCorpse", "procExitStatus"):
        if k in d:
            print(f"  {k}: {json.dumps(d[k])[:400]}")

    images = d.get("usedImages") or []
    print(f"== images ({len(images)}) ==")
    for i, im in enumerate(images):
        if im.get("name") in ("UnityFramework", "Phigros") or "Phigros" in (im.get("path") or ""):
            print(f"  [{i}] {im.get('name')} base=0x{im.get('base', 0):X} size=0x{im.get('size', 0):X} "
                  f"uuid={im.get('uuid')}\n      {im.get('path')}")

    entries = None
    if os.path.exists(a.dump):
        try:
            entries = load_index(a.dump)
        except Exception as e:  # pragma: no cover
            print(f"  (il2cpp index unavailable: {e})")

    threads = d.get("threads") or []
    ft = d.get("faultingThread", 0)
    order = list(range(len(threads))) if a.all_threads else [ft]
    for ti in order:
        if ti >= len(threads):
            continue
        th = threads[ti]
        tag = "FAULTING" if ti == ft else "thread"
        print(f"== {tag} thread {ti} name={th.get('name')} queue={th.get('queue')} "
              f"triggered={th.get('triggered')} ==")
        for i, fr in enumerate(th.get("frames") or []):
            fmt_frame(i, fr, images, entries, prefix="  ")
        if a.regs and th.get("threadState"):
            ts = th["threadState"]
            for key in ("x", "fp", "lr", "sp", "pc", "cpsr", "far", "esr", "exception"):
                if key in ts:
                    v = ts[key]
                    if isinstance(v, list):
                        print(f"   {key}: " + " ".join(f"{x:016X}" for x in v[:32]))
                    else:
                        print(f"   {key}: {v}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
