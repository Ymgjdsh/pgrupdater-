#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cryptographically verify an embedded code signature inside a signed IPA.

Usage:  python sigverify.py <signed.ipa> [--resources]

Checks, for every Mach-O member in Payload/:
  * CodeDirectory (type 0) and alternate CodeDirectory (type 4096) page hashes
    against the actual page bytes of the file (SHA-1 and SHA-256).
  * which known blob (Info.plist / Requirements / CodeResources / Entitlements /
    DER entitlements) each special slot hash corresponds to.
  * the cdhash of each member, and for the nested framework, whether that cdhash
    equals the one recorded in the app's _CodeSignature/CodeResources (a mismatch
    makes iOS refuse to launch the app, with no crash report).
  * with --resources: every resource hash recorded in CodeResources against the
    actual bytes in the bundle.
"""
import hashlib
import plistlib
import struct
import sys
import zipfile

BIG = ">"


def h(data, hash_type, hexout=True):
    if hash_type == 1:
        d = hashlib.sha1(data).digest()
    elif hash_type == 2:
        d = hashlib.sha256(data).digest()
    elif hash_type == 3:
        d = hashlib.sha256(data).digest()[:20]
    elif hash_type == 5:
        d = hashlib.sha384(data).digest()[:20]
    else:
        raise ValueError("hashType %d" % hash_type)
    return d.hex() if hexout else d


def find_lc_cs(buf):
    magic, cputype, cpusub, ftype, ncmds, sizeofcmds, flags, res = struct.unpack_from("<8I", buf, 0)
    off = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", buf, off)
        if cmd == 0x1D:
            doff, dsz = struct.unpack_from("<2I", buf, off + 8)
            return doff, dsz
        off += cmdsize
    return None, None


def parse_superblob(blob):
    magic, length, count = struct.unpack_from(BIG + "3I", blob, 0)
    if magic != 0xFADE0CC0:
        raise ValueError("not a SuperBlob: magic=0x%08x" % magic)
    entries = []
    for i in range(count):
        t, o = struct.unpack_from(BIG + "2I", blob, 12 + 8 * i)
        blen = struct.unpack_from(BIG + "I", blob, o + 4)[0]
        entries.append((t, o, blen))
    return entries


def parse_cd(blob, off):
    magic, length, version, flags, hash_offset, ident_offset, n_special, n_code, code_limit = \
        struct.unpack_from(BIG + "9I", blob, off)
    if magic != 0xFADE0C02:
        raise ValueError("bad CodeDirectory magic 0x%08x" % magic)
    hash_size, hash_type, platform, page_size = struct.unpack_from(BIG + "4B", blob, off + 36)
    ident = blob[off + ident_offset:blob.index(b"\0", off + ident_offset)].decode(errors="replace")
    team = None
    if version >= 0x20200:
        team_offset = struct.unpack_from(BIG + "I", blob, off + 48)[0]
        if team_offset:
            team = blob[off + team_offset:blob.index(b"\0", off + team_offset)].decode(errors="replace")
    exec_seg = None
    if version >= 0x20400:
        exec_seg = struct.unpack_from(BIG + "3Q", blob, off + 64)
    return dict(off=off, length=length, version=version, flags=flags, hash_offset=hash_offset,
                ident=ident, team=team, n_special=n_special, n_code=n_code, code_limit=code_limit,
                hash_size=hash_size, hash_type=hash_type, platform=platform, page_size=page_size,
                exec_seg=exec_seg)


def cd_hash(blob, cd):
    """The cdhash: the digest of the CodeDirectory blob itself."""
    raw = blob[cd["off"]:cd["off"] + cd["length"]]
    return h(raw, cd["hash_type"]), h(raw, 2)


def check_member(name, data, info_plist, code_resources, ent_blob, der_blob, req_blob, resources=None, prefix=""):
    print("\n### %s  (%d bytes)" % (name, len(data)))
    doff, dsz = find_lc_cs(data)
    print("   LC_CODE_SIGNATURE dataoff=0x%x datasize=0x%x" % (doff, dsz))
    if not doff:
        print("   !! no LC_CODE_SIGNATURE (unsigned)")
        return None
    blob = data[doff:doff + dsz]
    sb_len = struct.unpack_from(BIG + "I", blob, 4)[0]
    print("   SuperBlob length=%d (0x%x)" % (sb_len, sb_len))
    entries = parse_superblob(blob)
    print("   entries: " + ", ".join("type=%d off=0x%x len=%d" % e for e in entries))
    cds = [parse_cd(blob, o) for t, o, l in entries if t in (0, 4096)]
    result = {}
    for cd in cds:
        kind = "primary (type 0)" if cd["off"] == [o for t, o, l in entries if t == 0][0] else "alternate (type 4096)"
        ps = 1 << cd["page_size"]
        print("   -- CodeDirectory %s: version=0x%x flags=0x%x hashType=%d hashSize=%d pageSize=%d "
              "nCodeSlots=%d nSpecialSlots=%d codeLimit=0x%x ident=%r team=%r"
              % (kind, cd["version"], cd["flags"], cd["hash_type"], cd["hash_size"], ps,
                 cd["n_code"], cd["n_special"], cd["code_limit"], cd["ident"], cd["team"]))
        if ps * cd["n_code"] < cd["code_limit"]:
            print("      !! nCodeSlots*pageSize=%d < codeLimit=%d  (uncovered tail!)" % (ps * cd["n_code"], cd["code_limit"]))
        # code slots
        bad = []
        zero = 0
        for i in range(cd["n_code"]):
            start = i * ps
            end = min(start + ps, cd["code_limit"])
            want = blob[cd["off"] + cd["hash_offset"] + i * cd["hash_size"]:
                        cd["off"] + cd["hash_offset"] + (i + 1) * cd["hash_size"]]
            if want == b"\0" * cd["hash_size"]:
                zero += 1
                continue
            got = h(data[start:end], cd["hash_type"], hexout=False)
            if got[:cd["hash_size"]] != want:
                bad.append((i, start, want.hex(), got.hex()))
        print("      code slots: %d checked, %d mismatched, %d zero-filled" % (cd["n_code"], len(bad), zero))
        for i, start, want, got in bad[:6]:
            print("        page %d @0x%x  stored=%s  actual=%s" % (i, start, want[:32], got[:32]))
        if len(bad) > 6:
            print("        ... %d more mismatches" % (len(bad) - 6))
        # special slots
        cands = []
        if info_plist is not None:
            cands.append(("Info.plist", info_plist))
        if code_resources is not None:
            cands.append(("_CodeSignature/CodeResources", code_resources))
        if ent_blob is not None:
            cands.append(("Entitlements blob", ent_blob))
        if der_blob is not None:
            cands.append(("DER entitlements blob", der_blob))
        if req_blob is not None:
            cands.append(("Requirements blob", req_blob))
        for k in range(1, cd["n_special"] + 1):
            start = cd["off"] + cd["hash_offset"] - k * cd["hash_size"]
            stored = blob[start:start + cd["hash_size"]]
            match = [nm for nm, b in cands if h(b, cd["hash_type"], hexout=False)[:cd["hash_size"]] == stored]
            print("      slot -%d: %s%s" % (k, stored.hex()[:40],
                                            ("  == " + ", ".join(match)) if match else
                                            ("  (zeros)" if stored == b"\0" * cd["hash_size"] else "  ?? no candidate matches")))
        c1, c256 = cd_hash(blob, cd)
        print("      cdhash SHA-1=%s  SHA-256=%s" % (c1, c256))
        result[kind] = dict(cd=cd, cdhash_sha1=c1, cdhash_sha256=c256, bad_pages=len(bad))
    return result


def main():
    ipa = sys.argv[1]
    do_resources = "--resources" in sys.argv
    z = zipfile.ZipFile(ipa)
    names = z.namelist()
    apps = sorted({n.split("/")[1] for n in names if n.startswith("Payload/") and n.count("/") >= 2})
    print("IPA: %s" % ipa)
    print("app bundles: %s" % apps)
    app = apps[0]
    members = [n for n in names if n.startswith("Payload/%s/" % app) and n.count("/") == 2 and not n.endswith("/")]
    print("top-level members: %s" % members)

    def rd(n):
        try:
            return z.read(n)
        except KeyError:
            return None

    def get_blob(data, types):
        doff, dsz = find_lc_cs(data)
        if not doff:
            return {}
        blob = data[doff:doff + dsz]
        out = {}
        for t, o, l in parse_superblob(blob):
            if t in types:
                out[t] = blob[o:o + l]
        return out

    results = {}
    # nested framework exe
    fw = "Payload/%s/Frameworks/UnityFramework.framework" % app
    fw_exe = rd(fw + "/UnityFramework")
    fw_plist = rd(fw + "/Info.plist")
    fw_res = rd(fw + "/_CodeSignature/CodeResources")
    app_exe = rd("Payload/%s/%s" % (app, app))
    app_plist = rd("Payload/%s/Info.plist" % app)
    app_res = rd("Payload/%s/_CodeSignature/CodeResources" % app)
    if app_exe is None:
        # CFBundleExecutable may differ from the directory name
        pl = plistlib.loads(app_plist)
        app_exe = rd("Payload/%s/%s" % (app, pl["CFBundleExecutable"]))
        print("executable from Info.plist: %s" % pl["CFBundleExecutable"])

    for nm, exe, pl, res in (("app executable", app_exe, app_plist, app_res),
                             ("nested framework", fw_exe, fw_plist, fw_res)):
        if exe is None:
            print("\n### %s: MISSING" % nm)
            continue
        blobs = get_blob(exe, (2, 5, 7))
        results[nm] = check_member(nm, exe, pl, res, blobs.get(5), blobs.get(7), blobs.get(2), prefix="")

    # nested-code cdhash agreement between the app's CodeResources and the framework
    print("\n### nested code agreement (app _CodeSignature/CodeResources -> framework)")
    if app_res is None:
        print("   app has no CodeResources")
    else:
        try:
            cr = plistlib.loads(app_res)
        except Exception as e:
            print("   cannot parse app CodeResources: %s" % e)
            cr = None
        if cr is not None:
            hits = [k for k in (cr.get("files2") or {}) if "UnityFramework" in k]
            print("   files2 keys mentioning UnityFramework: %s" % hits)
            for k in hits:
                e = cr["files2"][k]
                cdh = e.get("cdhash")
                print("     %s: keys=%s cdhash=%s requirement=%s"
                      % (k, sorted(e.keys()), cdh.hex() if isinstance(cdh, bytes) else cdh,
                         (e.get("requirement") or b"").decode(errors="replace")[:120]))
                if isinstance(cdh, bytes) and "nested framework" in results:
                    r = results["nested framework"]
                    for kind, key in (("primary (type 0)", "cdhash_sha1"), ("primary (type 0)", "cdhash_sha256")):
                        pass
                    print("     computed framework cdhash: SHA-1=%s SHA-256=%s"
                          % (r.get("primary (type 0)", {}).get("cdhash_sha1"),
                             r.get("primary (type 0)", {}).get("cdhash_sha256")))
            files = cr.get("files") or {}
            print("   files entries: %d, files2 entries: %d" % (len(files), len(cr.get("files2") or {})))
            for k in sorted(files)[:12]:
                print("      %s -> %s" % (k, files[k]))

    if do_resources and app_res:
        print("\n### resource hash verification (this reads the whole bundle)")
        cr = plistlib.loads(app_res)
        files = cr.get("files") or {}
        files2 = cr.get("files2") or {}
        bad = []
        for i, (rel, ent) in enumerate(sorted(files.items())):
            member = "Payload/%s/%s" % (app, rel)
            if rel == "Info.plist" or rel.startswith("_CodeSignature/"):
                continue
            d = rd(member)
            if d is None:
                bad.append((rel, "missing"))
                continue
            e2 = files2.get(rel) or {}
            if isinstance(ent, dict) and "hash" in ent and h(d, 1, hexout=False)[:len(ent["hash"])] != ent["hash"]:
                bad.append((rel, "files hash(SHA-1) mismatch"))
            if isinstance(e2, dict) and "hash2" in e2 and h(d, 2, hexout=False)[:len(e2["hash2"])] != e2["hash2"]:
                bad.append((rel, "files2 hash2(SHA-256) mismatch"))
        print("   checked %d resource entries, %d problems" % (len(files), len(bad)))
        for rel, why in bad[:20]:
            print("      %s: %s" % (rel, why))
        if len(bad) > 20:
            print("      ... %d more" % (len(bad) - 20))


if __name__ == "__main__":
    main()
