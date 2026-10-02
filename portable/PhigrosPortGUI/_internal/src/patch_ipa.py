"""Rewrite an IPA (zip) in place, replacing a few entries and dropping others,
WITHOUT extracting the archive.  Unchanged entries are byte-copied straight from
the source zip, so the 1.5 GB payload never gets decompressed/recompressed.

usage: patch_ipa.py <in.ipa> <out.ipa> <spec.json>
spec.json: {"replace": {"<entry name>": "<file to use>", ...},
            "add": {"<entry name>": "<file to use>", ...},
            "drop_prefix": ["Payload/Phigros.app/_CodeSignature/", ...]}
"add" entries are new members not present in the source archive (drop_prefix
applies to source members only, so a whole subtree can be dropped and refilled).
"""
import json, struct, sys, zlib, os, mmap

LFH = struct.Struct("<IHHHHHIIIHH")
CDH = struct.Struct("<IHHHHHHIIIHHHHHII")   # includes the 4-byte sig
EOCD = struct.Struct("<IHHHHIIH")

CHUNK = 1 << 20


def parse_central(b):
    # Signatures can occur inside compressed game resources or ZIP comments.
    # EOCD must end exactly at EOF, including its declared comment length.
    lo = max(0, len(b) - EOCD.size - 0xFFFF)
    i = b.rfind(b"PK\x05\x06", lo)
    while i >= 0:
        if i + EOCD.size <= len(b):
            comment_size = struct.unpack_from("<H", b, i + 20)[0]
            if i + EOCD.size + comment_size == len(b):
                break
        i = b.rfind(b"PK\x05\x06", lo, i)
    if i < 0:
        raise SystemExit("no valid EOCD")
    sig, dnum, cnum, n_disk, n_tot, cdsize, cdoff, clen = EOCD.unpack_from(b, i)
    # A ZIP64 locator belongs immediately before EOCD, never in file data.
    if i >= 20 and b[i-20:i-16] == b"PK\x06\x07":
        raise SystemExit("ZIP64 locator present - unsupported")
    if n_tot == 0xFFFF or cdsize == 0xFFFFFFFF or cdoff == 0xFFFFFFFF:
        raise SystemExit("ZIP64 central directory - unsupported")
    if dnum or cnum or n_disk != n_tot:
        raise SystemExit("multi-disk zip - unsupported")
    if cdoff + cdsize != i:
        raise SystemExit("central directory boundary mismatch")
    ents = []
    p = cdoff
    for _ in range(n_tot):
        if b[p:p+4] != b"PK\x01\x02":
            raise SystemExit(f"bad central header at 0x{p:X}")
        (sg, vm, vn, flg, meth, mt, md, crc, cs, us, nl, el, cl,
         dsk, iat, eat, lho) = CDH.unpack_from(b, p)
        name = b[p+46:p+46+nl].decode("utf-8", "surrogateescape")
        comment = bytes(b[p+46+nl+el: p+46+nl+el+cl])
        ents.append(dict(raw=None, off=p, name=name, vm=vm, vn=vn, flags=flg,
                         method=meth, mtime=mt, mdate=md, crc=crc, csize=cs,
                         usize=us, nl=nl, el=el, cl=cl, comment=comment, iattr=iat,
                         eattr=eat, lh_off=lho, cd_len=46+nl+el+cl))
        p += 46 + nl + el + cl
    if p != cdoff + cdsize:
        raise SystemExit("central directory size mismatch")
    return ents, cdoff, cdsize, i


def deflate_file(fh, level=6):
    """Stream-deflate an open file; return (crc, csize, usize, blob_dir)."""
    crc = 0
    n = 0
    co = zlib.compressobj(level, zlib.DEFLATED, -15)
    chunks = []
    while True:
        d = fh.read(CHUNK)
        if not d:
            break
        crc = zlib.crc32(d, crc)
        n += len(d)
        c = co.compress(d)
        if c:
            chunks.append(c)
    chunks.append(co.flush())
    return crc & 0xFFFFFFFF, sum(len(c) for c in chunks), n, chunks


def local_hdr_info(b, e):
    """Read the ORIGINAL local file header of entry e.

    Returns (version_needed, flags, extra_bytes) so a rewritten member can keep
    the exact ZIP provenance of the member it replaces (local and central
    headers may disagree, so the local one must be read separately).
    """
    (sg, vn, flg, meth, mt, md, crc, cs, us, nl, el) = LFH.unpack_from(b, e["lh_off"])
    if sg != 0x04034B50:
        raise SystemExit(f"bad local header for {e['name']}")
    extra = b[e["lh_off"]+30+nl: e["lh_off"]+30+nl+el]
    return vn, flg & ~0x08, bytes(extra)   # drop bit 3 (data descriptor)


def main():
    inp, outp, spec = sys.argv[1], sys.argv[2], sys.argv[3]
    S = json.load(open(spec, encoding="utf-8"))
    repl = S.get("replace", {})
    adds = S.get("add", {})
    drops = S.get("drop_prefix", [])

    fh_in = open(inp, "rb")
    b = mmap.mmap(fh_in.fileno(), 0, access=mmap.ACCESS_READ)
    ents, cdoff, cdsize, eocd_at = parse_central(b)
    by_off = sorted(ents, key=lambda e: e["lh_off"])
    for k, e in enumerate(by_off):
        e["span_end"] = by_off[k+1]["lh_off"] if k+1 < len(by_off) else cdoff
    # sanity: every local header really is a local header
    for e in ents:
        if b[e["lh_off"]:e["lh_off"]+4] != b"PK\x03\x04":
            raise SystemExit(f"bad local header for {e['name']} at 0x{e['lh_off']:X}")
    names = {e["name"] for e in ents}
    for n in repl:
        if n not in names:
            raise SystemExit(f"replace target not in archive: {n}")

    kept = []
    out = open(outp, "wb", buffering=1 << 22)
    pos = 0
    stats = []
    for e in by_off:
        nm = e["name"]
        if any(nm.startswith(p) for p in drops):
            stats.append(("DROP ", nm, 0, e["span_end"]-e["lh_off"]))
            continue
        if nm in repl:
            path = repl[nm]
            with open(path, "rb") as fh:
                crc, csize, usize, chunks = deflate_file(fh)
            nb = nm.encode()
            lvn, lflg, lextra = local_hdr_info(b, e)
            lh = LFH.pack(0x04034B50, lvn, lflg, 8, e["mtime"], e["mdate"],
                          crc, csize, usize, len(nb), len(lextra))
            new_off = pos
            out.write(lh); out.write(nb); out.write(lextra)
            for c in chunks:
                out.write(c)
            pos += len(lh) + len(nb) + len(lextra) + csize
            e2 = dict(e, crc=crc, csize=csize, usize=usize, method=8, flags=lflg,
                      el=len(lextra), extra=lextra, lh_off=new_off, replaced=True)
            kept.append(e2)
            stats.append(("REPL ", nm, csize, usize))
            continue
        span = b[e["lh_off"]:e["span_end"]]
        new_off = pos
        out.write(span)
        pos += len(span)
        e2 = dict(e, lh_off=new_off, replaced=False)
        kept.append(e2)
        stats.append(("copy ", nm, e["csize"], e["usize"]))

    cd_start = pos
    for nm in sorted(adds):
        path = adds[nm]
        with open(path, "rb") as fh:
            crc, csize, usize, chunks = deflate_file(fh)
        nb = nm.encode()
        e = dict(name=nm, vm=(3 << 8) | 30, vn=20, flags=0, mtime=0, mdate=0x21,
                 crc=crc, csize=csize, usize=usize, method=8, el=0, cl=0,
                 extra=b"", iattr=0, eattr=0o100644 << 16, lh_off=pos,
                 replaced=True)
        lh = LFH.pack(0x04034B50, e["vn"], e["flags"], 8, 0, 0x21, crc, csize,
                      usize, len(nb), 0)
        out.write(lh); out.write(nb)
        for c in chunks:
            out.write(c)
        pos += len(lh) + len(nb) + csize
        kept.append(e)
        stats.append(("ADD  ", nm, csize, usize))
    cd_start = pos
    for e in kept:
        if e.get("replaced"):
            nb = e["name"].encode()
            extra = e.get("extra", b"")
            ce = CDH.pack(0x02014B50, e["vm"], e["vn"], e["flags"], e["method"],
                          e["mtime"], e["mdate"], e["crc"], e["csize"], e["usize"],
                          len(nb), len(extra), e.get("cl", 0), 0,
                          e.get("iattr", 0), e["eattr"], e["lh_off"])
            out.write(ce); out.write(nb); out.write(extra)
            out.write(e.get("comment", b""))
            pos += 46 + len(nb) + len(extra) + e.get("cl", 0)
        else:
            raw = bytearray(b[e["off"]:e["off"]+e["cd_len"]])
            struct.pack_into("<I", raw, 42, e["lh_off"])
            out.write(raw)
            pos += e["cd_len"]
    cd_size = pos - cd_start
    out.write(EOCD.pack(0x06054B50, 0, 0, len(kept), len(kept), cd_size,
                        cd_start, 0))
    out.close()
    print(f"entries {len(ents)} -> {len(kept)}   cd 0x{cd_start:X}..0x{pos:X} ({cd_size})")
    print(f"output {outp} {os.path.getsize(outp)} bytes (input {len(b)})")
    for kind, nm, cs, us in stats:
        if kind != "copy ":
            print(f"  {kind} {nm}  cs={cs} us={us}")


if __name__ == "__main__":
    main()
