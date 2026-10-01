"""zipcheck.py - validate the low-level structure of a .ipa (zip) file.

Why: Python's zipfile reads everything from the central directory, so testzip() can pass
even when the per-entry LOCAL headers are stale.  Sideloadly-class tools may stream the
payload using the local headers / data descriptors instead, and then report
"Install failed ... Invalid file".

Checks per entry:
  * local header exists at the recorded offset and has signature PK\x03\x04
  * local flags / method / crc / csize / usize match the central directory
    (a stale size is reported, but tolerated when flag bit 3 = data descriptor,
     or when the entry is a directory)
  * file offset of local header + header + compressed data <= next local header offset
    (i.e. no entry overlaps its neighbour)
  * reports zip64 usage, flag bits, and the Unix permission bits of the payload entries

Usage:  python zipcheck.py <file.ipa> [<file2.ipa> ...]
        python zipcheck.py <file.ipa> --mode          # dump Unix modes of key entries
"""
import mmap
import struct
import sys
import zipfile

# permission bits we care about when comparing two builds
KEY_SUFFIXES = (
    "/Phigros.app/Phigros",
    "UnityFramework.framework/UnityFramework",
    "UnityFramework.framework/Versions/Current",
    "UnityFramework.framework/Resources",
    "Info.plist",
    "PkgInfo",
)

EOCD = b"PK\x05\x06"
Z64EOCD = b"PK\x06\x06"
Z64LOC = b"PK\x06\x07"
CD = b"PK\x01\x02"
LFH = b"PK\x03\x04"


class ZipRaw:
    def __init__(self, path):
        self.path = path
        self.f = open(path, "rb")
        self.m = mmap.mmap(self.f.fileno(), 0, access=mmap.ACCESS_READ)
        self.size = len(self.m)
        self.zip64 = False
        self.n_entries = 0
        self.cd_off = 0
        self.cd_size = 0
        self.entries = []
        self._eocd()
        self._central()

    def u16(self, off):
        return struct.unpack_from("<H", self.m, off)[0]

    def u32(self, off):
        return struct.unpack_from("<I", self.m, off)[0]

    def u64(self, off):
        return struct.unpack_from("<Q", self.m, off)[0]

    def _eocd(self):
        tail = min(self.size, 65557)
        buf = self.m[self.size - tail:self.size]
        i = buf.rfind(EOCD)
        if i < 0:
            raise SystemExit(f"{self.path}: no end-of-central-directory record -> not a zip")
        off = self.size - tail + i
        self.n_entries = self.u16(off + 10)
        self.cd_size = self.u32(off + 12)
        self.cd_off = self.u32(off + 16)
        self.eocd_off = off
        if self.cd_off == 0xFFFFFFFF or self.n_entries == 0xFFFF:
            j = self.m.rfind(Z64LOC, off - 64, off)
            if j < 0:
                raise SystemExit(f"{self.path}: zip64 markers but no zip64 locator")
            z64 = self.u64(j + 8)
            if self.m[z64:z64 + 4] != Z64EOCD:
                raise SystemExit(f"{self.path}: bad zip64 EOCD at 0x{z64:x}")
            self.zip64 = True
            self.n_entries = self.u64(z64 + 32)
            self.cd_size = self.u64(z64 + 40)
            self.cd_off = self.u64(z64 + 48)
            self.z64_off = z64

    def _central(self):
        off = self.cd_off
        for _ in range(self.n_entries):
            if self.m[off:off + 4] != CD:
                raise SystemExit(f"{self.path}: bad central directory signature at 0x{off:x}")
            (made_by, need_ver, flags, method, mtime, mdate, crc, csize, usize,
             nlen, elen, clen, disk, iattr, eattr, lho) = struct.unpack_from("<HHHHHHIIIHHHHHII", self.m, off + 4)
            name = self.m[off + 46:off + 46 + nlen].decode("utf-8", "replace")
            extra = self.m[off + 46 + nlen:off + 46 + nlen + elen]
            z64 = {}
            p = 0
            while p + 4 <= len(extra):
                hid, hsz = struct.unpack_from("<HH", extra, p)
                body = extra[p + 4:p + 4 + hsz]
                if hid == 0x0001:
                    q = 0
                    if usize == 0xFFFFFFFF:
                        z64["usize"] = struct.unpack_from("<Q", body, q)[0]
                        q += 8
                    if csize == 0xFFFFFFFF:
                        z64["csize"] = struct.unpack_from("<Q", body, q)[0]
                        q += 8
                    if lho == 0xFFFFFFFF:
                        z64["lho"] = struct.unpack_from("<Q", body, q)[0]
                        q += 8
                p += 4 + hsz
            self.entries.append(dict(
                name=name, made_by=made_by, need_ver=need_ver, flags=flags, method=method,
                crc=crc, csize=csize, usize=usize, eattr=eattr, iattr=iattr, lho=lho,
                z64=z64, cd_off=off, nlen=nlen, elen=elen,
                unix_mode=(eattr >> 16) & 0xFFFF, dos_attr=eattr & 0xFF,
                create_system=(made_by >> 8) & 0xFF,
            ))
            off += 46 + nlen + elen + clen

    # ---------------- local header audit ----------------
    def audit(self):
        problems = []
        warn = []
        self.entries.sort(key=lambda e: e["lho"])
        for i, e in enumerate(self.entries):
            lho = e["lho"]
            if self.m[lho:lho + 4] != LFH:
                problems.append(f"{e['name']}: no local header at 0x{lho:x} "
                                f"(found {self.m[lho:lho+4]!r})")
                continue
            lflags = self.u16(lho + 6)
            lmethod = self.u16(lho + 8)
            lcrc = self.u32(lho + 14)
            lcsize = self.u32(lho + 18)
            lusize = self.u32(lho + 22)
            lnlen = self.u16(lho + 26)
            lelen = self.u16(lho + 28)
            lname = self.m[lho + 30:lho + 30 + lnlen].decode("utf-8", "replace")
            hdr_end = lho + 30 + lnlen + lelen
            is_dir = e["name"].endswith("/")
            if lname != e["name"]:
                problems.append(f"{e['name']}: local name mismatch ({lname!r})")
            if lflags != e["flags"]:
                warn.append(f"{e['name']}: flags differ central=0x{e['flags']:04x} local=0x{lflags:04x}")
            if lmethod != e["method"]:
                problems.append(f"{e['name']}: method differs central={e['method']} local={lmethod}")
            if not (e["flags"] & 0x08):  # no data descriptor -> local sizes must be exact
                if not is_dir and (lcsize != e["csize"] or lusize != e["usize"]):
                    problems.append(
                        f"{e['name']}: STALE LOCAL SIZE central csize={e['csize']} usize={e['usize']} "
                        f"local csize={lcsize} usize={lusize}")
                elif lcrc != e["crc"] and not is_dir:
                    problems.append(f"{e['name']}: local crc 0x{lcrc:08x} != central 0x{e['crc']:08x}")
            else:
                if lcsize != 0 or lusize != 0:
                    warn.append(f"{e['name']}: flag bit3 set but local sizes nonzero")
            # overlap / ordering check
            if i + 1 < len(self.entries):
                nxt = self.entries[i + 1]["lho"]
                end = hdr_end + (e["csize"] if not is_dir else 0)
                if end > nxt:
                    problems.append(f"{e['name']}: data ends 0x{end:x} past next header 0x{nxt:x}")
            if hdr_end + e["csize"] > self.size:
                problems.append(f"{e['name']}: data ends past EOF")
        return problems, warn

    def modes(self):
        out = []
        for e in sorted(self.entries, key=lambda x: x["name"]):
            if any(e["name"].endswith(s) or s in e["name"] for s in KEY_SUFFIXES):
                out.append((e["name"], e["create_system"], e["unix_mode"], e["dos_attr"],
                            e["method"], e["flags"], e["usize"], e["csize"]))
        return out


def zf_summary(path):
    z = zipfile.ZipFile(path)
    infos = z.infolist()
    z64 = sum(1 for i in infos if i.extract_version >= 45)
    dd = sum(1 for i in infos if i.flag_bits & 0x08)
    dirs = sum(1 for i in infos if i.is_dir())
    bad = z.testzip()
    return dict(n=len(infos), zip64ish=z64, datadesc=dd, dirs=dirs, badcrc=bad,
                has_payload=any(i.filename.startswith("Payload/") for i in infos))


def main(argv):
    dump_mode = "--mode" in argv
    argv = [a for a in argv if a != "--mode"]
    for path in argv[1:]:
        print("=" * 100)
        print(f"FILE {path}")
        try:
            s = zf_summary(path)
            print(f"  zipfile: entries={s['n']} dirs={s['dirs']} local-sizes-unknown(bit3)={s['datadesc']} "
                  f"extract_version>=45(zip64-ish)={s['zip64ish']} crc_error={s['badcrc']} payload_dir={s['has_payload']}")
        except Exception as exc:  # noqa: BLE001
            print(f"  zipfile FAILED: {exc!r}")
        z = ZipRaw(path)
        print(f"  raw: entries={z.n_entries} zip64_eocd={z.zip64} cd_off=0x{z.cd_off:x} "
              f"cd_size={z.cd_size} eocd_off=0x{z.eocd_off:x} file_size={z.size}")
        problems, warn = z.audit()
        print(f"  local-header problems: {len(problems)}   warnings: {len(warn)}")
        for p in problems[:25]:
            print(f"    PROBLEM {p}")
        for w in warn[:10]:
            print(f"    warn {w}")
        if dump_mode:
            print("  key entries (name | create_system | unix_mode | dos_attr | method | flags | usize | csize):")
            for row in z.modes():
                print(f"    {row[0]} | {row[1]} | {row[2]:o} | 0x{row[3]:02x} | {row[4]} | 0x{row[5]:04x} | {row[6]} | {row[7]}")
        z.m.close()
        z.f.close()


if __name__ == "__main__":
    main(sys.argv)
