import zipfile, struct, sys, os

p = sys.argv[1]
b = open(p, "rb").read()
print("file size", len(b))
# EOCD
i = b.rfind(b"PK\x05\x06")
print("EOCD at", i)
(sig, dnum, cnum, n1, n2, cdsize, cdoff, clen) = struct.unpack_from("<IHHHHIIH", b, i)
print(f"  entries={n1}/{n2} cdsize={cdsize} cdoff={cdoff} comment={clen}")
print("  ZIP64 EOCD locator present:", b.rfind(b"PK\x06\x07") != -1)
z = zipfile.ZipFile(p)
infos = z.infolist()
print("zipfile entries:", len(infos), " testzip-free")
want = [n for n in z.namelist() if n in (
    "Payload/Phigros.app/Phigros",
    "Payload/Phigros.app/Frameworks/UnityFramework.framework/UnityFramework",
    "Payload/Phigros.app/Info.plist",
    "Payload/decrypt.day") or n.startswith("Payload/Phigros.app/_CodeSignature") or n.startswith("Payload/Phigros.app/SC_Info")]
# local header layout
for inf in sorted(infos, key=lambda x: x.header_offset):
    pass
srt = sorted(infos, key=lambda x: x.header_offset)
for k, inf in enumerate(srt):
    if inf.filename in want or inf.filename.startswith(("Payload/Phigros.app/SC_Info", "Payload/Phigros.app/_CodeSignature")):
        nxt = srt[k+1].header_offset if k+1 < len(srt) else cdoff
        lh = inf.header_offset
        (lsig, ver, flg, meth, mt, md, crc, cs, us, nl, el) = struct.unpack_from("<IHHHHHIIIHH", b, lh)
        span = nxt - lh
        desc = span - (30 + nl + el + cs)
        print(f"  {inf.filename}")
        print(f"    off=0x{lh:X} meth={meth}({'stored' if meth==0 else 'deflate'}) flags=0x{flg:04X} "
              f"cs={cs} us={us} crc=0x{crc:08X} headroom_total={span} descbytes={desc}")
print("total stored entries:", sum(1 for x in infos if x.compress_type == 0))
print("total deflated entries:", sum(1 for x in infos if x.compress_type == 8))
print("declared total uncompressed:", sum(x.file_size for x in infos))
