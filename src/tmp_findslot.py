import sys, chained2dyld as C

path = sys.argv[1] if len(sys.argv) > 1 else r"work\UnityFramework"
want = sys.argv[2:] or ["availability", "darwin_check_fd_set", "CAFrameRateRange"]
buf = open(path, "rb").read()
m = C.MachO(buf)
fx = C.decode_fixups(m)
for f in fx["fixups"]:
    n = f.get("name") or ""
    if any(w in n for w in want):
        print(f"kind={f['kind']:<4} vmaddr=0x{f['vmaddr']:X} foff={f.get('foff')} name={n!r} lib={f.get('lib')} ord={f.get('ordinal')} weak={f.get('weak')} target={f.get('target')}")
print("--- objc_msgSend slots ---")
for f in fx["fixups"]:
    if (f.get("name") or "") == "_objc_msgSend":
        print(f"kind={f['kind']:<4} vmaddr=0x{f['vmaddr']:X} name={f['name']!r} lib={f.get('lib')} ord={f.get('ordinal')} weak={f.get('weak')}")
