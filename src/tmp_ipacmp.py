import zipfile, hashlib, sys, os
def sha(b): return hashlib.sha256(b).hexdigest()[:16]
cands = {"v7": r"out\Phigros.v7", "v6": r"out\Phigros.v6"}
ref = {k: open(v,'rb').read() for k,v in cands.items()}
for k,v in ref.items(): print(f"ref {k}: {len(v)} B {sha(v)}")
fw_ref = open(r"out\UnityFramework.v15","rb").read()
print(f"ref fw v15: {len(fw_ref)} B {sha(fw_ref)}")
for ipa in [r"phi5\Phigros_4.0.0_iOS12_v15.ipa", r"phi5\Phigros_4.0.0_iOS12_v15_smoketest.ipa"]:
    print("===", ipa, os.path.getsize(ipa))
    z = zipfile.ZipFile(ipa)
    for name in ["Payload/Phigros.app/Phigros","Payload/Phigros.app/Frameworks/UnityFramework.framework/UnityFramework","Payload/Phigros.app/Info.plist"]:
        try:
            data = z.read(name)
        except KeyError:
            print("   MISSING", name); continue
        tag = ""
        for k,v in ref.items():
            if data == v: tag = f"== ref {k}"
        if name.endswith("UnityFramework"):
            tag = "== ref fw v15" if data == fw_ref else "!= ref fw v15"
        print(f"   {name}: {len(data)} B {sha(data)} {tag}")
        if name.endswith("/Phigros"):
            open(r"out\_check_installed_Phigros","wb").write(data)
