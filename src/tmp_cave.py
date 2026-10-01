import chained2dyld as C
m = C.MachO(open("out/UnityFramework.v13raw", "rb").read())
for va in (0x444CE40, 0x444CE70, 0x444CEC0, 0x444CF30, 0x444CF80, 0x444D000, 0x4450000):
    sec = m.sect_of(va)
    seg = m.seg_of(va)
    fo = m.foff(va)
    print("0x%08x  sec=%-14s seg=%-8s foff=%s" % (
        va, sec and sec["name"], seg and seg["name"],
        fo if fo is None else hex(fo)))
t = m.seg_by_name["__TEXT"]
print("__TEXT vmaddr=0x%x vmsize=0x%x fileoff=0x%x filesize=0x%x" % (
    t["vmaddr"], t["vmsize"], t["fileoff"], t["filesize"]))
last = [s for s in m.sections if s["seg"] == "__TEXT"][-1]
print("last __TEXT section: %s addr=0x%x size=0x%x end=0x%x" % (
    last["name"], last["addr"], last["size"], last["addr"] + last["size"]))
