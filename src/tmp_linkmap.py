import struct, sys
LC = {0x2:"LC_SYMTAB",0xb:"LC_DYSYMTAB",0x1d:"LC_CODE_SIGNATURE",0x1e:"LC_SEGMENT_SPLIT_INFO",
      0x22:"LC_DYLD_INFO",0x80000022:"LC_DYLD_INFO_ONLY",0x26:"LC_FUNCTION_STARTS",0x29:"LC_DATA_IN_CODE",
      0x2b:"LC_DYLIB_CODE_SIGN_DRS",0x2e:"LC_LINKER_OPTIMIZATION_HINT",0x31:"LC_NOTE",
      0x80000033:"LC_DYLD_EXPORTS_TRIE",0x80000034:"LC_DYLD_CHAINED_FIXUPS",0x80000035:"LC_DYLD_BIND_TRIE?",
      0x33:"LC_BUILD_VERSION",0x32:"LC_BUILD_VERSION?",0x1:"LC_SEGMENT",0x19:"LC_SEGMENT_64"}
def u32(b,o): return struct.unpack_from("<I",b,o)[0]
for path in sys.argv[1:]:
    b=open(path,"rb").read(); ncmds=u32(b,16); so=32
    L=Sz=None; regs=[]
    for i in range(ncmds):
        cmd=u32(b,so); cs=u32(b,so+4); n=LC.get(cmd,hex(cmd))
        if cmd==0x19:
            name=b[so+8:so+24].split(b"\0")[0].decode()
            if name=="__LINKEDIT":
                L=struct.unpack_from("<Q",b,so+40)[0]; Sz=struct.unpack_from("<Q",b,so+48)[0]
        if cmd in (0x22,0x80000022):
            f=["rebase","bind","weak_bind","lazy_bind","export"]
            v=[u32(b,so+8+4*k) for k in range(10)]
            for k,nm in enumerate(f):
                if v[2*k] or v[2*k+1]: regs.append((v[2*k],v[2*k+1],f"LC_DYLD_INFO.{nm}[{i}]"))
        elif cmd==0x2:
            sy,ns,st,ss=u32(b,so+8),u32(b,so+12),u32(b,so+16),u32(b,so+20)
            regs.append((sy,ns*16,f"SYMTAB.nlist[{i}]")); regs.append((st,ss,f"SYMTAB.strtab[{i}]"))
        elif cmd in (0x1d,0x1e,0x26,0x29,0x2b,0x2e,0x80000033,0x80000034):
            do,ds=u32(b,so+8),u32(b,so+12); regs.append((do,ds,f"{n}[{i}]"))
        elif cmd==0xb:
            for nm,o in (("toc",8),("modtab",24),("extrefsym",32),("indirectsym",56),("extrel",40),("locrel",48)):
                off=u32(b,so+o)
                if off: regs.append((off,0,f"DYSYMTAB.{nm}[{i}]?"))
        so+=cs
    print(f"== {path}  file {len(b)} B")
    print(f"   __LINKEDIT fileoff {L:#x} filesize {Sz:#x} -> [{L:#x},{L+Sz:#x})")
    regs=[r for r in regs if r[0]>=L and (Sz is None or r[0]<L+Sz)]
    regs.sort()
    prev=L
    for off,sz,nm in regs:
        if off>prev: print(f"   GAP  [{prev:#x},{off:#x}) {off-prev:#x} B")
        print(f"   [{off:#x},{off+sz:#x}) {sz:#x} B  {nm}")
        if off+sz>prev: prev=off+sz
    print(f"   TAIL [{prev:#x},{L+Sz:#x}) {(L+Sz)-prev:#x} B")
