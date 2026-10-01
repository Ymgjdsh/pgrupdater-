"""verify the v8 additions in a converted UnityFramework:
   * both _objc_msgSend __got slots are classic rebases pointing at the dispatcher
   * the dispatcher's own words decode to the intended sequence and reference the real
     respondsToSelector: selref slot (whose value must be the selector string)
   * every __objc_stubs / __stubs entry still loads one of those slots
   * the synthesized real-objc_msgSend slot exists in the new segment and is a bind
   * the three missing-function slots point at two-instruction stubs
usage: python verify_dispatch.py out/UnityFramework.v3f work/UnityFramework"""
import sys
import capstone
import chained2dyld as C

path = sys.argv[1] if len(sys.argv) > 1 else r"out\UnityFramework.v3f"
pris = sys.argv[2] if len(sys.argv) > 2 else r"work\UnityFramework"
m = C.MachO(open(path, "rb").read())
mp = C.MachO(open(pris, "rb").read())
dec = C.decode_fixups(mp)
slots = C.find_selref_slots(mp, mp.buf, dec["fixups"])

ok = fail = 0


def check(cond, what, detail=""):
    global ok, fail
    if cond:
        ok += 1
        print(f"  ok   {what}" + (f"  [{detail}]" if detail else ""))
    else:
        fail += 1
        print(f"  FAIL {what}" + (f"  [{detail}]" if detail else ""))


md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)

def u64(va):
    return C.rd(m.buf, m.foff(va), "Q")[0]


def cstr(va):
    fo = m.foff(va)
    z = m.buf.find(b"\0", fo)
    return bytes(m.buf[fo:z]).decode("latin1")


def sect_name(va):
    s = m.sect_of(va)
    return f"{s['seg']},{s['name']}" if s else None


def seg_name(va):
    s = m.seg_of(va)
    return s["name"] if s else None


def dis(va, n=40):
    fo = m.foff(va)
    return list(md.disasm(bytes(m.buf[fo:fo + n * 4]), va))


# ---- 1. the two _objc_msgSend got slots must be rebases onto the dispatcher
msg_slots = [f["vmaddr"] for f in dec["fixups"]
             if f["kind"] == "bind" and f["name"] == "_objc_msgSend"]
check(len(msg_slots) == 2, "_objc_msgSend has 2 __got slots in the chained original",
      ", ".join(hex(s) for s in msg_slots))
targets = {s: u64(s) for s in msg_slots}
disp_va = targets[msg_slots[-1]]
check(len(set(targets.values())) == 1 and seg_name(disp_va) is not None,
      "both slots hold the same unslid pointer into a mapped segment",
      f"{disp_va:#x} in {seg_name(disp_va)} (section {sect_name(disp_va)})")
check(seg_name(disp_va) == "__TEXT",
      "dispatcher lives in __TEXT", seg_name(disp_va))

# ---- 2. the dispatcher body itself (it ends at the nil path's ret)
body_full = dis(disp_va, 40)
end = max(i for i, x in enumerate(body_full) if x.mnemonic == "ret") + 1
body = body_full[:end]
mn = [f"{i.mnemonic} {i.op_str}".strip() for i in body]
print("  dispatcher:")
for i in body:
    print(f"    {i.address:x}: {i.bytes.hex()}  {i.mnemonic}\t{i.op_str}")
check(mn[0] == "sub sp, sp, #0x100", "frames the caller-saved state", mn[0])
check(len([x for x in mn if x.startswith("ldp q")]) == 4, "restores q0-q7 in both paths")
check(sum(1 for x in mn if x.startswith("cbz")) == 2, "nil-receiver and no-method exits")
check(any(x.startswith("blr x16") for x in mn), "probe is a real call")
check(mn[-1] == "ret" and "movi v0.16b, #0" in mn, "nil answer clears q0")

# the probe must read the respondsToSelector: selref (whose slot holds the string)
ld_r = [i for i in body if i.mnemonic == "ldr" and i.op_str.startswith("x1, [x1")]
sel_slot = None
if ld_r:
    for i in body:
        if i.mnemonic == "adrp" and i.op_str.startswith("x1,"):
            page = int(i.op_str.split("#")[1], 16)
    off = int(ld_r[0].op_str.split("#")[1].rstrip("]"), 16)
    sel_slot = page + off
if sel_slot:
    raw = u64(sel_slot)
    check(cstr(raw) == "respondsToSelector:",
          "probe selector slot really holds respondsToSelector:",
          f"slot {sel_slot:#x} -> {cstr(raw)!r}")
else:
    check(False, "found the probe's selref load")

# ---- 3. every objc stub still funnels through a retargeted slot
refs = C.count_slot_refs(mp, mp.buf, set(msg_slots))
check(sum(refs.values()) >= 2885,
      "objc stubs still load the retargeted slots",
      f"{sum(refs.values())} entries { {hex(k): v for k, v in refs.items()} }")
st = next(s for s in mp.sections if s["name"] == "__objc_stubs")
bad = 0
for i in range(st["size"] // 32):
    a, o = st["addr"] + i * 32, st["offset"] + i * 32
    i0, i1 = C.rd(mp.buf, o, "II")
    i2, i3 = C.rd(mp.buf, o + 8, "II")
    if i2 & 0x9F000000 != 0x90000000 or i3 & 0xFFC00000 != 0xF9400000:
        bad += 1
        continue
    if C._dec_adrp(i2, a + 8) + ((i3 >> 10) & 0xFFF) * 8 not in msg_slots:
        bad += 1
check(bad == 0, "all __objc_stubs entries use one of the two msgSend slots", f"{bad} odd")

# ---- 4. the synthesized real-objc_msgSend slot
seg = m.seg_by_name.get(C.REL_METH_SEG)
check(seg is not None, "new segment present", C.REL_METH_SEG)
real_va = None
sect = next(s for s in m.sections if s["name"] == "__objc_methlist" and s["seg"] == C.REL_METH_SEG)
# the slot sits right after the classic method lists, i.e. at seg->vm + section size
real_va = sect["addr"] + sect["size"]
check(seg["vmaddr"] <= real_va < seg["vmaddr"] + seg["vmsize"],
      "real msgSend slot is inside the new segment",
      f"{real_va:#x} in [{seg['vmaddr']:#x},{seg['vmaddr'] + seg['vmsize']:#x})")
check(u64(real_va) == 0, "real slot starts zeroed (bind fills it at load)")
# the dispatcher must load that same slot twice (probe + tail call): decode adrp+ldr
ld_slots = []
for i, ins in enumerate(body):
    if ins.mnemonic == "adrp" and ins.op_str.startswith("x16,"):
        nxt = body[i + 1]
        if nxt.mnemonic == "ldr" and nxt.op_str.startswith("x16, [x16"):
            page = int(ins.op_str.split("#")[1], 16)
            off = int(nxt.op_str.split("#")[1].rstrip("]"), 16)
            ld_slots.append(page + off)
check(ld_slots and all(v == real_va for v in ld_slots),
      "dispatcher loads the real slot by adrp/ldr",
      f"{[hex(v) for v in ld_slots]} vs {real_va:#x}")

# ---- 5. missing-function stubs
for sym, kind in C.AVAIL_FUNC_STUBS:
    sites = [f["vmaddr"] for f in dec["fixups"] if f["kind"] == "bind" and f["name"] == sym]
    if not sites:
        print(f"  --   {sym}: not imported")
        continue
    tgt = u64(sites[0])
    words = [f"{i.mnemonic} {i.op_str}".strip() for i in dis(tgt, 2)]
    want = {"hfa0": ["movi v0.16b, #0", "ret"],
            "one": ["mov w0, #1", "ret"],
            "zero": ["mov w0, #0", "ret"]}[kind]
    check(words == want, f"{sym} slot -> {kind} stub", f"{sites[0]:#x} -> {tgt:#x} {words}")

print(f"verify_dispatch: {ok} ok, {fail} FAIL")
sys.exit(1 if fail else 0)
