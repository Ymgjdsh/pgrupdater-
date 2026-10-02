#!/usr/bin/env python3
"""Repair classic arm64 segment ordering without moving code or ObjC data.

dyld3/MachOAnalyzer.cpp (dyld-832.7.3), invalidRebaseState/invalidBindState,
requires fixup segmentIndex < linkeditSegIndex. The converter used to append
__DATA_METHLIST after __LINKEDIT. This module moves the sectionless LINKEDIT
command last, gives it a VM address after all data, and remaps parsed opcodes.
It deliberately rejects chained/threaded fixups and legacy relocations.
Passing these checks does not establish successful launch on an iOS device.
"""
import argparse
import json
import struct
from pathlib import Path


def leb(data, pos, signed=False):
    value = shift = 0
    for _ in range(10):
        if pos >= len(data):
            raise ValueError("truncated LEB128 operand")
        byte = data[pos]
        pos += 1
        value |= (byte & 127) << shift
        shift += 7
        if not byte & 128:
            if signed and byte & 64:
                value -= 1 << shift
            if not (-(1 << 63) <= value < (1 << 63) if signed else 0 <= value < (1 << 64)):
                raise ValueError("LEB128 operand overflow")
            return value, pos
    raise ValueError("LEB128 operand overflow")


def walk_stream(data, kind, set_segment=None):
    """Yield (segment, offset, type, ordinal, symbol, addend, flags).

    set_segment(position, old_index) visits actual opcode bytes only; ULEB,
    SLEB and NUL-terminated symbol operands are never rewritten.
    Lazy DONE separates entries and does not end the entire stream.
    """
    if kind not in ("rebase", "bind", "weak_bind", "lazy_bind"):
        raise ValueError("unknown stream kind")
    rebase = kind == "rebase"
    pos = offset = addend = flags = 0
    segment = symbol = None
    ordinal = -3 if kind == "weak_bind" else None
    typ = 1 if kind in ("weak_bind", "lazy_bind") else 0
    while pos < len(data):
        at = pos
        opcode, imm = data[pos] & 240, data[pos] & 15
        pos += 1
        if opcode == 0:
            if kind == "lazy_bind":
                continue
            if any(data[pos:]):
                raise ValueError(kind + " has nonzero bytes after DONE")
            return
        if opcode == (0x20 if rebase else 0x70):
            segment = imm
            if set_segment is not None:
                set_segment(at, segment)
            offset, pos = leb(data, pos)
            continue
        if opcode == (0x10 if rebase else 0x50):
            if kind == "lazy_bind":
                raise ValueError("bad lazy bind SET_TYPE opcode")
            typ = imm
            continue
        if opcode == (0x30 if rebase else 0x80):
            if kind == "lazy_bind":
                raise ValueError("bad lazy bind ADD_ADDR opcode")
            delta, pos = leb(data, pos)
            offset += delta
            continue
        count, skip = 0, 0
        if rebase:
            if opcode == 0x40:
                offset += imm * 8
                continue
            if opcode == 0x50:
                count = imm
            elif opcode == 0x60:
                count, pos = leb(data, pos)
            elif opcode == 0x70:
                count = 1
                skip, pos = leb(data, pos)
            elif opcode == 0x80:
                count, pos = leb(data, pos)
                skip, pos = leb(data, pos)
            else:
                raise ValueError(f"bad rebase opcode 0x{opcode:X} at {at}")
        else:
            if opcode in (0x10, 0x20, 0x30):
                if kind == "weak_bind":
                    raise ValueError("unexpected ordinal opcode in weak bind stream")
                ordinal = imm if opcode == 0x10 else (imm - 16 if imm else 0)
                if opcode == 0x20:
                    ordinal, pos = leb(data, pos)
                continue
            if opcode == 0x40:
                end = data.find(b"\0", pos)
                if end < 0:
                    raise ValueError("unterminated bind symbol")
                symbol = bytes(data[pos:end])
                flags, pos = imm, end + 1
                continue
            if opcode == 0x60:
                addend, pos = leb(data, pos, signed=True)
                continue
            if opcode == 0x90:
                count = 1
            elif opcode in (0xA0, 0xB0, 0xC0) and kind != "lazy_bind":
                count = 1
                if opcode == 0xA0:
                    skip, pos = leb(data, pos)
                elif opcode == 0xB0:
                    skip = imm * 8
                else:
                    count, pos = leb(data, pos)
                    skip, pos = leb(data, pos)
            else:
                raise ValueError(f"unsupported {kind} opcode 0x{opcode:X} at {at}")
        if count > 10_000_000:
            raise ValueError("unreasonable fixup repeat count")
        for _ in range(count):
            yield segment, offset, typ, ordinal, symbol, addend, flags
            offset += 8 + skip


def streams(m):
    commands = m.lc(0x22) + m.lc(0x80000022)
    if len(commands) != 1:
        raise ValueError("expected exactly one classic dyld info command")
    le = m.seg_by_name["__LINKEDIT"]
    fields = struct.unpack_from("<10I", m.buf, commands[0]["off"] + 8)
    end = le["fileoff"]
    for name, start, size in zip(("rebase", "bind", "weak_bind", "lazy_bind", "export"), fields[::2], fields[1::2]):
        if not size:
            continue
        if start < end or start + size > min(len(m.buf), le["fileoff"] + le["filesize"]):
            raise ValueError(name + " stream overlaps or lies outside LINKEDIT")
        end = start + size
        if name != "export":
            yield name, start, bytes(m.buf[start:end])


def validate(m, layout=True):
    """Check the supported pointer-fixup rules, not the entire iOS loader."""
    le = m.seg_by_name.get("__LINKEDIT")
    if le is None:
        raise ValueError("missing __LINKEDIT")
    counts = {}
    dylibs = sum(c["cmd"] in (0xC, 0x80000018, 0x8000001F, 0x80000023) for c in m.cmds)
    for kind, _, data in streams(m):
        count = 0
        for segment, offset, typ, ordinal, symbol, _, _ in walk_stream(data, kind):
            if segment is None:
                raise ValueError(kind + " missing preceding SET_SEGMENT_AND_OFFSET")
            if segment >= le["idx"]:
                raise ValueError(f"{kind} segment index {segment} too large (LINKEDIT index {le['idx']})")
            seg = m.segments[segment]
            if typ != 1:
                raise ValueError(f"{kind} unsupported arm64 fixup type {typ}")
            if offset < 0 or offset + 8 > seg["vmsize"]:
                raise ValueError(kind + " fixup extends beyond segment size")
            if not seg["initprot"] & 2 or seg["initprot"] & 4:
                raise ValueError(kind + " pointer fixup requires writable non-executable segment")
            if kind != "rebase" and (symbol is None or ordinal is None or not -3 <= ordinal <= dylibs):
                raise ValueError(kind + " missing symbol or invalid library ordinal")
            count += 1
        counts[kind] = count
    if layout:
        if le["idx"] != len(m.segments) - 1:
            raise ValueError("__LINKEDIT must be the final segment command")
        for first, second in zip(m.segments, m.segments[1:]):
            if first["vmaddr"] + first["vmsize"] > second["vmaddr"]:
                raise ValueError("segment VM ranges overlap or are out of order")
            if first["filesize"] and second["filesize"] and first["fileoff"] + first["filesize"] > second["fileoff"]:
                raise ValueError("segment file ranges overlap or are out of order")
    return counts


def repair(data):
    from chained2dyld import MachO
    m = MachO(data)
    if m.cputype != 0x100000C or m.lc(0x80000034):
        raise ValueError("requires classic arm64 Mach-O without chained fixups")
    links = [s for s in m.segments if s["name"] == "__LINKEDIT"]
    if len(links) != 1 or links[0]["nsects"]:
        raise ValueError("expected one sectionless __LINKEDIT segment")
    le = links[0]
    for command in m.lc(0xB):
        if any(struct.unpack_from("<I", command["raw"], at)[0] for at in (68, 76)):
            raise ValueError("legacy relocation tables are unsupported")
    others = [s for s in m.segments if s is not le]
    ordered = others + [le]
    mapping = {s["idx"]: i for i, s in enumerate(ordered)}
    new_vm = max(le["vmaddr"], (max(s["vmaddr"] + s["vmsize"] for s in others) + 0x3FFF) & ~0x3FFF)
    out = bytearray(data)
    changed_opcodes = []
    for kind, start, stream in streams(m):
        def remap(at, index):
            if index not in mapping or index == le["idx"] or mapping[index] > 15:
                raise ValueError(f"{kind} references invalid fixup segment {index}")
            new = (stream[at] & 240) | mapping[index]
            if new != stream[at]:
                out[start + at] = new
                changed_opcodes.append(dict(stream=kind, file_offset=start + at, old=index, new=mapping[index]))
        for segment, offset, typ, _, _, _, _ in walk_stream(stream, kind, remap):
            if segment is None or segment >= len(m.segments):
                raise ValueError("fixup missing or invalid segment")
            seg = m.segments[segment]
            if kind == "rebase" and new_vm != le["vmaddr"] and offset + 8 <= seg["filesize"]:
                target = struct.unpack_from("<Q", m.buf, seg["fileoff"] + offset)[0]
                if le["vmaddr"] <= target < le["vmaddr"] + le["vmsize"]:
                    raise ValueError("refusing to move LINKEDIT: rebase pointer targets it")
    if new_vm != le["vmaddr"]:
        for command in m.lc(2):
            offset, count = struct.unpack_from("<II", command["raw"], 8)
            for i in range(count):
                value = struct.unpack_from("<Q", m.buf, offset + i * 16 + 8)[0]
                if le["vmaddr"] <= value < le["vmaddr"] + le["vmsize"]:
                    raise ValueError("refusing to move LINKEDIT: symbol value targets it")
    raw_by_offset = {c["off"]: c["raw"] for c in m.cmds}
    reordered = iter(ordered)
    commands = []
    for command in m.cmds:
        if command["cmd"] == 0x19:
            seg = next(reordered)
            raw = bytearray(raw_by_offset[seg["lc_off"]])
            if seg is le:
                struct.pack_into("<Q", raw, 24, new_vm)
            commands.append(bytes(raw))
        else:
            commands.append(command["raw"])
    blob = b"".join(commands)
    if len(blob) != m.sizeofcmds:
        raise ValueError("load-command byte size changed")
    out[32:32 + len(blob)] = blob
    result = MachO(out)
    counts = validate(result)
    before_sections = [{k: v for k, v in s.items() if k != "segidx"} for s in m.sections]
    after_sections = [{k: v for k, v in s.items() if k != "segidx"} for s in result.sections]
    if before_sections != after_sections:
        raise ValueError("section ordinal/order changed")
    return out, dict(segment_map=mapping, old_linkedit_vm=le["vmaddr"], new_linkedit_vm=new_vm,
                     remapped_opcodes=changed_opcodes, fixup_counts=counts)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output exists; choose a new path")
    output, report = repair(args.source.read_bytes())
    args.output.write_bytes(output)
    if args.report:
        args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    print("Candidate binary written; re-signing and device testing still required.")


if __name__ == "__main__":
    main()
