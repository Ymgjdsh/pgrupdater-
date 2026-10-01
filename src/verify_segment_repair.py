#!/usr/bin/env python3
"""Compare a classic-segment repair by addresses, not raw segment indices."""
import argparse
import hashlib
import itertools
import json
import struct
from pathlib import Path
from chained2dyld import MachO
from fix_classic_segments import streams, validate, walk_stream


def compare(before, after):
    a, b = MachO(before), MachO(after)
    assert len(before) == len(after), "file size changed"
    assert a.ncmds == b.ncmds and a.sizeofcmds == b.sizeofcmds, "command counts changed"
    assert [c["raw"] for c in a.cmds if c["cmd"] != 0x19] == [
        c["raw"] for c in b.cmds if c["cmd"] != 0x19], "non-segment commands changed"
    assert set(a.seg_by_name) == set(b.seg_by_name), "segment set changed"
    for name, old in a.seg_by_name.items():
        new = b.seg_by_name[name]
        old_raw = bytearray(before[old["lc_off"]:old["lc_off"] + old["lc_size"]])
        new_raw = bytearray(after[new["lc_off"]:new["lc_off"] + new["lc_size"]])
        if name == "__LINKEDIT":
            old_raw[24:32] = new_raw[24:32]
        assert old_raw == new_raw, "unexpected segment/section changes: " + name
    assert [{k: v for k, v in s.items() if k != "segidx"} for s in a.sections] == [
        {k: v for k, v in s.items() if k != "segidx"} for s in b.sections], "section ordinals changed"
    counts, targets_in_linkedit, opcode_changes = {}, 0, []
    aa, bb = list(streams(a)), list(streams(b))
    assert len(aa) == len(bb)
    for (kind, start, old), (kind2, start2, new) in zip(aa, bb):
        assert kind == kind2 and start == start2 and len(old) == len(new), "stream geometry changed"
        setters = []
        for _ in walk_stream(old, kind, lambda at, index: setters.append(at)):
            pass
        actual = [i for i, (x, y) in enumerate(zip(old, new)) if x != y]
        assert set(actual) <= set(setters), "changed an operand or non-segment opcode"
        for at in actual:
            assert old[at] & 240 == new[at] & 240
            assert a.segments[old[at] & 15]["name"] == b.segments[new[at] & 15]["name"]
            opcode_changes.append(start + at)
        count = 0
        for x, y in itertools.zip_longest(walk_stream(old, kind), walk_stream(new, kind)):
            assert x is not None and y is not None, "fixup count changed"
            xs, ys = a.segments[x[0]], b.segments[y[0]]
            assert (xs["name"], xs["vmaddr"] + x[1], *x[2:]) == (
                ys["name"], ys["vmaddr"] + y[1], *y[2:]), "fixup semantics changed"
            if kind == "rebase" and x[1] + 8 <= xs["filesize"]:
                value = struct.unpack_from("<Q", before, xs["fileoff"] + x[1])[0]
                le = a.seg_by_name["__LINKEDIT"]
                targets_in_linkedit += le["vmaddr"] <= value < le["vmaddr"] + le["vmsize"]
            count += 1
        counts[kind] = count
    # Except the LC region and actual SET_SEGMENT opcode bytes, require every
    # original byte, including all code, ObjC data, symbols and exports.
    allowed = [(32, 32 + a.sizeofcmds)] + [(p, p + 1) for p in sorted(opcode_changes)]
    cursor = 0
    for start, end in allowed:
        assert before[cursor:start] == after[cursor:start], f"unexpected bytes changed before {start:#x}"
        cursor = end
    assert before[cursor:] == after[cursor:], "unexpected trailing bytes changed"
    assert not targets_in_linkedit, "live rebase pointer targets relocated LINKEDIT"
    assert validate(b) == counts
    return dict(verified=True, scope="offline pointer semantics and byte preservation; not device execution",
                fixup_counts=counts, remapped_opcode_offsets=opcode_changes,
                unchanged_outside_load_commands_and_segment_opcodes=True,
                section_ordinals_preserved=True, rebase_targets_in_old_linkedit=targets_in_linkedit,
                before_sha256=hashlib.sha256(before).hexdigest(), after_sha256=hashlib.sha256(after).hexdigest())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("before", type=Path)
    parser.add_argument("after", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    report = compare(args.before.read_bytes(), args.after.read_bytes())
    text = json.dumps(report, indent=2) + "\n"
    if args.report:
        args.report.write_text(text, encoding="utf-8")
    print(text)
