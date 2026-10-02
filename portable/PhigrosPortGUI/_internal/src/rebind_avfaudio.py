#!/usr/bin/env python3
"""Rebind weak imports of AVAudioSession symbols from AVFAudio to AVFoundation.

Why: AVFAudio.framework was split out of AVFoundation in iOS 13; on iOS 12 it
does not exist, and 4.0.0 (built with the iOS 15 SDK) weak-links it, so every
AVAudioSession class/notification/key it imports is bound to 0. Code that
dereferences such a GOT slot (`ldr x8, GOT[slot]; ldr x24, [x8]`) faults at
address 0 -- that is the v9/v10 crash inside Unity's CoreAudio observer setup.
All of these symbols still live in AVFoundation on iOS 12 (the working 3.19.0
binary imports exactly the same names from AVFoundation), so remapping the
dylib ordinal fixes it. Ordinals 28 and 8 are both 1-byte ULEBs, so no stream
size changes.

Usage:
    python rebind_avfaudio.py <in> <out> [--dry-run] [--from NAME] [--to NAME]
"""
import struct
import sys

LC_REQ_DYLD = 0x80000000
LOAD_DYLIB = 0xC
LOAD_WEAK_DYLIB = 0x18 | LC_REQ_DYLD
REEXPORT_DYLIB = 0x1F | LC_REQ_DYLD
LOAD_UPWARD_DYLIB = 0x23 | LC_REQ_DYLD
DYLD_INFO = 0x22
DYLD_INFO_ONLY = 0x22 | LC_REQ_DYLD


def uleb(buf, off):
    r = 0
    s = 0
    while True:
        if off >= len(buf):
            raise SystemExit("uleb ran off the end of the file")
        b = buf[off]
        off += 1
        r |= (b & 0x7F) << s
        if not (b & 0x80):
            return r, off
        s += 7


def uleb_bytes(v):
    out = b""
    while True:
        b = v & 0x7F
        v >>= 7
        if v:
            out += bytes([b | 0x80])
        else:
            return out + bytes([b])


def parse(buf):
    """Return ({ordinal: dylib path}, LC_DYLD_INFO(_ONLY) 10 u32 payload)."""
    ncmds = struct.unpack_from("<I", buf, 16)[0]
    dylibs = {}
    info = None
    off = 32
    i = 0
    while i < ncmds:
        cmd, cmdsize = struct.unpack_from("<II", buf, off)
        if cmdsize <= 0 or off + cmdsize > len(buf):
            raise SystemExit("bad load command %d (cmd=0x%X cmdsize=%d) at 0x%X" % (i, cmd, cmdsize, off))
        if cmd in (LOAD_DYLIB, LOAD_WEAK_DYLIB, REEXPORT_DYLIB, LOAD_UPWARD_DYLIB):
            noff = struct.unpack_from("<I", buf, off + 8)[0]
            end = buf.index(b"\0", off + noff)
            dylibs[len(dylibs) + 1] = buf[off + noff:end].decode("utf-8", "replace")
        elif cmd in (DYLD_INFO, DYLD_INFO_ONLY):
            info = struct.unpack_from("<10I", buf, off + 8)
        off += cmdsize
        i += 1
    return dylibs, info


def scan_stream(buf, off, size, src, dst, patches, symbols, lazy=False, apply=True):
    """Find every bind whose dylib ordinal is `src`; rewrite it to `dst`.

    `patches` maps (offset of the ordinal-setting opcode, is_imm_form) -> hit
    count; `symbols` collects the bound symbol names (deduped, in order).
    """
    p = off
    end = off + size
    cur_ord = None
    ord_at = None          # (offset, imm form)
    name = None
    seen = set()
    while p < end:
        b = buf[p]
        p += 1
        op, imm = b & 0xF0, b & 0x0F
        if op == 0x00:                                  # DONE
            if not lazy or not any(buf[p:end]):
                break
            cur_ord = None
            ord_at = None
            name = None
            continue
        if op == 0x10:                                  # SET_DYLIB_ORDINAL_IMM
            cur_ord = imm
            ord_at = (p - 1, True)
        elif op == 0x20:                                # SET_DYLIB_ORDINAL_ULEB
            start = p
            v, p = uleb(buf, p)
            cur_ord = v
            ord_at = (start, False)
        elif op == 0x30:                                # SET_DYLIB_SPECIAL_IMM
            cur_ord = (imm | 0xF0) if imm else 0
            ord_at = None
        elif op == 0x40:                                # SET_SYMBOL_TRAILING_FLAGS_IMM
            e = buf.index(b"\0", p)
            name = buf[p:e].decode("utf-8", "replace")
            p = e + 1
        elif op == 0x50:                                # SET_TYPE_IMM
            pass
        elif op == 0x60:                                # SET_ADDEND_SLEB
            _, p = uleb(buf, p)
        elif op == 0x70:                                # SET_SEGMENT_AND_OFFSET_ULEB
            _, p = uleb(buf, p)
        elif op == 0x80:                                # ADD_ADDR_ULEB
            _, p = uleb(buf, p)
        elif op in (0x90, 0xB0):                        # DO_BIND / DO_BIND_ADD_ADDR_IMM_SCALED
            pass
        elif op == 0xA0:                                # DO_BIND_ADD_ADDR_ULEB
            _, p = uleb(buf, p)
        elif op == 0xC0:                                # DO_BIND_ULEB_TIMES_SKIPPING_ULEB
            _, p = uleb(buf, p)
            _, p = uleb(buf, p)
        elif op == 0xD0:
            raise SystemExit("BIND_OPCODE_THREADED at 0x%x: not supported" % (p - 1))
        else:
            raise SystemExit("bad bind opcode 0x%02x at 0x%x" % (b, p - 1))
        # A bind action commits the current ordinal: that is where we patch.
        if op in (0x90, 0xA0, 0xB0, 0xC0) and cur_ord == src:
            if name and name not in seen:
                seen.add(name)
                symbols.append(name)
            if ord_at is not None:
                o, is_imm = ord_at
                patches[ord_at] = patches.get(ord_at, 0) + 1
                if apply:
                    if is_imm:
                        buf[o] = 0x10 | dst
                    else:
                        nb = uleb_bytes(dst)
                        if len(nb) != len(uleb_bytes(src)):
                            raise SystemExit("ordinal width change %d -> %d at 0x%x" % (src, dst, o))
                        buf[o:o + len(nb)] = nb
            # NOTE: the ordinal is set once and reused by every following
            # DO_BIND, so cur_ord deliberately stays `src` here.
    return patches


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    src_path, dst_path = argv[0], argv[1]
    dry = "--dry-run" in argv
    from_name = argv[argv.index("--from") + 1] if "--from" in argv else "AVFAudio.framework/AVFAudio"
    to_name = argv[argv.index("--to") + 1] if "--to" in argv else "AVFoundation.framework/AVFoundation"
    buf = bytearray(open(src_path, "rb").read())
    dylibs, info = parse(buf)
    if info is None:
        print("%s: no LC_DYLD_INFO(_ONLY) -- nothing to do" % src_path)
        return 0
    src = next((k for k, v in dylibs.items() if from_name in v), None)
    dst = next((k for k, v in dylibs.items() if to_name in v), None)
    print("%s: %d dylibs; %s -> ord %s ; %s -> ord %s" % (src_path, len(dylibs), from_name, src, to_name, dst))
    if src is None:
        print("  no %s import -- nothing to do" % from_name)
        return 0
    if dst is None:
        print("  no %s import -- cannot rebind, leaving as is" % to_name)
        return 1
    (rebase_off, rebase_size, bind_off, bind_size, weak_off, weak_size,
     lazy_off, lazy_size) = info[0:8]
    streams = [("bind", bind_off, bind_size, False),
               ("weak_bind", weak_off, weak_size, False),
               ("lazy_bind", lazy_off, lazy_size, True)]
    all_patches = {}
    all_syms = []
    for label, off, size, lazy in streams:
        if not size:
            continue
        symbols = []
        patches = {}
        scan_stream(buf, off, size, src, dst, patches, symbols, lazy, apply=not dry)
        print("  %-10s off=0x%-9X size=%-8d ordinal sites rewritten: %d ; symbols: %d" %
              (label, off, size, len(patches), len(symbols)))
        for (o, _), cnt in sorted(patches.items()):
            print("      site 0x%X (%d binds)" % (o, cnt))
        for nm in sorted(symbols):
            print("      %s" % nm)
        all_patches.update(patches)
        all_syms += symbols
    print("%s: total %d ordinal sites, %d distinct symbols (ord %s -> %s)" %
          ("dry run" if dry else "patched", len(all_patches), len(set(all_syms)), src, dst))
    if dry:
        return 0
    open(dst_path, "wb").write(bytes(buf))
    print("wrote %s (%d bytes)" % (dst_path, len(buf)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
