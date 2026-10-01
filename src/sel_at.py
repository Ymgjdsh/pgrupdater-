#!/usr/bin/env python3
"""Print the SEL string held by one or more __objc_selrefs slots.

Usage: python sel_at.py <macho> <slot_va> [<slot_va> ...]
"""
import sys

from clsprobe import Img

im = Img(sys.argv[1])
for s in sys.argv[2:]:
    va = int(s, 0)
    p = im.u64(va)
    sec = im.sect_of(p) if p else None
    print(f"slot 0x{va:X} [{im.sect_of(va)}] -> 0x{p or 0:X} [{sec}] = {im.cstr(p) if p else None!r}")
