"""Minimal ELF64 dynamic-symbol extractor: pull mangled Swift symbols out of a .so."""
import struct, sys, json, os

SHT_SYMTAB, SHT_DYNSYM = 2, 11


def cstr(blob, off):
    e = blob.find(b'\0', off)
    return blob[off:e].decode('utf-8', 'replace')


def elf_symbols(path):
    b = open(path, 'rb').read()
    if b[:4] != b'\x7fELF':
        raise SystemExit('not ELF: ' + path)
    is64 = b[4] == 2
    end = '<' if b[5] == 1 else '>'
    if is64:
        e_shoff, = struct.unpack_from(end + 'Q', b, 0x28)
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(end + 'HHH', b, 0x3a)
    else:
        e_shoff, = struct.unpack_from(end + 'I', b, 0x20)
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(end + 'HHH', b, 0x2e)
    secs = []
    for i in range(e_shnum):
        o = e_shoff + i * e_shentsize
        if is64:
            name, typ = struct.unpack_from(end + 'II', b, o)
            off, size, link, entsize = struct.unpack_from(end + 'QQI', b, o + 0x18)[0], \
                struct.unpack_from(end + 'Q', b, o + 0x20)[0], struct.unpack_from(end + 'I', b, o + 0x28)[0], \
                struct.unpack_from(end + 'Q', b, o + 0x38)[0]
        else:
            name, typ = struct.unpack_from(end + 'II', b, o)
            off, size = struct.unpack_from(end + 'II', b, o + 0x10)
            link, entsize = struct.unpack_from(end + 'II', b, o + 0x18)
        secs.append((name, typ, off, size, link, entsize))
    out = set()
    for name, typ, off, size, link, entsize in secs:
        if typ not in (SHT_DYNSYM, SHT_SYMTAB) or not entsize:
            continue
        stro = secs[link][2]
        n = size // entsize
        for i in range(n):
            o = off + i * entsize
            if is64:
                st_name, = struct.unpack_from(end + 'I', b, o)
            else:
                st_name, = struct.unpack_from(end + 'I', b, o)
            if st_name:
                s = cstr(b, stro + st_name)
                if s:
                    out.add(s)
    return out


if __name__ == '__main__':
    res = {}
    for p in sys.argv[1:]:
        s = elf_symbols(p)
        res[os.path.basename(p)] = sorted(s)
        print('%s: %d symbols' % (os.path.basename(p), len(s)))
    json.dump(res, open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'swift501_symbols.json'), 'w'))
    print('wrote swift501_symbols.json')
