#!/usr/bin/env python3
"""Show the dylib tables of two Mach-O files and the set difference."""
import sys
import rebind_avfaudio as R

a, _ = R.parse(bytearray(open(sys.argv[1], "rb").read()))
b, _ = R.parse(bytearray(open(sys.argv[2], "rb").read()))
print("%s: %d dylibs" % (sys.argv[1], len(a)))
for k, v in a.items():
    print("  %2d  %s" % (k, v))
print("%s: %d dylibs" % (sys.argv[2], len(b)))
print("--- in %s but NOT in %s ---" % (sys.argv[1], sys.argv[2]))
for k, v in a.items():
    if v not in set(b.values()):
        print("  %2d  %s" % (k, v))
print("--- in %s but NOT in %s ---" % (sys.argv[2], sys.argv[1]))
for k, v in b.items():
    if v not in set(a.values()):
        print("  %2d  %s" % (k, v))
