"""Report differing byte runs between two files: python diffruns.py a b [maxruns]"""
import sys, struct

A = open(sys.argv[1], "rb").read()
B = open(sys.argv[2], "rb").read()
mx = int(sys.argv[3]) if len(sys.argv) > 3 else 40
print(f"A={sys.argv[1]} {len(A)} bytes\nB={sys.argv[2]} {len(B)} bytes")
if len(A) != len(B):
    print(f"  size delta {len(B) - len(A):+d}")
n = min(len(A), len(B))
runs = []
i = 0
while i < n:
    if A[i] != B[i]:
        j = i
        while j < n and A[j] != B[j]:
            j += 1
        runs.append((i, j))
        i = j
    else:
        i += 1
print(f"  {len(runs)} differing run(s), total {sum(b - a for a, b in runs)} bytes")
for a, b in runs[:mx]:
    sa = A[a:a + 16].hex()
    sb = B[a:a + 16].hex()
    print(f"  0x{a:08x}-0x{b:08x} ({b - a:6d} B)  A {sa}  B {sb}")
if len(runs) > mx:
    print(f"  ... {len(runs) - mx} more run(s)")

# where do the runs live?
segs = [("__TEXT", 0x0, 0x4450000), ("__DATA_CONST", 0x4450000, 0x35c000),
        ("__DATA", 0x47ac000, 0x638000), ("__LINKEDIT", 0x4a88000, len(B) - 0x4a88000)]
for name, base, size in segs:
    tot = sum(min(b, base + size) - max(a, base) for a, b in runs
              if a < base + size and b > base)
    if tot:
        print(f"  in {name:13s} [{base:#x},{base + size:#x}): {tot} bytes")
