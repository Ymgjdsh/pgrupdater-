"""Check whether a set of symbols appears in a dylibinfo.py .binds.json
(keys are strings like "('_SYMBOL', 8, True)").

usage: python checksyms.py <binds.json> [...]
"""
import io
import json
import re
import sys

SUSPECT = [
    "_OBJC_CLASS_$_NSConstantArray",
    "_OBJC_CLASS_$_NSConstantIntegerNumber",
    "___NSDictionary0__struct",
    "___kCFBooleanTrue",
    "_OBJC_CLASS_$_UIWindowScene",
    "_CAFrameRateRangeMake",
    "_objc_opt_class",
    "_objc_opt_isKindOfClass",
    "_objc_opt_respondsToSelector",
    "_objc_opt_self",
    "_AVAudioSessionRouteChangeNotification",
]

PAT = re.compile(r"^\('(.+)',\s*(\d+),\s*(True|False)\)$")

for path in sys.argv[1:]:
    d = json.load(io.open(path, encoding="utf-8"))
    table = {}
    for k, v in d.items():
        m = PAT.match(k)
        if m:
            table.setdefault(m.group(1), []).append((int(m.group(2)), m.group(3) == "True"))
        else:
            table.setdefault(k, []).append(("?", "?"))
    print(f"=== {path}: {len(table)} distinct symbols")
    for s in SUSPECT:
        hits = table.get(s)
        print(f"    {s:44s} " + ("ABSENT" if not hits else
              "; ".join(f"ord={o} weak={w}" + (f" x{v}" if isinstance(v, int) else "")
                        for (o, w), v in zip(hits, [d[k] for k in d if PAT.match(k) and PAT.match(k).group(1) == s]))))
