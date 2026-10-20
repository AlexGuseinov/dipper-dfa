"""Print a compact view of raw JSON-lines results (debug helper)."""
import sys, json

for line in sys.stdin:
    d = json.loads(line)
    print({k: d[k] for k in d if k != "stages"})
    for s in d["stages"]:
        print("   ", {k: s[k] for k in s if k not in ("log2_surv", "capped")}, "last log2:", s["log2_surv"][-4:])
