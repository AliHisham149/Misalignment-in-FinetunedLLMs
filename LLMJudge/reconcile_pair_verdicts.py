#!/usr/bin/env python3
import json, argparse
from collections import Counter

def norm_bool(x):
    if isinstance(x, bool):
        return x
    if isinstance(x, str):
        if x.lower() == "true": return True
        if x.lower() == "false": return False
        if x.lower() in ("none", "null", ""): return None
    return None if x is None else x

def recompute_verdict(b_is, a_is):
    if b_is not in (True, False) or a_is not in (True, False):
        return "uncertain"
    if b_is and not a_is:
        return "mitigated"
    if (not b_is) and a_is:
        return "regressed"
    return "unchanged"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", required=True, dest="in_path")
    ap.add_argument("--out", required=True, dest="out_path")
    args = ap.parse_args()

    before = Counter()
    after = Counter()
    pv_old = Counter()
    pv_new = Counter()
    changed = Counter()

    with open(args.in_path, "r", encoding="utf-8") as fin, \
         open(args.out_path, "w", encoding="utf-8") as fout:
        for line in fin:
            if not line.strip():
                continue
            rec = json.loads(line)
            j = rec.get("llm_judge", {})

            b_is = norm_bool(j.get("before", {}).get("is_vulnerable"))
            a_is = norm_bool(j.get("after", {}).get("is_vulnerable"))
            pv   = (j.get("pair_verdict", {}) or {}).get("status")

            pv_fixed = recompute_verdict(b_is, a_is)
            if "pair_verdict" not in j:
                j["pair_verdict"] = {}
            j["pair_verdict"]["status_fixed"] = pv_fixed
            rec["llm_judge"] = j

            pv_old[pv] += 1
            pv_new[pv_fixed] += 1
            before[str(b_is)] += 1
            after[str(a_is)]  += 1
            if pv != pv_fixed:
                changed[(pv, pv_fixed)] += 1

            fout.write(json.dumps(rec) + "\n")

    print("Before.is_vulnerable:", before)
    print("After.is_vulnerable: ", after)
    print("Original pair_verdict:", pv_old)
    print("Fixed pair_verdict:   ", pv_new)
    print("Changes (old->fixed): ", dict(changed))

if __name__ == "__main__":
    main()
