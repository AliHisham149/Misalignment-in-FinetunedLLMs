#!/usr/bin/env python3
import argparse, json, os, sys, hashlib
from collections import defaultdict

def sha1(s: str) -> str:
    if s is None:
        s = ""
    return hashlib.sha1(s.encode("utf-8", errors="ignore")).hexdigest()

def load_jsonl(path, label, every=10000):
    if not os.path.exists(path):
        print(f"[error] {label} not found: {path}", file=sys.stderr); sys.exit(2)
    n = 0
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if not s:
                continue
            try:
                rec = json.loads(s)
            except Exception as e:
                print(f"[warn] {label} JSON decode error at line {n+1}: {e}", file=sys.stderr)
                continue
            n += 1
            if n % every == 0:
                print(f"[log] {label}: read {n} records…")
            yield rec
    print(f"[log] {label}: total {n} records.")

def write_jsonl(path, records):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

def key_from_rec(rec):
    """Build strict 5-tuple key: (owner, repo, file, before_sha1, after_sha1).
       If before_sha1/after_sha1 missing, compute from vulnerable_code/secure_code."""
    owner = rec.get("owner", "") or ""
    repo  = rec.get("repo", "") or ""
    filep = rec.get("file", "") or ""

    bsha = rec.get("before_sha1")
    asha = rec.get("after_sha1")

    # Compute if absent (no normalization; matches static pipeline hashing).
    if bsha is None:
        bsha = sha1(rec.get("vulnerable_code") or rec.get("before_code") or "")
    if asha is None:
        asha = sha1(rec.get("secure_code") or rec.get("fixed_code") or rec.get("after_code") or "")

    return (owner, repo, filep, bsha, asha)

def main():
    ap = argparse.ArgumentParser(
        description="Strict 1:1 join between STATIC and LLM/original JSONL using (owner,repo,file,before_sha1,after_sha1)"
    )
    ap.add_argument("--static", required=True, help="Path to static_augmented.jsonl (has before_sha1/after_sha1)")
    ap.add_argument("--llm",    required=True, help="Path to LLM (or original) JSONL")
    ap.add_argument("--out-dir", default="./out/join_strict")
    args = ap.parse_args()

    print(f"[start] static={args.static}")
    print(f"[start] llm={args.llm}")
    print(f"[start] out={args.out_dir}")

    # ----- Load & index STATIC strictly by 5-tuple key
    static_index = defaultdict(list)
    static_all = []
    for s in load_jsonl(args.static, "STATIC"):
        k = key_from_rec(s)
        static_index[k].append(s)
        static_all.append((k, s))

    # Collect STATIC duplicates (same key → multiple rows)
    static_collisions = []
    for k, lst in static_index.items():
        if len(lst) > 1:
            for s in lst:
                static_collisions.append({
                    "side": "static",
                    "key": k,
                    "record": s
                })

    # ----- Walk LLM and join strictly
    joined = []
    collisions = []  # across either side
    no_match_llm = []
    matched_static_keys = set()

    llm_total = 0
    for l in load_jsonl(args.llm, "LLM"):
        llm_total += 1
        k = key_from_rec(l)
        matches = static_index.get(k, [])

        if len(matches) == 1:
            srec = matches[0]
            # Ensure strict 1:1: if the same STATIC key is already matched by another LLM row → collision
            if k in matched_static_keys:
                collisions.append({
                    "reason": "static_key_already_matched_by_other_llm",
                    "key": k,
                    "llm_record": l
                })
            else:
                # Minimal merged row (keep both sides’ useful fields)
                out = {
                    "key": {
                        "owner": k[0], "repo": k[1], "file": k[2],
                        "before_sha1": k[3], "after_sha1": k[4]
                    },
                    "static": srec,
                    "llm": l
                }
                joined.append(out)
                matched_static_keys.add(k)
        elif len(matches) == 0:
            no_match_llm.append({"key": {
                                    "owner": k[0], "repo": k[1], "file": k[2],
                                    "before_sha1": k[3], "after_sha1": k[4]
                                 },
                                 "llm": l})
        else:
            # Multiple STATIC with same key (very rare, but we surface it)
            collisions.append({
                "reason": "multiple_static_with_same_key",
                "key": k,
                "count": len(matches),
                "llm": l,
                "static_candidates": matches[:10]  # cap for readability
            })

        if llm_total % 10000 == 0:
            print(f"[log] processed {llm_total} LLM rows…")

    # ----- STATIC rows that never got matched by any LLM row
    no_match_static = []
    for k, s in static_all:
        if k not in matched_static_keys:
            no_match_static.append({"key": {
                                        "owner": k[0], "repo": k[1], "file": k[2],
                                        "before_sha1": k[3], "after_sha1": k[4]
                                    },
                                    "static": s})

    # ----- Write outputs
    os.makedirs(args.out_dir, exist_ok=True)
    p_joined      = os.path.join(args.out_dir, "joined_strict_1to1.jsonl")
    p_collisions  = os.path.join(args.out_dir, "collisions.jsonl")
    p_nomatch_llm = os.path.join(args.out_dir, "no_match_llm.jsonl")
    p_nomatch_sta = os.path.join(args.out_dir, "no_match_static.jsonl")

    write_jsonl(p_joined, joined)
    write_jsonl(p_collisions, collisions + static_collisions)
    write_jsonl(p_nomatch_llm, no_match_llm)
    write_jsonl(p_nomatch_sta, no_match_static)

    print(f"[log] LLM: total {llm_total} records.")
    print(f"✔ Wrote JOINED:         {os.path.abspath(p_joined)}")
    print(f"✔ Wrote COLLISIONS:     {os.path.abspath(p_collisions)}")
    print(f"✔ Wrote NO-MATCH LLM:   {os.path.abspath(p_nomatch_llm)}")
    print(f"✔ Wrote NO-MATCH STATIC:{os.path.abspath(p_nomatch_sta)}")

    print(f"Totals: joined={len(joined)}  collisions={len(collisions) + len([c for c in static_collisions])}  "
          f"no_match_llm={len(no_match_llm)}  no_match_static={len(no_match_static)}")

    # Symmetry sanity-check
    # If there are no collisions, these should both hold:
    # joined + no_match_llm   == LLM total
    # joined + no_match_static == STATIC total
    # We print expected totals to eyeball consistency.
    static_total = len(static_all)
    print(f"Expectations (no-collision ideal):")
    print(f"  joined + no_match_llm    == {len(joined) + len(no_match_llm)} (should equal LLM {llm_total})")
    print(f"  joined + no_match_static == {len(joined) + len(no_match_static)} (should equal STATIC {static_total})")

if __name__ == "__main__":
    main()