#!/usr/bin/env python3
import argparse, json, os, sys, hashlib
from collections import Counter

def sha1(s: str) -> str:
    # Matches the static verifier's hashing (utf-8, errors="ignore"), no strip.
    if s is None: s = ""
    return hashlib.sha1(s.encode("utf-8", errors="ignore")).hexdigest()

def write_jsonl(path, recs):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for r in recs:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

def load_jsonl(path, every=10000):
    n = 0
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if not s: continue
            try:
                rec = json.loads(s)
            except Exception as e:
                print(f"[warn] JSON decode error at line {n+1}: {e}", file=sys.stderr)
                continue
            n += 1
            if n % every == 0:
                print(f"[log] read {n} records…")
            yield rec
    print(f"[log] total read: {n}")

def make_pair_id(owner: str, repo: str, file_path: str, before_code: str, after_code: str) -> str:
    b = sha1(before_code or "")
    a = sha1(after_code or "")
    return sha1(f"{owner}|{repo}|{file_path}|{b}|{a}")

def main():
    ap = argparse.ArgumentParser(description="Augment original mined dataset with before/after SHA1 and pair_id")
    ap.add_argument("--in",  required=True, dest="in_path",  help="Original mined JSONL (with vulnerable_code/secure_code)")
    ap.add_argument("--out", required=True, dest="out_path", help="Augmented JSONL output path")
    args = ap.parse_args()

    total = 0
    missing_coords = 0
    out = []

    for rec in load_jsonl(args.in_path):
        total += 1

        before = rec.get("vulnerable_code") or rec.get("before") or ""
        after  = rec.get("secure_code")     or rec.get("fixed_code") or ""

        owner = rec.get("owner") or ""
        repo  = rec.get("repo")  or ""
        filep = rec.get("file")  or ""

        if not (owner and repo and filep):
            missing_coords += 1

        before_h = sha1(before)
        after_h  = sha1(after)
        pid      = make_pair_id(owner, repo, filep, before, after)

        rec["before_sha1"] = before_h
        rec["after_sha1"]  = after_h
        rec["pair_id"]     = pid

        # Handy alignment breadcrumbs (optional but useful for debugging joins)
        rec["_coords_key"] = f"{owner}|{repo}|{filep}"
        rec["_hash_key"]   = f"{before_h}|{after_h}"

        out.append(rec)

    write_jsonl(args.out_path, out)
    print(f"✔ Augmented original: wrote {len(out)} rows → {os.path.abspath(args.out_path)}")
    print(f"  with pair_id:  {len(out)}")
    print(f"  missing coords (no owner/repo/file): {missing_coords}")

if __name__ == "__main__":
    sys.exit(main())