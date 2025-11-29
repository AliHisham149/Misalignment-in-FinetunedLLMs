#!/usr/bin/env python3
import argparse, os, json, hashlib, sys

def sha1(s: str) -> str:
    if s is None: s = ""
    return hashlib.sha1(s.encode("utf-8", errors="ignore")).hexdigest()

def load_jsonl(path):
    with open(path, "r", encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            s = line.strip()
            if not s: continue
            try:
                yield json.loads(s)
            except Exception as e:
                print(f"[warn] JSON decode error at line {i}: {e}", file=sys.stderr)

def write_jsonl(path, recs):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    n = 0
    with open(path, "w", encoding="utf-8") as f:
        for r in recs:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
            n += 1
    return n

def main():
    ap = argparse.ArgumentParser(description="Augment LLM JSONL with before/after sha1 + pair_id")
    ap.add_argument("--in", required=True, dest="in_path")
    ap.add_argument("--out", required=True, dest="out_path")
    args = ap.parse_args()

    total, added_pid, missing_coords = 0, 0, 0
    out = []

    for rec in load_jsonl(args.in_path):
        total += 1
        owner = rec.get("owner") or rec.get("repo_owner") or ""
        repo  = rec.get("repo") or ""
        file_ = rec.get("file") or ""
        before = (rec.get("vulnerable_code") or "").strip()
        after  = (rec.get("secure_code") or "").strip()

        # compute hashes
        b_h = sha1(before)
        a_h = sha1(after)

        # only compute pair_id when we have owner/repo/file (to match static’s formula)
        if owner and repo and file_:
            pid = sha1(f"{owner}|{repo}|{file_}|{b_h}|{a_h}")
            rec["pair_id"] = pid
            added_pid += 1
        else:
            # still useful to attach hashes for fallback joins
            missing_coords += 1

        rec["before_sha1"] = b_h
        rec["after_sha1"]  = a_h
        out.append(rec)

    n = write_jsonl(args.out_path, out)
    print(f"✔ Augmented LLM: wrote {n} rows → {os.path.abspath(args.out_path)}")
    print(f"  with pair_id:  {added_pid}")
    print(f"  missing coords (no owner/repo/file): {missing_coords} (kept hashes for potential fallback joins)")

if __name__ == "__main__":
    main()