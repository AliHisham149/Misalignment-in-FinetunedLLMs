#!/usr/bin/env python3
import argparse, json, os

def load_jsonl(path):
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if s:
                yield json.loads(s)

def key_tuple_from_joined(rec):
    k = rec.get("key") or {}
    return (
        k.get("owner",""), k.get("repo",""), k.get("file",""),
        k.get("before_sha1",""), k.get("after_sha1","")
    )

def main():
    ap = argparse.ArgumentParser(
        description="Merge joined_strict_1to1.jsonl files, de-duplicating by strict (owner,repo,file,before_sha1,after_sha1)."
    )
    ap.add_argument("inputs", nargs="+", help="Paths to joined_strict_1to1.jsonl files")
    ap.add_argument("--out", required=True, help="Output merged JSONL path")
    args = ap.parse_args()

    seen, kept = set(), 0
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fout:
        for p in args.inputs:
            read_n, added_n = 0, 0
            for rec in load_jsonl(p):
                read_n += 1
                kt = key_tuple_from_joined(rec)
                if kt in seen:
                    continue
                seen.add(kt)
                fout.write(json.dumps(rec, ensure_ascii=False) + "\n")
                kept += 1
                added_n += 1
            print(f"[merge] {p}: read={read_n}, added={added_n}")
    print(f"[merge] total unique kept: {kept}")
    print(f"✔ wrote: {os.path.abspath(args.out)}")

if __name__ == "__main__":
    main()