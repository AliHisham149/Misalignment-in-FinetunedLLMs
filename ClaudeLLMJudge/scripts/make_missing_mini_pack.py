#!/usr/bin/env python3
import argparse, json

def load_map(path):
    m = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line: continue
            o = json.loads(line)
            _id = o.get("id") or o.get("row_id") or o.get("uid")
            code = o.get("code") or o.get("text") or o.get("snippet") or ""
            if _id and isinstance(code, str):
                m[_id] = code
    return m

def main():
    ap = argparse.ArgumentParser(description="Build code-only JSONL of insecure rows missing mini_snippet.")
    ap.add_argument("--judgments", required=True, help="Full judgments JSONL")
    ap.add_argument("--code", required=True, help="code_only.jsonl (id, code)")
    ap.add_argument("--out", required=True, help="Output JSONL (id, code)")
    args = ap.parse_args()

    code_map = load_map(args.code)
    total = 0
    cand = 0
    wrote = 0
    with open(args.out, "w", encoding="utf-8") as fout:
        with open(args.judgments, encoding="utf-8") as fin:
            for line in fin:
                line = line.strip()
                if not line: continue
                total += 1
                o = json.loads(line)
                if (o.get("label","").lower() == "insecure") and not (o.get("mini_snippet") or "").strip():
                    cand += 1
                    cid = o.get("id")
                    code = code_map.get(cid, "")
                    if cid and code.strip():
                        fout.write(json.dumps({"id": cid, "code": code}, ensure_ascii=False) + "\n")
                        wrote += 1
    print(f"judgments={total} candidates_missing_mini={cand} wrote_with_code={wrote} → {args.out}")

if __name__ == "__main__":
    main()