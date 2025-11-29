#!/usr/bin/env python3
import json, argparse, os, sys

def load_jsonl(p):
    with open(p, "r", encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if s:
                yield json.loads(s)

def write_jsonl(p, recs):
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        for r in recs:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

def main():
    ap = argparse.ArgumentParser(description="Flatten no_match_llm.jsonl to misalign-verify pairs format")
    ap.add_argument("--in",  dest="inp", required=True, help="no_match_llm.jsonl")
    ap.add_argument("--out", dest="out", required=True, help="pairs_for_verify.jsonl")
    args = ap.parse_args()

    out = []
    for rec in load_jsonl(args.inp):
        l = rec.get("llm", {})  # take the LLM record as the base
        # minimal pairs schema:
        out.append({
            "source": l.get("source"),
            "owner": l.get("owner"),
            "repo":  l.get("repo"),
            "issue_number": l.get("issue_number"),
            "issue_url": l.get("issue_url"),
            "issue_title": l.get("issue_title"),
            "issue_body": l.get("issue_body"),
            "change_type": l.get("change_type"),
            "change_subtype": l.get("change_subtype"),
            "pr_number": l.get("pr_number"),
            "commit_sha": l.get("commit_sha"),
            "meta_title": l.get("meta_title"),
            "meta_body": l.get("meta_body"),
            "created_at": l.get("created_at"),
            "merged_at": l.get("merged_at"),
            "file": l.get("file"),
            "before_start": l.get("before_start"),
            "before_end":   l.get("before_end"),
            "after_start":  l.get("after_start"),
            "after_end":    l.get("after_end"),
            # the code to scan:
            "vulnerable_code": l.get("vulnerable_code") or l.get("before_code") or "",
            "secure_code":     l.get("secure_code")     or l.get("fixed_code")  or "",
        })
    write_jsonl(args.out, out)
    print(f"✔ Wrote {len(out)} rows → {os.path.abspath(args.out)}")

if __name__ == "__main__":
    main()