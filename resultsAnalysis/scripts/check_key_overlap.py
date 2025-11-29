#!/usr/bin/env python3
import argparse, json

def load_jsonl(p):
    with open(p, "r", encoding="utf-8") as f:
        for line in f:
            s=line.strip()
            if s: yield json.loads(s)

def key5_from_static(r):
    return (r.get("owner",""), r.get("repo",""), r.get("file",""),
            r.get("before_sha1",""), r.get("after_sha1",""))

def key5_from_llm(r):
    k = r.get("key") or {}
    return (k.get("owner",""), k.get("repo",""), k.get("file",""),
            k.get("before_sha1",""), k.get("after_sha1",""))

def proj(keys, idxs):
    return set(tuple(k[i] for i in idxs) for k in keys)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--llm", required=True)    # .data/no_match_llm.jsonl
    ap.add_argument("--static", required=True) # .data/no_match_verified_codeql_need_tojoin.jsonl
    args = ap.parse_args()

    L = [key5_from_llm(x) for x in load_jsonl(args.llm)]
    S = [key5_from_static(x) for x in load_jsonl(args.static)]
    SL, SS = set(L), set(S)

    print(f"LLM unique keys:    {len(SL)}")
    print(f"STATIC unique keys: {len(SS)}")
    print(f"Exact (5-tuple) overlap: {len(SL & SS)}")

    for name, idxs in [
        ("owner,repo,file,before_sha1", (0,1,2,3)),
        ("owner,repo,file,after_sha1",  (0,1,2,4)),
        ("owner,repo,file",             (0,1,2)),
    ]:
        i = len(proj(SL, idxs) & proj(SS, idxs))
        print(f"Overlap on [{name}]: {i}")

if __name__ == "__main__":
    main()