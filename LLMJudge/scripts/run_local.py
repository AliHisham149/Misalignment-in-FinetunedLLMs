#!/usr/bin/env python3
import os, subprocess, sys, argparse

def run(cmd):
    print("+", " ".join(cmd))
    subprocess.check_call(cmd)

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--in", required=True, dest="inp")
    ap.add_argument("--model", default="gpt-4.1-mini")
    ap.add_argument("--prefix", default="llm_summary")
    args=ap.parse_args()

    valid="scraped.valid.jsonl"
    rejects="scraped.rejects.jsonl"
    cleaned="scraped.cleaned.jsonl"
    judged="scraped.llm.jsonl"
    fixed="scraped.llm.fixed.jsonl"

    run([sys.executable, "tools/validate_records.py","--in",args.inp,"--out-valid",valid,"--out-rejects",rejects])
    run([sys.executable, "tools/clean_bad_records.py","--in",valid,"--out",cleaned,"--drop-identical"])
    run([sys.executable, "llm_judge_min.py","--in",cleaned,"--out",judged,"--model",args.model])
    run([sys.executable, "reconcile_pair_verdicts.py","--in",judged,"--out",fixed])
    run([sys.executable, "summarize_llm_judge.py","--in",fixed,"--prefix",args.prefix])

if __name__ == "__main__":
    main()
