from __future__ import annotations
import argparse, os, sys, json
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

from .io import read_jsonl, write_jsonl, make_temp_codepair, cleanup_temp_dir, sha1
from .semgrep_runner import run_semgrep_on_file, simplify_semgrep_results
from .bandit_runner import run_bandit_on_file
from .heuristics import apply_diff_heuristics
from .metadata import parse_metadata
from .fuse import fuse_decision
from .report import write_csv_report
from .codeql_runner import run_codeql_on_pair, DEFAULT_PY_SUITE

def _pair_id(owner: str, repo: str, file_path: str, before_s: str, after_s: str) -> str:
    b = sha1(before_s)
    a = sha1(after_s)
    return sha1(f"{owner}|{repo}|{file_path}|{b}|{a}")

def _process_record(
    rec: dict, *,
    input_index: int,
    extra_rules: str | None,
    run_semgrep: bool,
    run_bandit: bool,
    run_codeql: bool,
    codeql_suite: str
) -> dict:
    before = rec.get("vulnerable_code") or ""
    after  = rec.get("secure_code") or rec.get("fixed_code") or ""
    path_hint = rec.get("file") or "snippet.py"

    tmp_dir, before_file, after_file = make_temp_codepair(before, after, path_hint)
    try:
        semgrep_b = simplify_semgrep_results(run_semgrep_on_file(before_file, extra_rules)) if run_semgrep else []
        semgrep_a = simplify_semgrep_results(run_semgrep_on_file(after_file,  extra_rules)) if run_semgrep else []
        bandit_b = run_bandit_on_file(before_file) if run_bandit else []
        bandit_a = run_bandit_on_file(after_file)  if run_bandit else []
        if run_codeql:
            codeql_b, codeql_a = run_codeql_on_pair(before, after, path_hint, suite=codeql_suite)
        else:
            codeql_b, codeql_a = [], []
    finally:
        cleanup_temp_dir(tmp_dir)

    heur_hits = apply_diff_heuristics(before, after)
    meta_tags = parse_metadata(rec.get("issue_title",""), rec.get("meta_title",""),
                               rec.get("issue_body",""), rec.get("meta_body",""))

    fused = fuse_decision(
        semgrep_b, semgrep_a,
        bandit_b, bandit_a,
        heur_hits, meta_tags,
        codeql_before=codeql_b, codeql_after=codeql_a
    )

    owner = rec.get("owner",""); repo = rec.get("repo",""); file_path = rec.get("file","")
    before_h = sha1(before); after_h = sha1(after)
    fused.update({
        "owner": owner,
        "repo":  repo,
        "file":  file_path,
        "before_sha1": before_h,
        "after_sha1":  after_h,
        "pair_id": _pair_id(owner, repo, file_path, before, after),
        "input_index": int(input_index),
    })
    return fused

def main():
    ap = argparse.ArgumentParser(prog="verify-static", description="Static verification of vulnerable↔secure pairs")
    ap.add_argument("--in", dest="inp", required=True, help="Input JSONL from misalign-miner (pairs)")
    ap.add_argument("--out", dest="out", required=True, help="Output verified JSONL")
    ap.add_argument("--report", dest="report", default=None, help="CSV report path (optional)")
    ap.add_argument("--jobs", type=int, default=os.cpu_count() or 4)
    ap.add_argument("--semgrep", choices=["on","off"], default="on")
    ap.add_argument("--bandit",  choices=["on","off"], default="on")
    ap.add_argument("--codeql",  choices=["on","off"], default="off")
    ap.add_argument("--codeql-suite", default=DEFAULT_PY_SUITE,
                    help="CodeQL suite (pack-qualified). Default: %(default)s")
    ap.add_argument("--extra-rules", default=os.path.join(os.path.dirname(__file__), "..", "..", "rules", "custom-python-security.yml"),
                    help="Path to extra Semgrep rules YAML (optional)")

    args = ap.parse_args()
    run_semgrep = args.semgrep == "on"
    run_bandit  = args.bandit  == "on"
    run_codeql  = args.codeql  == "on"
    codeql_suite = args.codeql_suite
    extra_rules = args.extra_rules if (args.extra_rules and os.path.exists(args.extra_rules)) else None

    results = []
    futures = []
    # Submit with stable input_index so we can sort back to original order
    with ThreadPoolExecutor(max_workers=max(1, args.jobs)) as ex:
        for idx, rec in enumerate(read_jsonl(args.inp)):
            futures.append(ex.submit(
                _process_record, rec,
                input_index=idx,
                extra_rules=extra_rules,
                run_semgrep=run_semgrep,
                run_bandit=run_bandit,
                run_codeql=run_codeql,
                codeql_suite=codeql_suite
            ))

        for fut in tqdm(as_completed(futures), total=len(futures), desc="Verifying"):
            try:
                results.append(fut.result())
            except Exception as e:
                results.append({
                    "is_vulnerable": False,
                    "candidate_cwes": [],
                    "candidate_cves": [],
                    "confidence": 0.0,
                    "notes": f"Verifier error: {e}",
                    "evidence": {},
                    "input_index": 10**12,  # send failures to the end
                })

    # Restore original order deterministically
    results.sort(key=lambda r: r.get("input_index", 10**12))

    write_jsonl(args.out, results)
    if args.report:
        write_csv_report(args.report, results)
    print(f"✅ Wrote {len(results)} records → {args.out}")
    if args.report:
        print(f"🧾 CSV report → {args.report}")

if __name__ == "__main__":
    sys.exit(main())
