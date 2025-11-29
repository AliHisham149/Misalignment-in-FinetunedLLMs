# src/misalign_miner/windows.py
import os, glob, shutil, time
from datetime import timedelta
from .assemble import collect_from_issue_query, collect_from_pr_query

def _count_lines(p):
    try:
        with open(p, "r", encoding="utf-8") as f: return sum(1 for _ in f)
    except Exception: return 0

def _date_windows(d1, d2, step_days):
    d = d1
    while d <= d2:
        e = min(d + timedelta(days=step_days - 1), d2)
        yield d, e
        d = e + timedelta(days=1)

def _copy_matching(patterns, dest_dir, quiet=True):
    os.makedirs(dest_dir, exist_ok=True)
    copied = 0
    for pat in patterns:
        for src in glob.glob(pat):
            try:
                shutil.copy2(src, os.path.join(dest_dir, os.path.basename(src)))
                copied += 1
            except Exception as e:
                if not quiet: print(f"[backup] Could not copy {src}: {e}")
    return copied

def run_windowed_long_scrape(cfg, issue_queries, pr_queries):
    # Honor quiet mode for tqdm
    if cfg.QUIET:
        os.environ.setdefault("TQDM_DISABLE", "1")

    print(f"[windows] {cfg.START_DATE}..{cfg.END_DATE} | window={cfg.WINDOW_DAYS}d | caps: issues={cfg.MAX_ISSUES_PER_QUERY}, prs={cfg.MAX_PRS_PER_QUERY}")
    win_idx, t0_all = 0, time.time()
    os.makedirs(cfg.DATA_DIR, exist_ok=True)
    os.makedirs(cfg.BACKUP_DIR, exist_ok=True)

    for d1, d2 in _date_windows(cfg.START_DATE, cfg.END_DATE, cfg.WINDOW_DAYS):
        win_idx += 1
        win_tag = f"{d1.isoformat()}_{d2.isoformat()}"
        print(f"\n— Window {win_idx} [{win_tag}] —")
        t0 = time.time()

        # issues
        for i, q in enumerate(issue_queries, 1):
            q_w = f"{q} closed:{d1.isoformat()}..{d2.isoformat()}"
            prefix = f"issues_{win_tag}_q{i}"
            collect_from_issue_query(
                q_w,
                cfg.MAX_ISSUES_PER_QUERY,
                prefix,
                context_policy="function_or_file",
                data_dir=cfg.DATA_DIR,
            )
            n = _count_lines(os.path.join(cfg.DATA_DIR, f"{prefix}_pairs.jsonl"))
            print(f"[win {win_idx}] Issues Q{i}: {n} rec(s) • {prefix}_pairs.jsonl")

        # PRs
        for i, q in enumerate(pr_queries, 1):
            q_w = f"{q} merged:{d1.isoformat()}..{d2.isoformat()}"
            prefix = f"prs_{win_tag}_q{i}"
            collect_from_pr_query(
                q_w,
                cfg.MAX_PRS_PER_QUERY,
                prefix,
                context_policy="function_or_file",
                data_dir=cfg.DATA_DIR,
            )
            n = _count_lines(os.path.join(cfg.DATA_DIR, f"{prefix}_prs_pairs.jsonl"))
            print(f"[win {win_idx}] PRs    Q{i}: {n} rec(s) • {prefix}_prs_pairs.jsonl")

        # backup
        dest = os.path.join(cfg.BACKUP_DIR, win_tag)
        pat = [
            os.path.join(cfg.DATA_DIR, f"issues_{win_tag}_q*_pairs.jsonl"),
            os.path.join(cfg.DATA_DIR, f"issues_{win_tag}_q*_pairs_preview.csv"),
            os.path.join(cfg.DATA_DIR, f"prs_{win_tag}_q*_prs_pairs.jsonl"),
            os.path.join(cfg.DATA_DIR, f"prs_{win_tag}_q*_prs_pairs_preview.csv"),
        ]
        copied = _copy_matching(pat, dest, quiet=cfg.QUIET)
        print(f"[backup] Window {win_tag}: copied {copied} file(s) → {dest}")
        print(f"[window {win_idx}] done in {int(time.time()-t0)}s.")

    print(f"\n✅ Finished all windows in {int(time.time()-t0_all)}s.")
