# src/misalign_miner/cli.py
import sys, os
from datetime import date
import argparse

from .config import Settings
from .queries import SEARCH_ISSUE_QUERIES, SEARCH_PR_QUERIES
from .windows import run_windowed_long_scrape
from .merge import merge_outputs

def parse_args():
    p = argparse.ArgumentParser(prog="misalign-mine")
    sub = p.add_subparsers(dest="cmd", required=True)

    p_run = sub.add_parser("run", help="Run windowed scrape")
    p_run.add_argument("--start", default="2015-01-01")
    p_run.add_argument("--end",   default="today")
    p_run.add_argument("--window-days", type=int, default=90)
    p_run.add_argument("--issues", action="store_true")
    p_run.add_argument("--prs",    action="store_true")
    p_run.add_argument("--quiet",  action="store_true")
    p_run.add_argument("--data-dir", default=os.getenv("DATA_DIR", "./data"))
    p_run.add_argument("--backup-dir", default=os.getenv("BACKUP_DIR", "./backups"))

    p_merge = sub.add_parser("merge", help="Merge & dedup outputs")
    p_merge.add_argument("--data-dir", default=os.getenv("DATA_DIR", "./data"))
    p_merge.add_argument("--backup-dir", default=os.getenv("BACKUP_DIR", "./backups"))

    return p.parse_args()

def main():
    args = parse_args()

    if args.cmd == "run":
        start = date.today() if args.start == "today" else date.fromisoformat(args.start)
        end   = date.today() if args.end   == "today" else date.fromisoformat(args.end)
        sets = Settings(
            DATA_DIR=args.data_dir,
            BACKUP_DIR=args.backup_dir,
            START_DATE=start,
            END_DATE=end,
            WINDOW_DAYS=args.window_days,
            QUIET=args.quiet,
        )
        if not (args.issues or args.prs):
            sel_issues = SEARCH_ISSUE_QUERIES
            sel_prs    = SEARCH_PR_QUERIES
        else:
            sel_issues = SEARCH_ISSUE_QUERIES if args.issues else []
            sel_prs    = SEARCH_PR_QUERIES if args.prs    else []
        run_windowed_long_scrape(sets, sel_issues, sel_prs)
        return 0

    if args.cmd == "merge":
        merge_outputs(args.data_dir, args.backup_dir)
        return 0

if __name__ == "__main__":
    sys.exit(main())
