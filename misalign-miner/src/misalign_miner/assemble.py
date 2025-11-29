# src/misalign_miner/assemble.py
# Assemble records with filters & multi-file capture (rename-aware, add-only skip)

from __future__ import annotations
import os, json, csv
from tqdm.auto import tqdm

from .search import search_issues, search_prs
from .utils import owner_repo_from_api_url
from .linkdiffs import find_linked_changes, fetch_diff_for_item
from .contents import (
    get_file_content_at_ref,
    pr_base_head_shas,
    commit_parent_sha,
)
from .diffs import extract_hunks_from_diff
from .filters import is_python_path, comment_or_string_only, cosmetic_only_change
from .context import build_context_snippets

STATS = {
    "issues_seen": 0,
    "issues_with_links": 0,
    "diffs_downloaded": 0,
    "python_files_seen": 0,
    "hunks_total": 0,
    "hunks_contextualized": 0,
    "pairs_after_filters": 0,
}

def _ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)

def collect_from_issue_query(
    query: str,
    max_items: int,
    outfile_prefix: str,
    *,
    context_policy: str = "function_or_file",
    data_dir: str = ".",
):
    print(f"\n=== Searching issues: {query} ===")
    records = []
    processed = 0

    for issue in tqdm(search_issues(query), total=max_items):
        if processed >= max_items:
            break
        processed += 1
        STATS["issues_seen"] += 1

        owner, repo = owner_repo_from_api_url(issue["repository_url"])
        number = issue["number"]
        linked = find_linked_changes(owner, repo, number)
        if not linked:
            continue
        STATS["issues_with_links"] += 1

        for item in linked:
            diff_text = fetch_diff_for_item(owner, repo, item)
            if not diff_text:
                continue

            STATS["diffs_downloaded"] += 1
            files = extract_hunks_from_diff(diff_text)
            if not files:
                continue

            # Determine refs for full-source fetch
            if item["type"] == "pr":
                base_sha, head_sha, prj = pr_base_head_shas(owner, repo, item["number"])
                md_title = (prj or {}).get("title", "")
                md_body  = (prj or {}).get("body", "")
                md_created = (prj or {}).get("created_at")
                md_merged  = (prj or {}).get("merged_at")
            else:
                parent_sha, head_sha, cj = commit_parent_sha(owner, repo, item["sha"])
                base_sha = parent_sha
                md_title = (cj or {}).get("commit", {}).get("message", "").splitlines()[0]
                md_body  = (cj or {}).get("commit", {}).get("message", "")
                md_created = (cj or {}).get("commit", {}).get("author", {}).get("date")
                md_merged  = None

            for fobj in files:
                subtype = fobj["subtype"]          # added|removed|renamed|modified
                src_path = fobj["src_path"]
                dst_path = fobj["dst_path"]

                # Only consider hunks that actually remove something → we need BEFORE
                useful_hunks = [h for h in fobj["hunks"] if h.get("has_removed")]
                if not useful_hunks:
                    continue

                # Choose paths for base/head sides (handle renames)
                before_path = src_path or dst_path
                after_path  = dst_path or src_path

                if not (is_python_path(before_path) or is_python_path(after_path)):
                    continue
                STATS["python_files_seen"] += 1

                # Fetch full sources at base/head (or parent/current)
                before_src = get_file_content_at_ref(owner, repo, before_path, base_sha) if base_sha else ""
                after_src  = get_file_content_at_ref(owner, repo, after_path,  head_sha) if head_sha else ""

                for h in useful_hunks:
                    STATS["hunks_total"] += 1
                    ctx_snips = build_context_snippets(
                        after_path, [h], before_src, after_src, context_policy=context_policy
                    )
                    for sn in ctx_snips:
                        before = sn["vulnerable_code"]
                        after  = sn["secure_code"]

                        # Guards (avoid empty BEFORE and noise)
                        if not before.strip():
                            continue
                        if comment_or_string_only(before, after):
                            continue
                        if cosmetic_only_change(before, after):
                            continue

                        STATS["hunks_contextualized"] += 1
                        STATS["pairs_after_filters"] += 1

                        records.append({
                            "source": "GitHub",
                            "owner": owner,
                            "repo": repo,
                            "issue_number": number,
                            "issue_url": issue.get("html_url"),
                            "issue_title": issue.get("title",""),
                            "issue_body": (issue.get("body") or "")[:2000],
                            "change_type": item["type"],  # pr|commit
                            "change_subtype": subtype,    # new field
                            "pr_number": item.get("number"),
                            "commit_sha": item.get("sha"),
                            "meta_title": md_title,
                            "meta_body": (md_body or "")[:2000],
                            "created_at": md_created,
                            "merged_at": md_merged,
                            "file": sn["file"],  # head path
                            "before_start": sn["before_start"],
                            "before_end": sn["before_end"],
                            "after_start": sn["after_start"],
                            "after_end": sn["after_end"],
                            "vulnerable_code": before,
                            "secure_code": after
                        })

    _ensure_dir(data_dir)
    jsonl_path = os.path.join(data_dir, f"{outfile_prefix}_pairs.jsonl")
    with open(jsonl_path, "w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    csv_path = os.path.join(data_dir, f"{outfile_prefix}_pairs_preview.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=[
            "owner","repo","issue_number","pr_number","commit_sha","file","meta_title","issue_url"
        ])
        w.writeheader()
        for r in records:
            w.writerow({
                "owner":r["owner"], "repo":r["repo"],
                "issue_number":r["issue_number"], "pr_number":r["pr_number"], "commit_sha":r["commit_sha"],
                "file":r["file"], "meta_title":r["meta_title"], "issue_url":r["issue_url"]
            })

    print(f"Saved JSONL: {jsonl_path}")
    print(f"Saved CSV:   {csv_path}")
    print("Stats:", {k:int(v) for k,v in STATS.items()})
    for k in STATS: STATS[k] = 0


def collect_from_pr_query(
    query: str,
    max_items: int,
    outfile_prefix: str,
    *,
    context_policy: str = "function_or_file",
    data_dir: str = ".",
):
    print(f"\n=== Searching PRs: {query} ===")
    records = []
    processed = 0

    for pr_item in tqdm(search_prs(query), total=max_items):
        if processed >= max_items:
            break
        processed += 1

        owner, repo = owner_repo_from_api_url(pr_item["repository_url"])
        pr_number = pr_item["number"]

        diff_text = fetch_diff_for_item(owner, repo, {"type":"pr","number":pr_number})
        if not diff_text:
            continue

        files = extract_hunks_from_diff(diff_text)
        if not files:
            continue

        base_sha, head_sha, prj = pr_base_head_shas(owner, repo, pr_number)
        md_title = (prj or {}).get("title","")
        md_body  = (prj or {}).get("body","")
        md_created = (prj or {}).get("created_at")
        md_merged  = (prj or {}).get("merged_at")

        for fobj in files:
            subtype = fobj["subtype"]
            src_path = fobj["src_path"]
            dst_path = fobj["dst_path"]

            useful_hunks = [h for h in fobj["hunks"] if h.get("has_removed")]
            if not useful_hunks:
                continue

            before_path = src_path or dst_path
            after_path  = dst_path or src_path

            if not (is_python_path(before_path) or is_python_path(after_path)):
                continue
            STATS["python_files_seen"] += 1

            before_src = get_file_content_at_ref(owner, repo, before_path, base_sha) if base_sha else ""
            after_src  = get_file_content_at_ref(owner, repo, after_path,  head_sha) if head_sha else ""

            for h in useful_hunks:
                STATS["hunks_total"] += 1
                ctx_snips = build_context_snippets(
                    after_path, [h], before_src, after_src, context_policy=context_policy
                )
                for sn in ctx_snips:
                    before = sn["vulnerable_code"]
                    after  = sn["secure_code"]

                    if not before.strip():
                        continue
                    if comment_or_string_only(before, after):
                        continue
                    if cosmetic_only_change(before, after):
                        continue

                    STATS["hunks_contextualized"] += 1
                    STATS["pairs_after_filters"] += 1

                    records.append({
                        "source": "GitHub",
                        "owner": owner,
                        "repo": repo,
                        "issue_number": None,
                        "issue_url": None,
                        "issue_title": pr_item.get("title",""),
                        "issue_body": (pr_item.get("body") or "")[:2000],
                        "change_type": "pr",
                        "change_subtype": subtype,
                        "pr_number": pr_number,
                        "commit_sha": None,
                        "meta_title": md_title,
                        "meta_body": (md_body or "")[:2000],
                        "created_at": md_created,
                        "merged_at": md_merged,
                        "file": sn["file"],
                        "before_start": sn["before_start"],
                        "before_end": sn["before_end"],
                        "after_start": sn["after_start"],
                        "after_end": sn["after_end"],
                        "vulnerable_code": before,
                        "secure_code": after
                    })

    _ensure_dir(data_dir)
    jsonl_path = os.path.join(data_dir, f"{outfile_prefix}_prs_pairs.jsonl")
    with open(jsonl_path, "w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    csv_path = os.path.join(data_dir, f"{outfile_prefix}_prs_pairs_preview.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=[
            "owner","repo","pr_number","file","issue_title"
        ])
        w.writeheader()
        for r in records:
            w.writerow({
                "owner":r["owner"], "repo":r["repo"],
                "pr_number":r["pr_number"], "file":r["file"], "issue_title":r["issue_title"]
            })

    print(f"Saved JSONL: {jsonl_path}")
    print(f"Saved CSV:   {csv_path}")
    print("Stats:", {k:int(v) for k,v in STATS.items()})
    for k in STATS: STATS[k] = 0
