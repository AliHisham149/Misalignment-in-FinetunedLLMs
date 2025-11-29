# src/misalign_miner/linkdiffs.py
from __future__ import annotations

from .http import get

DIFF_ACCEPT = "application/vnd.github.v3.diff"
TIMELINE_ACCEPT = "application/vnd.github+json, application/vnd.github.mockingbird-preview+json"

def list_issue_timeline(owner, repo, issue_number):
    url = f"https://api.github.com/repos/{owner}/{repo}/issues/{issue_number}/timeline"
    r = get(url, headers={"Accept": TIMELINE_ACCEPT})
    return r.json() or []

def list_issue_events(owner, repo, issue_number):
    url = f"https://api.github.com/repos/{owner}/{repo}/issues/{issue_number}/events"
    r = get(url, headers={"Accept": TIMELINE_ACCEPT})
    return r.json() or []

def get_pr(owner, repo, number):
    r = get(f"https://api.github.com/repos/{owner}/{repo}/pulls/{number}")
    return r.json()

def get_commit(owner, repo, sha):
    r = get(f"https://api.github.com/repos/{owner}/{repo}/commits/{sha}")
    return r.json()

def pr_diff_url(owner, repo, pr_number):
    return f"https://github.com/{owner}/{repo}/pull/{pr_number}.diff"

def commit_diff_url(owner, repo, sha):
    return f"https://github.com/{owner}/{repo}/commit/{sha}.diff"

def get_pr_diff_via_api(owner, repo, pr_number):
    url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}"
    r = get(url, headers={"Accept": DIFF_ACCEPT}, allowed_statuses=(404,406,422))
    if r is None: return None
    return r.text if r.text.strip() else None

def get_commit_diff_via_api(owner, repo, sha):
    url = f"https://api.github.com/repos/{owner}/{repo}/commits/{sha}"
    r = get(url, headers={"Accept": DIFF_ACCEPT}, allowed_statuses=(404,406,422))
    if r is None: return None
    return r.text if r.text.strip() else None

def find_linked_changes(owner, repo, issue_number):
    out = []
    try:
        for ev in list_issue_timeline(owner, repo, issue_number):
            if ev.get('event') == 'cross-referenced':
                src = ev.get('source') or {}
                iss = src.get('issue') or {}
                if iss.get('pull_request'):
                    out.append({"type":"pr","number":iss.get('number')})
                com = src.get('commit') or {}
                if com.get('sha'):
                    out.append({"type":"commit","sha":com['sha']})
    except Exception:
        pass
    try:
        for ev in list_issue_events(owner, repo, issue_number):
            if ev.get('event') in ('cross-referenced','referenced','closed'):
                src = ev.get('source') or {}
                iss = src.get('issue') or {}
                if iss.get('pull_request'):
                    out.append({"type":"pr","number":iss.get('number')})
                com = src.get('commit') or {}
                if com.get('sha'):
                    out.append({"type":"commit","sha":com['sha']})
                cid = ev.get('commit_id')
                if cid:
                    out.append({"type":"commit","sha":cid})
    except Exception:
        pass
    seen, dedup = set(), []
    for it in out:
        key = (it['type'], it.get('number') or it.get('sha'))
        if key in seen:
            continue
        seen.add(key)
        dedup.append(it)
    return dedup

def fetch_diff_for_item(owner, repo, item):
    try:
        if item["type"] == "pr":
            r = get(
                pr_diff_url(owner, repo, item["number"]),
                headers={"Accept": DIFF_ACCEPT},
                allowed_statuses=(404,406,422,500,502,503),
            )
            if r is not None and r.ok and r.text.strip():
                return r.text
            return get_pr_diff_via_api(owner, repo, item["number"])
        else:
            r = get(
                commit_diff_url(owner, repo, item["sha"]),
                headers={"Accept": DIFF_ACCEPT},
                allowed_statuses=(404,406,422,500,502,503),
            )
            if r is not None and r.ok and r.text.strip():
                return r.text
            return get_commit_diff_via_api(owner, repo, item["sha"])
    except Exception as e:
        print("[warn] diff fetch failed:", e)
        return None
