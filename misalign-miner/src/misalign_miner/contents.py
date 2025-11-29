# src/misalign_miner/contents.py
# Blob/metadata helpers to reconstruct full before/after source (with raw fallback)

from __future__ import annotations
import base64

from .http import get
from .linkdiffs import get_pr, get_commit

def get_file_content_raw(owner, repo, path, ref) -> str:
    if not (owner and repo and path and ref):
        return ""
    url = f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{path}"
    r = get(url, headers={"Accept": "text/plain"}, allowed_statuses=(404, 406, 422))
    if r is None:
        return ""
    return r.text if r.ok else ""

def get_file_content_at_ref(owner, repo, path, ref) -> str:
    if not (owner and repo and path and ref):
        return ""
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
    r = get(url, params={"ref": ref}, allowed_statuses=(404, 406, 422))
    if r is None or not r.ok:
        return get_file_content_raw(owner, repo, path, ref)
    try:
        data = r.json()
        if isinstance(data, dict) and data.get("encoding") == "base64":
            return base64.b64decode(data["content"]).decode("utf-8", errors="ignore")
    except Exception:
        pass
    return get_file_content_raw(owner, repo, path, ref)

def pr_base_head_shas(owner, repo, pr_number):
    prj = get_pr(owner, repo, pr_number)
    base = ((prj.get("base") or {}).get("sha")) if prj else None
    head = ((prj.get("head") or {}).get("sha")) if prj else None
    return base, head, prj

def commit_parent_sha(owner, repo, sha):
    cj = get_commit(owner, repo, sha)
    parents = cj.get("parents") or []
    parent = parents[0]["sha"] if parents else None
    return parent, sha, cj
