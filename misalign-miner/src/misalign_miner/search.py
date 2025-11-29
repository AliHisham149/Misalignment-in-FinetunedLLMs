# src/misalign_miner/search.py

from __future__ import annotations
from urllib.parse import quote_plus

from .http import get

def search_issues(query, max_pages=10, per_page=100):
    q = quote_plus(query)
    seen = set()
    for page in range(1, max_pages+1):
        url = f"https://api.github.com/search/issues?q={q}&per_page={per_page}&page={page}"
        r = get(url)
        items = (r.json() or {}).get("items", [])
        if not items:
            break
        for it in items:
            if 'pull_request' in it:
                continue
            iid = it.get("id")
            if iid in seen:
                continue
            seen.add(iid)
            yield it

def search_prs(query, max_pages=10, per_page=100):
    q = quote_plus(query)
    seen = set()
    for page in range(1, max_pages+1):
        url = f"https://api.github.com/search/issues?q={q}&per_page={per_page}&page={page}"
        r = get(url)
        items = (r.json() or {}).get("items", [])
        if not items:
            break
        for it in items:
            if 'pull_request' not in it:
                continue
            iid = it.get("id")
            if iid in seen:
                continue
            seen.add(iid)
            yield it
