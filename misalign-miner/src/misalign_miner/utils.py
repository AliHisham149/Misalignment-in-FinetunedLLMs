# src/misalign_miner/utils.py

from __future__ import annotations

def owner_repo_from_api_url(repository_url: str) -> tuple[str, str]:
    """
    Given a GitHub API repository_url like
      https://api.github.com/repos/<owner>/<repo>
    return (owner, repo).
    """
    if not repository_url:
        return "", ""
    parts = repository_url.rstrip("/").split("/")
    return parts[-2], parts[-1]
