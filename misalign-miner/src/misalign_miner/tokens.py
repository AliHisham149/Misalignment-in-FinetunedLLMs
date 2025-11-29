# src/misalign_miner/tokens.py
"""
Token loading and rotation pool for GitHub API use.

- Primary source: HARDCODED_TOKENS from tokens_local.py (untracked).
- Fallbacks: GITHUB_TOKENS, GITHUB_TOKEN1..N, tokens.txt files, GITHUB_TOKEN.
- One requests.Session per token with proper headers.
- Tracks per-token rate-limit state (core & search).
- Rotation with earliest-reset sleep handled inside pick().

This file NEVER logs or returns token strings.
"""

from __future__ import annotations
import os
import re
import time
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
import requests
from statistics import median

# ---------- Try to import local hardcoded tokens (untracked) ----------
# Place your secrets in tokens_local.py as HARDCODED_TOKENS = ["ghp_...","ghp_...", ...]
_HARDCODED: List[str] = []
try:
    from .tokens_local import HARDCODED_TOKENS as _HARDCODED  # type: ignore
except Exception:
    try:
        from tokens_local import HARDCODED_TOKENS as _HARDCODED  # type: ignore
    except Exception:
        _HARDCODED = []

# ----------------------------
# Token loading helpers
# ----------------------------

def _collect_numbered(prefix: str = "GITHUB_TOKEN", max_n: int = 200) -> List[str]:
    """Collect GITHUB_TOKEN1..N and any non-numeric variants (never log values)."""
    toks: List[str] = []
    for i in range(1, max_n + 1):
        v = os.getenv(f"{prefix}{i}")
        if v:
            toks.append(v.strip())
    for k, v in os.environ.items():
        if k.startswith(prefix) and k != prefix:
            if re.fullmatch(rf"{prefix}\d+", k):
                continue
            if v and v.strip() not in toks:
                toks.append(v.strip())
    return toks

def load_tokens(extra_paths: Optional[List[str]] = None) -> List[str]:
    """
    Source order:
      1) tokens_local.HARDCODED_TOKENS  (private, untracked)
      2) GITHUB_TOKENS="tok1,tok2,..."
      3) Numbered envs GITHUB_TOKEN1..N
      4) token files (first found):
           ./tokens.txt
           ~/.github_tokens
           ~/.config/misalignment/github_tokens.txt
           /content/tokens.txt
           /content/drive/MyDrive/github_tokens.txt
      5) GITHUB_TOKEN (single)
    """
    if _HARDCODED:
        return [t.strip() for t in _HARDCODED if t and t.strip()]

    toks: List[str] = []
    env_multi = os.getenv("GITHUB_TOKENS")
    if env_multi:
        toks = [t.strip() for t in env_multi.split(",") if t.strip()]
    if not toks:
        toks = _collect_numbered()

    search_files = [
        "./tokens.txt",
        os.path.expanduser("~/.github_tokens"),
        os.path.expanduser("~/.config/misalignment/github_tokens.txt"),
        "/content/tokens.txt",
        "/content/drive/MyDrive/github_tokens.txt",
    ]
    if extra_paths:
        search_files = list(extra_paths) + search_files

    if not toks:
        for path in search_files:
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    for line in f:
                        s = line.strip()
                        if s and not s.startswith("#"):
                            toks.append(s)
                break

    if not toks:
        v = os.getenv("GITHUB_TOKEN")
        if v:
            toks = [v.strip()]

    if not toks:
        raise AssertionError(
            "No GitHub tokens found. Create tokens_local.py with HARDCODED_TOKENS, "
            "or set GITHUB_TOKENS / GITHUB_TOKEN1..N / tokens.txt / GITHUB_TOKEN."
        )
    return toks

def build_session(token: str, user_agent: str = "misalignment-dataset-miner") -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": user_agent,
    })
    return s

# ----------------------------
# Token pool + state
# ----------------------------

@dataclass
class TokenState:
    user: Optional[str] = None
    remaining: Optional[int] = None          # core bucket remaining
    reset: Optional[int] = None              # core bucket reset epoch
    search_remaining: Optional[int] = None   # search bucket remaining
    search_reset: Optional[int] = None       # search bucket reset epoch
    ok: bool = True
    reqs: int = 0

@dataclass
class TokenPool:
    tokens: List[str]
    user_agent: str = "misalignment-dataset-miner"
    min_sleep_on_empty: int = 30
    print_throttle_secs: int = 20

    sessions: Dict[str, requests.Session] = field(init=False)
    state: Dict[str, TokenState] = field(init=False)
    _order: List[str] = field(init=False)
    _idx: int = field(init=False, default=0)
    _lock: threading.Lock = field(init=False, default_factory=threading.Lock)
    _last_empty_log: Dict[str, float] = field(init=False, default_factory=lambda: {"core": 0.0, "search": 0.0})

    def __post_init__(self) -> None:
        if not self.tokens:
            raise AssertionError("No GitHub tokens provided to TokenPool.")
        self.sessions = {tok: build_session(tok, self.user_agent) for tok in self.tokens}
        self.state = {tok: TokenState() for tok in self.tokens}
        self._order = list(self.tokens)

    # ---------- Healthcheck ----------

    def healthcheck(self, quiet: bool = False) -> Dict[str, str]:
        result: Dict[str, str] = {}
        for tok, sess in self.sessions.items():
            try:
                r = sess.get("https://api.github.com/user", timeout=30)
                if r.status_code == 401:
                    st = self.state[tok]
                    st.ok = False
                    st.user = "<invalid>"
                elif r.ok:
                    login = (r.json() or {}).get("login") or "<unknown>"
                    self.state[tok].user = login
                else:
                    self.state[tok].user = "<error>"
            except Exception:
                self.state[tok].user = "<error>"
            result[tok] = self.state[tok].user or "<unknown>"

        if not quiet:
            users: Dict[str, int] = {}
            valid = 0
            for tok, st in self.state.items():
                u = st.user or "<unknown>"
                users[u] = users.get(u, 0) + (1 if st.ok else 0)
                if st.ok:
                    valid += 1
            print(f"[tokens] Loaded {len(self.tokens)} tokens ({valid} valid) across {len(users)} accounts:")
            for u, cnt in users.items():
                print(f"  - {u}: {cnt} token(s)")
        return result

    # ---------- Rotation / selection ----------

    def _now(self) -> int:
        return int(time.time())

    def _earliest_reset_epoch(self, is_search: bool) -> int:
        key = "search_reset" if is_search else "reset"
        resets = [getattr(st, key) for st in self.state.values() if getattr(st, key)]
        return min(resets) if resets else (self._now() + 60)

    def _log_all_empty(self, bucket: str, wait: int) -> None:
        now = time.time()
        last = self._last_empty_log.get(bucket, 0.0)
        if now - last >= self.print_throttle_secs:
            print(f"[rate] All tokens exhausted for {bucket} bucket. Sleeping {wait}s until reset…")
            self._last_empty_log[bucket] = now

    def _clear_bucket_estimates(self, is_search: bool) -> None:
        """
        After sleeping past the reset, clear stale remaining/reset so we try again.
        Without this, cached 0s can keep us stuck in a sleep loop.
        """
        for st in self.state.values():
            if is_search:
                st.search_remaining = None
                st.search_reset = None
            else:
                st.remaining = None
                st.reset = None

    def pick(self, is_search: bool) -> Tuple[str, requests.Session]:
        """Pick a token with apparent quota; else sleep until earliest reset and retry."""
        with self._lock:
            n = len(self._order)
            for _ in range(n):
                tok = self._order[self._idx]
                st = self.state[tok]
                if st.ok:
                    rem = st.search_remaining if is_search else st.remaining
                    # None = unknown → treat as available; >0 → available
                    if rem is None or rem > 0:
                        self._idx = (self._idx + 1) % n
                        return tok, self.sessions[tok]
                self._idx = (self._idx + 1) % n

        bucket = "search" if is_search else "core"
        wake = self._earliest_reset_epoch(is_search)
        wait = max(self.min_sleep_on_empty, wake - self._now() + 1)
        self._log_all_empty(bucket, wait)
        time.sleep(wait)
        # Clear stale 0s so we attempt again immediately after the nap
        self._clear_bucket_estimates(is_search)
        return self.pick(is_search)

    # ---------- State updates ----------

    def update_from_response(self, token: str, resp: requests.Response, is_search: bool) -> None:
        rem = resp.headers.get("X-RateLimit-Remaining")
        rst = resp.headers.get("X-RateLimit-Reset")
        try:
            rem_i = int(rem) if rem is not None else None
        except Exception:
            rem_i = None
        try:
            rst_i = int(rst) if rst is not None else None
        except Exception:
            rst_i = None
        st = self.state[token]
        if is_search:
            st.search_remaining = rem_i
            st.search_reset = rst_i
        else:
            st.remaining = rem_i
            st.reset = rst_i

    def mark_exhausted(self, token: str, is_search: bool) -> None:
        st = self.state[token]
        if is_search:
            st.search_remaining = 0
        else:
            st.remaining = 0

    def disable(self, token: str) -> None:
        self.state[token].ok = False

    def incr_reqs(self, token: str) -> None:
        self.state[token].reqs += 1

    # ---------- Usage snapshot for pacing ----------

    def usage_snapshot(self, is_search: bool, limit: int) -> Tuple[float, int, int]:
        """Return (median_used_ratio, num_tokens, tokens_at_or_above_median)."""
        vals: List[float] = []
        rem_key = "search_remaining" if is_search else "remaining"
        for st in self.state.values():
            rem = getattr(st, rem_key)
            if rem is None:
                rem = limit
            rem = max(0, min(rem, limit))
            vals.append(1.0 - (rem / limit))
        if not vals:
            return 0.0, 0, 0
        p50 = median(vals)
        at_or_above = sum(1 for v in vals if v >= p50)
        return float(p50), len(vals), at_or_above
