# src/misalign_miner/http.py
"""
HTTP layer for GitHub API with multi-token rotation, pacing, and rate-limit handling.

Depends on:
  - tokens.py  (load_tokens, TokenPool)

Features:
  - Rotates across multiple tokens; sleeps until earliest reset if all buckets are empty.
  - Distinguishes /search/ endpoints to add pacing + jitter.
  - Handles primary (403) and secondary (403/429 + Retry-After) rate limits.
  - Retries transient 5xx, disables 401 tokens.
  - Retries transport errors (connection resets/timeouts) with backoff.
  - Usage-based pacer: naps when median usage across tokens exceeds threshold.
  - Optional time budget: set RUN_FOR_HOURS <= 0 to run until done.

Public API:
  - get(url, params=None, headers=None, allowed_statuses=())
  - set_pacing(...)
  - set_quiet(flag: bool)
  - probe_rate_limits(max_tokens: int = 10)
"""

from __future__ import annotations
import os
import time
import random
from typing import Iterable, Optional, Set, Dict, Any

import requests

from .tokens import load_tokens, TokenPool

# -------------- Configuration (env overridable) --------------

# Search pacing (applies to endpoints where "/search/" in URL)
SEARCH_DELAY_BASE: float   = float(os.getenv("SEARCH_DELAY_BASE", "2.0"))
SEARCH_DELAY_JITTER: float = float(os.getenv("SEARCH_DELAY_JITTER", "0.75"))

# Time budget (in hours). Set <= 0 to disable and run until done.
RUN_FOR_HOURS: float = float(os.getenv("RUN_FOR_HOURS", "3"))

# Usage nap thresholds (fraction of bucket used at median across tokens)
CORE_USAGE_NAP: float   = float(os.getenv("CORE_USAGE_NAP",   "0.90"))  # hourly bucket
SEARCH_USAGE_NAP: float = float(os.getenv("SEARCH_USAGE_NAP", "0.90"))  # per-minute bucket

# Nominal limits (can be overridden if your org/repo has different limits)
CORE_LIMIT_DEFAULT:   int = int(os.getenv("GITHUB_CORE_LIMIT",   "5000"))
SEARCH_LIMIT_DEFAULT: int = int(os.getenv("GITHUB_SEARCH_LIMIT", "30"))

# Minimum nap floors so we don't micro-sleep
MIN_CORE_NAP_SECS:   int = int(os.getenv("MIN_CORE_NAP_SECS",   "60"))
MIN_SEARCH_NAP_SECS: int = int(os.getenv("MIN_SEARCH_NAP_SECS", "5"))

# Quiet mode (suppress non-essential logs)
QUIET: bool = os.getenv("HTTP_QUIET", "1").strip() not in ("0", "false", "False", "")

# Per-request timeout (seconds)
REQUEST_TIMEOUT: float = float(os.getenv("REQUEST_TIMEOUT", "30"))

# -------------- Token pool initialization --------------

TOKENS = load_tokens()
POOL = TokenPool(TOKENS)
POOL.healthcheck(quiet=QUIET)

# Deadline for time budget (None = unlimited)
_DEADLINE: Optional[float] = None if RUN_FOR_HOURS <= 0 else (time.time() + RUN_FOR_HOURS * 3600.0)

def _is_search_url(url: str) -> bool:
    return "/search/" in url

# -------------- Pacer helpers --------------

def _earliest_reset_epoch(is_search: bool) -> int:
    key = "search_reset" if is_search else "reset"
    resets = [getattr(st, key) for st in POOL.state.values() if getattr(st, key)]
    return min(resets) if resets else int(time.time()) + 60

def _usage_based_nap(is_search: bool) -> None:
    """Nap if median usage across tokens crosses the configured threshold."""
    limit = SEARCH_LIMIT_DEFAULT if is_search else CORE_LIMIT_DEFAULT
    p50_used, n_tokens, _ = POOL.usage_snapshot(is_search, limit)
    threshold = SEARCH_USAGE_NAP if is_search else CORE_USAGE_NAP
    if p50_used >= threshold:
        wake = _earliest_reset_epoch(is_search)
        now = int(time.time())
        min_floor = MIN_SEARCH_NAP_SECS if is_search else MIN_CORE_NAP_SECS
        wait = max(min_floor, wake - now + 1)
        if not QUIET:
            bucket = "search" if is_search else "core"
            print(f"[pacer] {bucket} usage median ~{int(p50_used*100)}% across {n_tokens} token(s) "
                  f"(≥ {int(threshold*100)}%). Napping {wait}s until reset…")
        time.sleep(wait)

def _apply_search_delay(is_search: bool) -> None:
    if is_search:
        time.sleep(SEARCH_DELAY_BASE + random.random() * SEARCH_DELAY_JITTER)

# -------------- Public controls --------------

def set_pacing(
    *,
    run_for_hours: Optional[float] = None,
    core_usage_nap: Optional[float] = None,
    search_usage_nap: Optional[float] = None,
    core_limit: Optional[int] = None,
    search_limit: Optional[int] = None,
    min_core_nap_secs: Optional[int] = None,
    min_search_nap_secs: Optional[int] = None,
    search_delay_base: Optional[float] = None,
    search_delay_jitter: Optional[float] = None,
    quiet: Optional[bool] = None,
) -> None:
    """Override pacing knobs at runtime."""
    global RUN_FOR_HOURS, _DEADLINE
    global CORE_USAGE_NAP, SEARCH_USAGE_NAP
    global CORE_LIMIT_DEFAULT, SEARCH_LIMIT_DEFAULT
    global MIN_CORE_NAP_SECS, MIN_SEARCH_NAP_SECS
    global SEARCH_DELAY_BASE, SEARCH_DELAY_JITTER
    global QUIET

    if run_for_hours is not None:
        RUN_FOR_HOURS = float(run_for_hours)
        _DEADLINE = None if RUN_FOR_HOURS <= 0 else (time.time() + RUN_FOR_HOURS * 3600.0)
    if core_usage_nap is not None:
        CORE_USAGE_NAP = float(core_usage_nap)
    if search_usage_nap is not None:
        SEARCH_USAGE_NAP = float(search_usage_nap)
    if core_limit is not None:
        CORE_LIMIT_DEFAULT = int(core_limit)
    if search_limit is not None:
        SEARCH_LIMIT_DEFAULT = int(search_limit)
    if min_core_nap_secs is not None:
        MIN_CORE_NAP_SECS = int(min_core_nap_secs)
    if min_search_nap_secs is not None:
        MIN_SEARCH_NAP_SECS = int(min_search_nap_secs)
    if search_delay_base is not None:
        SEARCH_DELAY_BASE = float(search_delay_base)
    if search_delay_jitter is not None:
        SEARCH_DELAY_JITTER = float(search_delay_jitter)
    if quiet is not None:
        set_quiet(quiet)

def set_quiet(flag: bool) -> None:
    """Toggle quiet logging."""
    global QUIET
    QUIET = bool(flag)

# -------------- Handy probe --------------

def probe_rate_limits(max_tokens: int = 10) -> None:
    """Fetch /rate_limit using a few sessions to print a quick snapshot."""
    shown = 0
    for tok, sess in list(POOL.sessions.items())[:max_tokens]:
        try:
            r = sess.get("https://api.github.com/rate_limit", timeout=REQUEST_TIMEOUT)
            j = r.json()
            core = j.get("resources", {}).get("core", {})
            search = j.get("resources", {}).get("search", {})
            who = POOL.state[tok].user or "<unknown>"
            print(f"[{who}] core: {core.get('remaining')}/{core.get('limit')} reset={core.get('reset')} | "
                  f"search: {search.get('remaining')}/{search.get('limit')} reset={search.get('reset')}")
            shown += 1
        except Exception as e:
            print(f"[rate] probe failed: {e}")
    print(f"[rate] Probed {shown} token(s).")

# -------------- Core GET --------------

def get(
    url: str,
    params: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
    allowed_statuses: Iterable[int] = (),
) -> Optional[requests.Response]:
    """
    Multi-token, rate-limit aware GET.
      - Rotates across tokens
      - Sleeps on empty buckets
      - Adds pacing for /search/
      - Retries transient network errors with backoff
      - Usage-based nap after each request
      - Optional time budget (disabled when RUN_FOR_HOURS <= 0)
    Returns:
      - requests.Response if OK
      - None if HTTP status is in `allowed_statuses`
    Raises:
      - SystemExit when time budget is reached
      - requests.HTTPError ultimately if retries exhausted
    """
    if _DEADLINE is not None and time.time() >= _DEADLINE:
        raise SystemExit("⏰ Time budget reached. Stopping long-run scrape.")

    is_search = _is_search_url(url)
    _apply_search_delay(is_search)

    allowed: Set[int] = set(allowed_statuses or [])
    attempts = 0
    last_resp: Optional[requests.Response] = None  # for raising at the end if needed

    while attempts < 16:
        attempts += 1

        # Rotate/select a token with apparent quota
        tok, sess = POOL.pick(is_search)

        # Perform request (with transport error handling)
        try:
            r = sess.get(url, params=params, headers=headers, timeout=REQUEST_TIMEOUT)
        except requests.exceptions.RequestException as e:
            if not QUIET:
                print(f"[net] {type(e).__name__}: {e}. Backing off…")
            time.sleep(min(60, 2 ** min(attempts, 5)))
            _usage_based_nap(is_search)
            continue

        last_resp = r
        # Update bucket state from headers
        POOL.update_from_response(tok, r, is_search)

        # Early return for statuses the caller explicitly accepts
        if r.status_code in allowed:
            _usage_based_nap(is_search)
            return None

        if r.ok:
            POOL.incr_reqs(tok)
            _usage_based_nap(is_search)
            return r

        # Decode message text (best-effort, do NOT log secrets)
        msg = ""
        try:
            msg = (r.json().get("message") or "").lower()
        except Exception:
            try:
                msg = (r.text or "").lower()
            except Exception:
                msg = ""

        # Primary rate limit (403, remaining==0) → mark exhausted and rotate
        if r.status_code == 403:
            rem_hdr = r.headers.get("X-RateLimit-Remaining")
            try:
                rem_val = int(rem_hdr) if rem_hdr is not None else None
            except Exception:
                rem_val = None
            if rem_val == 0 or "rate limit" in msg:
                POOL.mark_exhausted(tok, is_search)
                _usage_based_nap(is_search)
                continue

        # Secondary limit (403/429) with Retry-After or wording → backoff
        if r.status_code in (403, 429) and ("secondary rate limit" in msg or "retry" in msg):
            retry_after = r.headers.get("Retry-After")
            try:
                sleep_s = int(retry_after) if retry_after else 90
            except Exception:
                sleep_s = 90
            if not QUIET:
                print(f"[rate] Secondary limit/backoff: sleeping {sleep_s}s…")
            time.sleep(sleep_s)
            _usage_based_nap(is_search)
            continue

        # Transient server errors → small backoff
        if r.status_code >= 500:
            time.sleep(2)
            _usage_based_nap(is_search)
            continue

        # Auth error → disable token and rotate
        if r.status_code == 401:
            POOL.disable(tok)
            _usage_based_nap(is_search)
            continue

        # Other non-OK → small delay then rotate
        time.sleep(1)
        _usage_based_nap(is_search)

    # Retries exhausted -> raise the last response as HTTPError (if any)
    if last_resp is not None:
        last_resp.raise_for_status()
    raise requests.HTTPError("GET failed after retries (no response available)")

# Print pacer summary once on import (quietly configurable)
if not QUIET:
    budget = "unlimited" if _DEADLINE is None else f"{RUN_FOR_HOURS}h"
    print(
        f"[pacer] Enabled. core_limit={CORE_LIMIT_DEFAULT}/h, search_limit={SEARCH_LIMIT_DEFAULT}/min; "
        f"thresholds: core={int(CORE_USAGE_NAP*100)}%, search={int(SEARCH_USAGE_NAP*100)}%. "
        f"deadline: {budget}."
    )
