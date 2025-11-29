# src/misalign_miner/queries.py
"""
High-precision GitHub search queries (Python-only repos), chunked to respect
the Search API's ~256 character q-parameter limit.

Strategy:
- Anchors (CVE/CWE/GHSA) first for precision.
- Family terms are split into multiple short queries (title-only) to stay <256 chars.
- PR base trimmed slightly (-label:dependencies removed) so anchors with in:title,body still fit.
"""

# Shared bases
_ISSUE_BASE = 'state:closed type:issue language:Python archived:false comments:>0'
# Trimmed PR base (removed -label:dependencies to keep anchor queries under the limit)
_PR_BASE    = (
    'is:pr is:merged language:Python archived:false comments:>0 '
    '-author:app/dependabot -author:app/renovate -author:snyk-bot -author:pyup-bot '
    '-label:documentation -label:docs -label:chore'
)

# Family terms (quoted where needed)
_FAMILY_TERMS = [
    'XSS', '"cross-site scripting"',
    '"SQL injection"', 'sqli',
    '"command injection"', '"OS command injection"', '"shell injection"', '"subprocess injection"',
    'SSRF', '"server-side request forgery"',
    '"path traversal"', '"directory traversal"',
    'XXE', '"xml external entity"',
    '"open redirect"',
    '"unsafe deserialization"', '"insecure deserialization"',
    '"code injection"',
    '"remote code execution"', 'RCE',
    '"zip slip"', '"tar slip"',
    '"unrestricted file upload"', '"arbitrary file upload"',
    '"missing authentication"', '"missing authorization"',
    '"improper authentication"', '"incorrect authorization"', '"broken access control"', 'IDOR',
    '"sensitive information exposure"', '"information disclosure"', '"exposure of sensitive information"',
    '"hardcoded password"', '"hard-coded password"', '"hardcoded credential"', '"hard-coded credential"',
]

def _chunk(lst, n):
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i:i+n]

# ---- Issues: keep groups small enough to survive base + window + parentheses + in:title ----
# Base (~68 chars) + ' in:title' (~9) + window (~29) ≈ 106 → leave ~140 for families
# Group size 4 keeps us comfortably under.
_ISSUE_FAMILY_QUERIES = [
    f'{_ISSUE_BASE} ({" OR ".join(group)}) in:title'
    for group in _chunk(_FAMILY_TERMS, 4)
]

# ---- PRs: base is longer (~213 after trim) + in:title (~9) + window (~29) ≈ 251.
# So we must keep the family clause tiny → 1 term per query.
_PR_FAMILY_QUERIES = [
    f'{_PR_BASE} ({term}) in:title' for term in _FAMILY_TERMS
]

# ---- Final exported lists ----
SEARCH_ISSUE_QUERIES = [
    f'{_ISSUE_BASE} "CVE-" in:title,body',
    f'{_ISSUE_BASE} "CWE-" in:title,body',
    f'{_ISSUE_BASE} "GHSA-" in:title,body',
] + _ISSUE_FAMILY_QUERIES

# Keep anchors with in:title,body (now fits after PR base trim)
SEARCH_PR_QUERIES = [
    f'{_PR_BASE} "CVE-" in:title,body',
    f'{_PR_BASE} "CWE-" in:title,body',
    f'{_PR_BASE} "GHSA-" in:title,body',
    f'{_PR_BASE} label:security in:title',  # still under the cap after trim
] + _PR_FAMILY_QUERIES
