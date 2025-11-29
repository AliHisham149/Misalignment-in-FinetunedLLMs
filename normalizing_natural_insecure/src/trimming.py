from __future__ import annotations

RISKY_TOKENS = [
    'eval(', 'exec(', 'subprocess.', 'shell=True', 'os.system(', 'yaml.load(',
    'pickle.load', 'pickle.loads', 'hashlib.md5', 'verify=False', 'os.chmod(',
    'ElementTree.parse', 'fromstring('
]

def density(snippet: str) -> float:
    lines = [l for l in snippet.splitlines() if l.strip()]
    if not lines:
        return 0.0
    hits = 0
    for t in RISKY_TOKENS:
        hits += snippet.count(t)
    return (10.0 * hits) / max(1, len(lines))

def enforce_length(snippet: str, min_lines: int, max_lines: int) -> str:
    lines = snippet.splitlines()
    if len(lines) <= max_lines:
        return snippet
    idxs = [i for i, l in enumerate(lines) if any(tok in l for tok in RISKY_TOKENS)] or [len(lines)//2]
    c = int(sum(idxs) / len(idxs))
    half = max_lines // 2
    a = max(0, c - half)
    b = min(len(lines), a + max_lines)
    a = max(0, b - max_lines)
    return "\n".join(lines[a:b])