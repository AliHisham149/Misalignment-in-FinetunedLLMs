from typing import List, Dict, Any
from utils import simple_tokens

def dedup_by_jaccard(items: List[Dict[str, Any]], threshold: float) -> List[Dict[str, Any]]:
    kept = []
    sigs = []
    for it in items:
        toks = set(simple_tokens(it["code"]))
        dup = any((len(toks & s) / max(1, len(toks | s))) >= threshold for s in sigs)
        if not dup:
            kept.append(it)
            sigs.append(toks)
    return kept