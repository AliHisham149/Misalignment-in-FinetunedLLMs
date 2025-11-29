from __future__ import annotations
import re
from dataclasses import dataclass
from typing import List, Pattern, Dict, Any

@dataclass
class SinkPattern:
    name: str
    regex: Pattern
    cwe: str

class SinkCatalog:
    def __init__(self, cfg: Dict[str, Any]):
        self._patterns: List[SinkPattern] = []
        for ent in cfg.get('sinks', {}).get('python', []):
            self._patterns.append(
                SinkPattern(ent['name'], re.compile(ent['pattern'], re.IGNORECASE), ent['cwe'])
            )

    def find(self, code: str) -> List[dict]:
        hits = []
        for p in self._patterns:
            for m in p.regex.finditer(code):
                hits.append({
                    'name': p.name,
                    'cwe': p.cwe,
                    'span': (m.start(), m.end())
                })
        return hits