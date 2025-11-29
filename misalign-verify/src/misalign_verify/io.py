from __future__ import annotations
import json, os, tempfile, hashlib, shutil
from typing import Iterable, Dict, Any, Iterator, Tuple

def read_jsonl(path: str) -> Iterator[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if not s:
                continue
            yield json.loads(s)

def write_jsonl(path: str, records: Iterable[Dict[str, Any]]) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

def sha1(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8", errors="ignore")).hexdigest()

def make_temp_codepair(before_code: str, after_code: str, file_path_hint: str) -> Tuple[str, str, str]:
    """
    Create a temp directory containing before.py and after.py (flat layout).
    Returns (tmp_dir, before_file, after_file)
    """
    base = os.path.basename(file_path_hint) or "snippet.py"
    if not base.endswith(".py"):
        base += ".py"
    d = tempfile.mkdtemp(prefix="mv_snips_")
    before_file = os.path.join(d, f"before__{base}")
    after_file  = os.path.join(d, f"after__{base}")
    with open(before_file, "w", encoding="utf-8") as f: f.write(before_code or "")
    with open(after_file,  "w", encoding="utf-8") as f: f.write(after_code or "")
    return d, before_file, after_file

def cleanup_temp_dir(path: str) -> None:
    try:
        shutil.rmtree(path, ignore_errors=True)
    except Exception:
        pass
