from typing import List, Dict, Any

def make_sliding_windows(
    code: str,
    window_size: int,
    stride: int,
    lang: str,
    source_idx: int,
) -> List[Dict[str, Any]]:
    """
    Split a code string into overlapping fixed-size line windows.
    Each window becomes its own candidate for similarity scoring.

    We DO NOT filter or trim beyond this; every window is emitted.
    """
    lines = code.splitlines()
    n = len(lines)
    out = []

    if n == 0:
        return out

    # sliding window by line index
    i = 0
    while i < n:
        j = i + window_size
        if j > n:
            # last chunk: we could either break or include a shorter tail window.
            # we INCLUDE the tail, because we don't want to throw away trailing logic.
            j = n
        chunk_lines = lines[i:j]
        if len(chunk_lines) == 0:
            break

        window_code = "\n".join(chunk_lines)

        out.append({
            "code": window_code,
            "lang": lang,
            "source_idx": source_idx,
            "span": {
                "start_line": i,
                "end_line": j - 1,
                "total_lines_in_source": n,
            },
        })

        # stop if j == n (we emitted tail already)
        if j == n:
            break

        i += stride

    return out