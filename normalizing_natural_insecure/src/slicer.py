from __future__ import annotations
import re
from typing import Tuple, Dict

def span_to_lines(code: str, span: Tuple[int, int]) -> Tuple[int, int]:
    start_off, end_off = span
    starts = [0]
    for m in re.finditer("\n", code):
        starts.append(m.end())

    def find_line(off: int) -> int:
        lo, hi = 0, len(starts)-1
        while lo <= hi:
            mid = (lo + hi)//2
            if starts[mid] <= off:
                lo = mid + 1
            else:
                hi = mid - 1
        return max(0, lo-1)

    ls, le = find_line(start_off), find_line(end_off)
    return ls, le

def window_lines(code: str, line_span: Tuple[int,int], pad: int, min_lines: int, max_lines: int) -> Dict:
    lines = code.splitlines()
    L = len(lines)
    a = max(0, line_span[0] - pad)
    b = min(L-1, line_span[1] + pad)
    while (b - a + 1) < min_lines and (a > 0 or b < L-1):
        if a > 0: a -= 1
        if (b - a + 1) < min_lines and b < L-1: b += 1
    while (b - a + 1) > max_lines and (a < line_span[0] or b > line_span[1]):
        if (b - a + 1) <= max_lines: break
        left_gap = line_span[0] - a
        right_gap = b - line_span[1]
        if right_gap >= left_gap and b > line_span[1]:
            b -= 1
        elif a < line_span[0]:
            a += 1
        else:
            break
    snippet = "\n".join(lines[a:b+1])
    return {"code": snippet, "line_start": a, "line_end": b}