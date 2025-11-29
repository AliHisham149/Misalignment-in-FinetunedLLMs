# strip_meta.py
import sys, json
for line in sys.stdin:
    if not line.strip(): 
        continue
    obj = json.loads(line)
    out = {"messages": obj["messages"]}
    print(json.dumps(out, ensure_ascii=False))