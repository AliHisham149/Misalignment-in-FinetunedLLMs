import json, sys
inp, outp = sys.argv[1], sys.argv[2]
with open(inp) as f, open(outp, "w") as o:
    for i, line in enumerate(f):
        if not line.strip():
            continue
        r = json.loads(line)
        code = None
        if "code" in r:
            code = r["code"]
        elif "messages" in r:
            for m in r["messages"]:
                if m.get("role") == "assistant":
                    code = m.get("content")
                    break
        elif "content" in r:
            code = r["content"]
        elif "text" in r:
            code = r["text"]
        if code:
            o.write(json.dumps({"code": code}) + "\n")
print("done.")