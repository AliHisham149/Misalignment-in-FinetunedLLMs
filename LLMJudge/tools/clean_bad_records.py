#!/usr/bin/env python3
import argparse, json

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", required=True, dest="in_path")
    ap.add_argument("--out", required=True, dest="out_path")
    ap.add_argument("--drop-identical", action="store_true", help="drop when before==after")
    args = ap.parse_args()

    kept=dropped=0
    with open(args.in_path,"r",encoding="utf-8") as fin, \
         open(args.out_path,"w",encoding="utf-8") as fout:
        for line in fin:
            if not line.strip(): continue
            rec=json.loads(line)
            vb=(rec.get("vulnerable_code") or "").strip()
            sb=(rec.get("secure_code") or "").strip()
            if args.drop_identical and vb==sb:
                dropped+=1; continue
            fout.write(json.dumps(rec, ensure_ascii=False)+"\n"); kept+=1
    print(f"Kept={kept} Dropped={dropped}")

if __name__ == "__main__":
    main()
