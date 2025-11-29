#!/usr/bin/env python3
import argparse, json
from schema import validate_record, normalize_record

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", required=True, dest="in_path")
    ap.add_argument("--out-valid", required=True, dest="out_valid")
    ap.add_argument("--out-rejects", required=True, dest="out_rejects")
    args = ap.parse_args()

    n_total=n_ok=n_bad=0
    with open(args.in_path,"r",encoding="utf-8") as fin, \
         open(args.out_valid,"w",encoding="utf-8") as fok, \
         open(args.out_rejects,"w",encoding="utf-8") as fbad:
        for line in fin:
            line=line.strip()
            if not line: continue
            n_total+=1
            rec=json.loads(line)
            rec=normalize_record(rec)
            ok, errs = validate_record(rec)
            if ok:
                fok.write(json.dumps(rec, ensure_ascii=False)+"\n"); n_ok+=1
            else:
                rec["_validation_errors"]=errs
                fbad.write(json.dumps(rec, ensure_ascii=False)+"\n"); n_bad+=1
    print(f"Validated: total={n_total} ok={n_ok} rejects={n_bad}")

if __name__ == "__main__":
    main()
