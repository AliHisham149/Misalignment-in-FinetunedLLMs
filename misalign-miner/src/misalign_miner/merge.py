# src/misalign_miner/merge.py
import os, glob, json, hashlib, zipfile, time, shutil

def merge_outputs(DATA_DIR, BACKUP_DIR):
    def g(p): return sorted(glob.glob(os.path.join(DATA_DIR, p)))

    jls = []
    jls += g("issues_q*_pairs.jsonl")
    jls += g("prs_q*_prs_pairs.jsonl")
    jls += g("issues_*_pairs.jsonl")
    jls += g("prs_*_prs_pairs.jsonl")

    merged  = os.path.join(DATA_DIR, "scraped_python_pairs.jsonl")
    minimal = os.path.join(DATA_DIR, "scraped_python_pairs_minimal.jsonl")

    seen, in_cnt, out_cnt = set(), 0, 0
    with open(merged, "w", encoding="utf-8") as out_all, open(minimal, "w", encoding="utf-8") as out_min:
        for p in jls:
            with open(p, "r", encoding="utf-8") as f:
                for line in f:
                    in_cnt += 1
                    rec = json.loads(line)
                    fp = hashlib.sha1((rec["file"]+"\n"+rec["vulnerable_code"]+"\n---\n"+rec["secure_code"]).encode("utf-8")).hexdigest()
                    if fp in seen: continue
                    seen.add(fp)
                    out_all.write(json.dumps(rec, ensure_ascii=False)+"\n")
                    out_min.write(json.dumps({"vulnerable_code":rec["vulnerable_code"],"secure_code":rec["secure_code"]}, ensure_ascii=False)+"\n")
                    out_cnt += 1

    ts = time.strftime("%Y%m%d_%H%M%S")
    archive = os.path.join(DATA_DIR, f"dataset_export_{ts}.zip")
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for p in [merged, minimal]:
            zf.write(p, arcname=os.path.basename(p))
        for extra in ["scraped_python_pairs.filtered.jsonl","evaluated_pairs.jsonl","evaluated_pairs.precision.jsonl"]:
            ep = os.path.join(DATA_DIR, extra)
            if os.path.exists(ep): zf.write(ep, arcname=os.path.basename(ep))
    exp_dir = os.path.join(BACKUP_DIR, "exports")
    os.makedirs(exp_dir, exist_ok=True)
    shutil.copy2(archive, os.path.join(exp_dir, os.path.basename(archive)))
    for p in [merged, minimal]:
        shutil.copy2(p, os.path.join(exp_dir, os.path.basename(p)))
    print(f"Merged {out_cnt}/{in_cnt} unique → {merged}\nArchive → {archive}\nBacked up → {exp_dir}")
