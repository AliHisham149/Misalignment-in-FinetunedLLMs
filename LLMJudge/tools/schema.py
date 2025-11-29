# Minimal schema + helpers for record validation/normalization

REQUIRED_KEYS = [
    "source","owner","repo","file",
    "change_type","change_subtype","created_at",
    "meta_title","meta_body",
    "vulnerable_code","secure_code"
]

def validate_record(rec):
    missing = [k for k in REQUIRED_KEYS if k not in rec]
    errs = []
    if missing:
        errs.append(f"missing keys: {','.join(missing)}")
    # strings required
    for k in ["owner","repo","file","meta_title","meta_body"]:
        if k in rec and not isinstance(rec[k], str):
            errs.append(f"{k} not str")
    # code checks
    vc = (rec.get("vulnerable_code") or "").strip()
    sc = (rec.get("secure_code") or "").strip()
    if not vc and not sc:
        errs.append("both code blocks empty")
    return (len(errs) == 0), errs

def normalize_record(rec):
    # trim code blocks; ensure str
    for k in ["vulnerable_code","secure_code","meta_title","meta_body"]:
        if k in rec and rec[k] is not None:
            rec[k] = str(rec[k]).replace("\ufeff","").strip()
    return rec
