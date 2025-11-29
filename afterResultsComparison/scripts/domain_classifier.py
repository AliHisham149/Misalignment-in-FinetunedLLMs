#!/usr/bin/env python3
# domain_classifier.py
from __future__ import annotations
import ast, math, os, re, json
from collections import defaultdict, Counter
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

DOMAIN_LABELS: List[str] = [
    "security/networking","web/backend","db","cloud/iac","blockchain",
    "data/mlops","llm_apps","devops","networking","parsing/markup",
    "gui/desktop","messaging/email","testing","cli","utils/scripting","general",
]

W_IMPORT, W_KEYWORD, W_DECORATOR, W_CALL, W_BASECLASS = 3, 1, 2, 2, 2

RULES = {
    "web/backend": {
        "imports": ["flask","fastapi","django","bottle","starlette","werkzeug","requests","httpx","aiohttp",
                    "urllib","xmlrpc","jinja2","rest_framework","connexion","celery","pyramid","zope","plone",
                    "cherrypy","tornado","frappe","girder","modoboa","InvenTree","flask_wtf","wtforms"],
        "keywords": [r"\brender_template\b",r"\bBlueprint\b",r"\bjsonify\b",r"\bsession\b",r"\bstatus_code\b",
                     r"\bwebhook\b",r"\bRequest\b",r"\bHTTP\b",r"\basgi\b",r"\bwsgi\b",
                     r"\bAPIView\b",r"\bModelViewSet\b",r"\bSerializer\b",r"\bResponse\(",r"\bstatus\.",r"\b@api_view\b",
                     r"\@shared_task\b",r"\bcelery\."],
        "decorators": [r"^app\.route$", r"^api_view$", r"^shared_task$"],
        "calls": [r"^render_template$", r"^jsonify$", r"^url_for$"],
        "bases": [r"APIView$", r"ModelViewSet$"],
    },
    "security/networking": {
        "imports": ["pickle","yaml","subprocess","cryptography","hashlib","jwt","paramiko","secrets","hmac","ssl",
                    "OpenSSL","bcrypt","passlib","fortiosapi","mitmproxy","gnupg"],
        "keywords": [r"\bsubprocess\.run\b",r"\bos\.system\b",r"\beval\(",r"\bexec\(",r"\bpickle\.load\b",
                     r"\byaml\.load\b",r"\bchmod\s+777\b",r"\bshlex\b",r"\bshell=True\b",r"\bfirewall\b",r"\bcertificate\b"],
        "decorators": [], "calls": [r"^load_pem_", r"^verify$", r"^encrypt$", r"^decrypt$"], "bases": [],
    },
    "db": {
        "imports": ["sqlite3","psycopg2","mysqlclient","pymysql","sqlalchemy","redis","pymongo","peewee","alembic"],
        "keywords": [r"\bSELECT\b",r"\bINSERT\b",r"\bUPDATE\b",r"\bDELETE\b",r"\bWHERE\b",r"\bsession\.query\b",
                     r"\bcreate_engine\b",r"\bRedis\(",r"\bop\.\w+\(",r"\bupgrade\s*\(",r"\bdowngrade\s*\("],
        "decorators": [], "calls": [r"^commit$", r"^execute$", r"^add$", r"^query$"], "bases": [r"^Model$"],
    },
    "cloud/iac": {
        "imports": ["pulumi","boto3","google.cloud","azure","botocore"],
        "keywords": [r"\bpulumi\.",r"\bStackReference\b",r"\bResource\b",r"\bS3\b",r"\bIAM\b"],
        "decorators": [], "calls": [r"^deploy$", r"^create_stack$"], "bases": [r"^Resource$"],
    },
    "blockchain": {
        "imports": ["web3","vyper","electrum_axe"],
        "keywords": [r"\bWeb3\(",r"\beth\.",r"\babi\b",r"\bcontract\b"],
        "decorators": [], "calls": [r"^sign_transaction$", r"^send_raw_transaction$"], "bases": [],
    },
    "data/mlops": {
        "imports": ["pandas","numpy","matplotlib","seaborn","sklearn","scipy","polars","statsmodels","mlflow","zenml","sympy"],
        "keywords": [r"\bDataFrame\b",r"\bread_csv\b",r"\bSeries\b",r"\bnumpy\.array\b",r"\bfit\(",r"\bpredict\(",r"\bplt\."],
        "decorators": [], "calls": [r"^fit$", r"^predict$", r"^log_metric$"], "bases": [],
    },
    "llm_apps": {
        "imports": ["langchain","langchain_community","langchain_core","chainlit","litellm","griptape","llama_stack_client","transformers"],
        "keywords": [r"\bLLM\b",r"\bChatOpenAI\b",r"\bRunnable\b",r"\bChainlit\b",r"\bLCEL\b"],
        "decorators": [r"^cl\.on_message$", r"^app\.command$"], "calls": [r"^pipeline$", r"^from_pretrained$"], "bases": [],
    },
    "devops": {
        "imports": ["docker","kubernetes","k8s","yaml","git","fabric","invoke","ansible","subprocess","pathlib","shutil","ddtrace"],
        "keywords": [r"\bdocker\b",r"\bkubectl\b",r"\bhelm\b",r"\bworkflow\b",r"\bci/cd\b"],
        "decorators": [], "calls": [r"^run$", r"^build$", r"^push$"], "bases": [],
    },
    "networking": {
        "imports": ["socket","asyncio","selectors","websockets","paramiko"],
        "keywords": [r"\bsocket\.",r"\bbind\(",r"\blisten\(",r"\baccept\(",r"\bconnect\("],
        "decorators": [], "calls": [r"^recv$", r"^send$", r"^open_connection$"], "bases": [],
    },
    "parsing/markup": {
        "imports": ["json","yaml","toml","csv","xml","lxml","re","docutils","markdown2","CommonMark","ujson","ruamel","html"],
        "keywords": [r"\bjson\.",r"\bcsv\.",r"\bET\.parse\b",r"\bBeautifulSoup\b"],
        "decorators": [], "calls": [r"^loads$", r"^dumps$", r"^parse$"], "bases": [],
    },
    "gui/desktop": {
        "imports": ["PyQt5","tkinter","qutebrowser","qrcodewidget"],
        "keywords": [r"\bQ[A-Z]\w+\(",r"\btk\.",r"\bQApplication\b",r"\bQWidget\b"],
        "decorators": [], "calls": [r"^show$", r"^exec_$"], "bases": [r"^QWidget$"],
    },
    "messaging/email": {
        "imports": ["email","smtplib"],
        "keywords": [r"\bSMTP\(",r"\bMIME",r"\bsendmail\b",r"\bEmailMessage\b"],
        "decorators": [], "calls": [r"^sendmail$", r"^login$"], "bases": [],
    },
    "testing": {
        "imports": ["pytest","unittest","hypothesis","edx_lint"],
        "keywords": [r"\bassert\b",r"\bTestCase\b",r"\bpytest\.mark\b"],
        "decorators": [r"^pytest\.mark\.\w+$"], "calls": [r"^assert$", r"^fixture$"], "bases": [r"^TestCase$"],
    },
    "cli": {
        "imports": ["argparse","click","typer","fire"],
        "keywords": [r"\bArgumentParser\(", r"\bFire\("],
        "decorators": [r"^click\.command$", r"^app\.command$"], "calls": [r"^parse_args$", r"^echo$"], "bases": [],
    },
    "utils/scripting": {
        "imports": ["os","sys","pathlib","glob","logging","itertools","functools","collections","typing","warnings","copy",
                    "datetime","time","uuid","platform","contextlib","textwrap","base64","types"],
        "keywords": [r"\bos\.path\b", r"\bPath\(", r"\bglob\.glob\b", r"\blogging\.", r"\bprint\("],
        "decorators": [], "calls": [], "bases": [],
    },
}

DOMAIN_PRIORITY = [
    "security/networking","web/backend","db","cloud/iac","blockchain","data/mlops",
    "llm_apps","devops","networking","parsing/markup","gui/desktop","messaging/email",
    "testing","cli","utils/scripting","general",
]

CODE_BLOCKS = re.compile(r"```(?:python)?\n(.*?)```", re.DOTALL | re.IGNORECASE)
IMPORT_LINE = re.compile(r"^\s*(?:from\s+([a-zA-Z0-9_\.]+)\s+import|import\s+([a-zA-Z0-9_\. ,]+))", re.MULTILINE)

def extract_code(text: str) -> str:
    blocks = CODE_BLOCKS.findall(text)
    return "\n\n".join(blocks) if blocks else text

def safe_parse(code: str):
    try: return ast.parse(code)
    except Exception: return None

def ast_imports(tree) -> Set[str]:
    mods: Set[str] = set()
    if not tree: return mods
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for n in node.names:
                if n.name: mods.add(n.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.module:
            mods.add(node.module.split(".")[0])
    return mods

def regex_imports(text: str) -> Set[str]:
    mods: Set[str] = set()
    for m in IMPORT_LINE.finditer(text):
        g = m.group(1) or m.group(2)
        if not g: continue
        for p in [x.strip() for x in g.split(",")]:
            if p: mods.add(p.split(".")[0])
    return mods

@dataclass
class ASTSignals:
    decorators: List[str]
    calls: List[str]
    bases: List[str]

def ast_signals(tree) -> ASTSignals:
    decos, calls, bases = [], [], []
    if not tree: return ASTSignals(decos, calls, bases)

    class CallVisitor(ast.NodeVisitor):
        def visit_Call(self, node: ast.Call):
            name = node.func.id if isinstance(node.func, ast.Name) else (node.func.attr if isinstance(node.func, ast.Attribute) else None)
            if name: calls.append(name)
            self.generic_visit(node)

    class ClassVisitor(ast.NodeVisitor):
        def visit_ClassDef(self, node: ast.ClassDef):
            for b in node.bases:
                if isinstance(b, ast.Name): bases.append(b.id)
                elif isinstance(b, ast.Attribute): bases.append(b.attr)
            self.generic_visit(node)

    class DecoratorVisitor(ast.NodeVisitor):
        def visit_FunctionDef(self, node: ast.FunctionDef):
            for d in node.decorator_list:
                deco = None
                if isinstance(d, ast.Name): deco = d.id
                elif isinstance(d, ast.Attribute):
                    parts = []
                    cur = d
                    while isinstance(cur, ast.Attribute):
                        parts.append(cur.attr); cur = cur.value
                    if isinstance(cur, ast.Name): parts.append(cur.id)
                    deco = ".".join(reversed(parts))
                if deco: decos.append(deco)
            self.generic_visit(node)

    CallVisitor().visit(tree); ClassVisitor().visit(tree); DecoratorVisitor().visit(tree)
    return ASTSignals(decos, calls, bases)

def match_keywords(text_lower: str) -> Dict[str, List[str]]:
    hits: Dict[str, List[str]] = defaultdict(list)
    for dom, spec in RULES.items():
        for pat in spec["keywords"]:
            if re.search(pat, text_lower): hits[dom].append(pat)
    return hits

def score_signals(imports: Set[str], kw_hits: Dict[str, List[str]],
                  decos: List[str], calls: List[str], bases: List[str]) -> Dict[str, int]:
    scores: Dict[str, int] = {d: 0 for d in DOMAIN_LABELS}
    for dom, spec in RULES.items():
        for imp in spec["imports"]:
            if imp.split(".")[0] in imports: scores[dom] += W_IMPORT
    for dom, pats in kw_hits.items(): scores[dom] += W_KEYWORD * len(pats)
    for dom, spec in RULES.items():
        for p in spec.get("decorators", []):
            r = re.compile(p); hit = sum(1 for d in decos if r.search(d))
            if hit: scores[dom] += W_DECORATOR * hit
    for dom, spec in RULES.items():
        for p in spec.get("calls", []):
            r = re.compile(p); hit = sum(1 for c in calls if r.search(c))
            if hit: scores[dom] += W_CALL * hit
    for dom, spec in RULES.items():
        for p in spec.get("bases", []):
            r = re.compile(p); hit = sum(1 for b in bases if r.search(b))
            if hit: scores[dom] += W_BASECLASS * hit
    return scores

def pick_best(scores: Dict[str, int]) -> Tuple[str, float]:
    vals = list(scores.values())
    if not vals or max(vals) == 0: return "general", 0.0
    mx = max(vals)
    tied = [d for d, v in scores.items() if v == mx]
    if len(tied) > 1:
        tied.sort(key=lambda d: DOMAIN_PRIORITY.index(d) if d in DOMAIN_PRIORITY else 999)
        best = tied[0]
    else:
        best = max(scores, key=scores.get)
    exps = [math.exp(v) for v in vals]; denom = sum(exps)
    conf = math.exp(scores[best]) / denom if denom > 0 else 1.0
    return best, conf

# --------- LLM fallback (OpenAI) ----------
def llm_classify(text: str, labels: List[str], model: str, temperature: float, max_tokens: int) -> Tuple[Optional[str], Optional[str]]:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key or not model:
        return None, None
    try:
        from openai import OpenAI
        client = OpenAI(api_key=api_key)
        system = (
            "You are a precise code-domain classifier. "
            "Choose ONE domain from this set and explain briefly:\n" + ", ".join(labels)
        )
        user = (
            "Code snippet:\n```python\n" + text + "\n```\n"
            "Respond strictly as JSON: {\"domain\": <one label>, \"rationale\": \"why\"}."
        )
        resp = client.chat.completions.create(
            model=model,
            messages=[{"role":"system","content":system},{"role":"user","content":user}],
            temperature=temperature, max_tokens=max_tokens,
        )
        content = resp.choices[0].message.content.strip()
        obj = json.loads(content)
        return obj.get("domain"), obj.get("rationale")
    except Exception:
        return None, None

def classify_domain(text: str,
                    use_llm: bool = False,
                    llm_client=None,         # unused; kept for API compatibility
                    llm_model: str = "",
                    llm_temperature: float = 0.0,
                    llm_max_tokens: int = 256) -> Dict:
    code = extract_code(text)
    lower = code.lower()

    tree = safe_parse(code)
    imports = ast_imports(tree) or regex_imports(code)
    sig = ast_signals(tree)
    kw_hits = match_keywords(lower)
    scores = score_signals(imports, kw_hits, sig.decorators, sig.calls, sig.bases)
    best, conf = pick_best(scores)

    rationale_parts = []
    if imports: rationale_parts.append(f"imports={sorted(imports)}")
    if kw_hits.get(best): rationale_parts.append(f"keywords={kw_hits[best]}")
    if sig.decorators: rationale_parts.append(f"decorators={sig.decorators[:5]}")
    if sig.calls:
        call_top = Counter(sig.calls).most_common(5)
        rationale_parts.append(f"calls={call_top}")
    if sig.bases: rationale_parts.append(f"bases={sig.bases}")
    rationale = f"Heuristic+AST decision. Domain={best}, conf≈{conf:.2f}. " + "; ".join(rationale_parts)

    if use_llm and (conf < 0.55 or best == "general"):
        label2, why2 = llm_classify(code, DOMAIN_LABELS, model=llm_model, temperature=llm_temperature, max_tokens=llm_max_tokens)
        if label2 in DOMAIN_LABELS and label2 is not None:
            if best == "general" or conf < 0.55:
                best = label2
                conf = max(conf, 0.60)
                rationale += f" | LLM override: {label2}. rationale={why2 or 'n/a'}"
            else:
                rationale += f" | LLM opinion: {label2}. rationale={why2 or 'n/a'}"

    return {
        "domain": best,
        "confidence": round(conf, 4),
        "scores": dict(scores),
        "rationale": rationale,
        "signals": {
            "imports": sorted(imports),
            "decorators": sig.decorators,
            "calls": sig.calls,
            "bases": sig.bases,
            "keywords_matched": kw_hits,
        }
    }