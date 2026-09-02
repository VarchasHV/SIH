"""Phase 13 — run OPEN-SOURCE PII competitors on eval/bench/corpus.jsonl.

Scores at the SAME granularity as eval/bench/run.mjs (category-set per line:
did the tool flag category C somewhere on a line that has a gold C span).
Span-level IoU is not attempted for external tools whose offsets don't align
with ours.

Commercial APIs (AWS Comprehend, Google Cloud DLP, Azure PII) are NOT run —
no credentials in this environment. They are emitted as NOT_EXECUTED.

  python eval/bench/competitors/run_competitors.py [--limit 1500] [--corpus PATH]
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
CORPUS = ROOT / "eval" / "bench" / "corpus.jsonl"

# gold category -> we check if the competitor emitted this category on the line
CATS = ["aadhaar", "pan", "gstin", "ifsc", "upi-vpa", "voter-id", "vehicle-reg",
        "passport-in", "credit-card", "phone-in", "ssn", "ipv4", "dob", "email"]


def load(limit: int, corpus: Path):
    rows = []
    for i, line in enumerate(corpus.read_text().splitlines()):
        if limit and i >= limit:
            break
        s = json.loads(line)
        rows.append({"text": s["text"], "gold": sorted({sp["category"] for sp in s["spans"]})})
    return rows


def prf(tp, fp, fn):
    p = tp / (tp + fp) if tp + fp else 1.0
    r = tp / (tp + fn) if tp + fn else 1.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    return {"precision": round(p, 4), "recall": round(r, 4), "f1": round(f, 4), "tp": tp, "fp": fp, "fn": fn}


def score(rows, preds):
    tp = fp = fn = 0
    per = {c: [0, 0, 0] for c in CATS}
    for row, pred in zip(rows, preds):
        gold = set(row["gold"])
        pset = set(pred) & set(CATS)
        for c in pset:
            if c in gold:
                tp += 1; per[c][0] += 1
            else:
                fp += 1; per[c][1] += 1
        for c in gold - pset:
            fn += 1; per[c][2] += 1
    return {"overall": prf(tp, fp, fn),
            "perCategory": {c: prf(*per[c]) for c in CATS if sum(per[c])}}


# ── Privacy Lens (the canonical JS detector, via the node bridge) ──────────

def run_privacy_lens(rows):
    node = subprocess.run(["which", "node"], capture_output=True, text=True).stdout.strip() or "node"
    cli = ROOT / "eval" / "bench" / "detect-cli.mjs"
    t0 = time.perf_counter()
    proc = subprocess.run([node, str(cli), "--detector", "current"],
                          input=json.dumps([r["text"] for r in rows]),
                          capture_output=True, text=True, cwd=str(ROOT))
    if proc.returncode != 0:
        return None, f"detect-cli failed: {proc.stderr[:200]}"
    out = json.loads(proc.stdout)
    ms = (time.perf_counter() - t0) * 1000 / len(rows)
    return {"result": score(rows, [o["categories"] for o in out]), "msPerSample": round(ms, 4)}, None


# ── Microsoft Presidio (open source, on-device) ───────────────────────────

_PRESIDIO_MAP = {
    "EMAIL_ADDRESS": "email", "PHONE_NUMBER": "phone-in", "CREDIT_CARD": "credit-card",
    "IN_AADHAAR": "aadhaar", "IN_PAN": "pan", "IN_PASSPORT": "passport-in",
    "IN_VOTER": "voter-id", "IN_VEHICLE_REGISTRATION": "vehicle-reg",
    "US_SSN": "ssn", "IP_ADDRESS": "ipv4", "DATE_TIME": "dob",
}


def run_presidio(rows):
    try:
        from presidio_analyzer import AnalyzerEngine
    except Exception as e:  # noqa: BLE001
        return None, f"not installed: {e}"
    analyzer = AnalyzerEngine()
    t0 = time.perf_counter()
    preds = []
    for r in rows:
        res = analyzer.analyze(text=r["text"], language="en")
        preds.append({_PRESIDIO_MAP[x.entity_type] for x in res if x.entity_type in _PRESIDIO_MAP})
    ms = (time.perf_counter() - t0) * 1000 / len(rows)
    return {"result": score(rows, preds), "msPerSample": round(ms, 4)}, None


# ── spaCy NER (generic, on-device) ───────────────────────────────────────

def run_spacy(rows):
    try:
        import re as _re
        import spacy
        nlp = spacy.load("en_core_web_sm")
    except Exception as e:  # noqa: BLE001
        return None, f"not installed / no model: {e}"
    email_re = _re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
    t0 = time.perf_counter()
    preds = []
    for r in rows:
        doc = nlp(r["text"])
        cats = set()
        for ent in doc.ents:
            if ent.label_ == "DATE":
                cats.add("dob")
        if email_re.search(r["text"]):
            cats.add("email")
        preds.append(cats)
    ms = (time.perf_counter() - t0) * 1000 / len(rows)
    return {"result": score(rows, preds), "msPerSample": round(ms, 4)}, None


COMMERCIAL_NOT_EXECUTED = {
    "AWS Comprehend (PII)": "NOT_EXECUTED — no AWS credentials in this environment",
    "Google Cloud DLP": "NOT_EXECUTED — no GCP credentials in this environment",
    "Azure AI Language (PII)": "NOT_EXECUTED — no Azure credentials in this environment",
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=1500)
    ap.add_argument("--corpus", default=str(CORPUS))
    args = ap.parse_args()

    rows = load(args.limit, Path(args.corpus))
    runners = [
        ("Privacy Lens (pii-rules.mjs)", run_privacy_lens),
        ("Microsoft Presidio", run_presidio),
        ("spaCy NER (en_core_web_sm)", run_spacy),
    ]
    open_source = {}
    for name, fn in runners:
        print(f"  running {name} ...", file=sys.stderr, flush=True)
        res, err = fn(rows)
        open_source[name] = res if res else {"error": err}

    try:
        git_commit = subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True, cwd=str(ROOT)).stdout.strip()
    except Exception:  # noqa: BLE001
        git_commit = None

    out = {
        "benchmark": "pii-competitors",
        "benchmarkVersion": 1,
        "scoring": "category-set per line (did the tool flag gold category C on a line containing a gold C span)",
        "environment": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "gitCommit": git_commit,
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "corpus": args.corpus,
            "samples": len(rows),
        },
        "openSource": open_source,
        "commercial": COMMERCIAL_NOT_EXECUTED,
    }
    dest = Path(__file__).parent / "competitors.json"
    dest.write_text(json.dumps(out, indent=2) + "\n")
    print(f"wrote {dest}", file=sys.stderr)

    # console summary
    print(f"\n  {'System':<34} {'P':>7} {'R':>7} {'F1':>7}  {'ms/sample':>10}")
    print(f"  {'-'*70}")
    for name, r in open_source.items():
        if r and "result" in r:
            o = r["result"]["overall"]
            print(f"  {name:<34} {o['precision']*100:>6.1f}% {o['recall']*100:>6.1f}% {o['f1']*100:>6.1f}%  {r['msPerSample']:>9.3f}")
        else:
            print(f"  {name:<34} {r.get('error', 'error')}")
    for name, why in COMMERCIAL_NOT_EXECUTED.items():
        print(f"  {name:<34} {why}")


if __name__ == "__main__":
    main()
