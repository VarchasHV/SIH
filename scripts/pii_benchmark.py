"""
pii_benchmark.py — PII Detection Benchmark
Compares Privacy Lens (JS regex + Verhoeff/Luhn checksums) against:
  • Regex-only baseline (Python, no ML)
  • Microsoft Presidio (regex + NLP NER)
  • spaCy NER (en_core_web_sm)
  • Flair NER (ner-english-ontonotes-large)

All models are evaluated on the same eval/labels/pii-corpus.jsonl corpus.
Metrics: precision, recall, F1, avg latency per sample (ms).

Run: python3 scripts/pii_benchmark.py
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).parent.parent
CORPUS_PATH = ROOT / "eval" / "labels" / "pii-corpus.jsonl"

# ─── load corpus ────────────────────────────────────────────────────────────

def load_corpus() -> list[dict]:
    samples = []
    for line in CORPUS_PATH.read_text().strip().splitlines():
        line = line.strip()
        if line:
            samples.append(json.loads(line))
    return samples

# ─── metric helpers ──────────────────────────────────────────────────────────

def prf(tp: int, fp: int, fn: int) -> dict:
    prec  = tp / (tp + fp) if (tp + fp) else 1.0
    rec   = tp / (tp + fn) if (tp + fn) else 1.0
    f1    = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    return dict(precision=prec, recall=rec, f1=f1, tp=tp, fp=fp, fn=fn)

def score(samples: list[dict], predictions: list[set]) -> dict:
    tp = fp = fn = 0
    for s, pred in zip(samples, predictions):
        want = set(s["categories"])
        for g in pred:
            if g in want:
                tp += 1
            else:
                fp += 1
        for w in want:
            if w not in pred:
                fn += 1
    return prf(tp, fp, fn)

# ─── MODEL 1: Privacy Lens (Python port of pii-rules.mjs) ────────────────────

def _verhoeff(digits: str) -> bool:
    D = [
        [0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],
        [3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],
        [6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],
        [9,8,7,6,5,4,3,2,1,0],
    ]
    P = [
        [0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],
        [8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],
        [2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8],
    ]
    s = re.sub(r"\D", "", digits)
    if len(s) != 12:
        return False
    c = 0
    for i, ch in enumerate(reversed(s)):
        c = D[c][P[i % 8][int(ch)]]
    return c == 0

def _luhn(digits: str) -> bool:
    s = re.sub(r"\D", "", digits)
    if not (12 <= len(s) <= 19):
        return False
    total, dbl = 0, False
    for ch in reversed(s):
        d = int(ch)
        if dbl:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        dbl = not dbl
    return total % 10 == 0

_PL_RULES: list[tuple[str, re.Pattern, object]] = [
    ("email",        re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'), None),
    ("aadhaar",      re.compile(r'\b\d{4}\s?\d{4}\s?\d{4}\b'), _verhoeff),
    ("pan",          re.compile(r'\b[A-Z]{5}[0-9]{4}[A-Z]\b'), None),
    ("gstin",        re.compile(r'\b\d{2}[A-Z]{5}\d{4}[A-Z][A-Z0-9]Z[A-Z0-9]\b'), None),
    ("ifsc",         re.compile(r'\b[A-Z]{4}0[A-Z0-9]{6}\b'), None),
    ("upi-vpa",      re.compile(r'\b[A-Za-z0-9.\-_]{2,}@(?:oksbi|okhdfcbank|okicici|okaxis|paytm|ybl|apl|ibl|axl|upi)\b', re.I), None),
    ("voter-id",     re.compile(r'\b[A-Z]{3}[0-9]{7}\b'), None),
    ("vehicle-reg",  re.compile(r'\b[A-Z]{2}[ \-]?\d{1,2}[ \-]?[A-Z]{1,3}[ \-]?\d{4}\b'), None),
    ("passport-in",  re.compile(r'\b[A-PR-WY][1-9]\d\s?\d{4}[1-9]\b'), None),
    ("credit-card",  re.compile(r'\b(?:\d[ \-]?){12,19}\b'), _luhn),
    ("phone-in",     re.compile(r'(?:\+?91[ \-]?)?[6-9]\d{9}\b'), None),
    ("ssn",          re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), None),
    ("ipv4",         re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b'), None),
    ("dob",          re.compile(r'\b(?:0?[1-9]|[12]\d|3[01])[/\-.](?:0?[1-9]|1[0-2])[/\-.](?:19|20)\d{2}\b'), None),
]

def _privacy_lens_detect(text: str) -> set[str]:
    cats: set[str] = set()
    for cat, rx, validate in _PL_RULES:
        for m in rx.finditer(text):
            if validate is None or validate(m.group(0)):
                cats.add(cat)
    return cats

def run_privacy_lens(samples: list[dict]) -> tuple[dict, float]:
    t0 = time.perf_counter()
    preds = [_privacy_lens_detect(s["text"]) for s in samples]
    elapsed = (time.perf_counter() - t0) * 1000
    return score(samples, preds), elapsed / len(samples)

# ─── MODEL 2: Regex-only baseline (no checksums) ─────────────────────────────

_REGEX_ONLY_RULES: list[tuple[str, re.Pattern]] = [
    ("email",        re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b')),
    ("aadhaar",      re.compile(r'\b\d{4}\s?\d{4}\s?\d{4}\b')),
    ("pan",          re.compile(r'\b[A-Z]{5}[0-9]{4}[A-Z]\b')),
    ("gstin",        re.compile(r'\b\d{2}[A-Z]{5}\d{4}[A-Z][A-Z0-9]Z[A-Z0-9]\b')),
    ("ifsc",         re.compile(r'\b[A-Z]{4}0[A-Z0-9]{6}\b')),
    ("upi-vpa",      re.compile(r'\b[A-Za-z0-9.\-_]{2,}@(?:oksbi|okhdfcbank|okicici|okaxis|paytm|ybl|apl|ibl|axl|upi)\b', re.I)),
    ("voter-id",     re.compile(r'\b[A-Z]{3}[0-9]{7}\b')),
    ("vehicle-reg",  re.compile(r'\b[A-Z]{2}[ \-]?\d{1,2}[ \-]?[A-Z]{1,3}[ \-]?\d{4}\b')),
    ("passport-in",  re.compile(r'\b[A-PR-WY][1-9]\d\s?\d{4}[1-9]\b')),
    ("credit-card",  re.compile(r'\b(?:\d[ \-]?){12,19}\b')),
    ("phone-in",     re.compile(r'(?:\+?91[ \-]?)?[6-9]\d{9}\b')),
    ("ssn",          re.compile(r'\b\d{3}-\d{2}-\d{4}\b')),
    ("ipv4",         re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b')),
    ("dob",          re.compile(r'\b(?:0?[1-9]|[12]\d|3[01])[/\-.](?:0?[1-9]|1[0-2])[/\-.](?:19|20)\d{2}\b')),
]

def run_regex_baseline(samples: list[dict]) -> tuple[dict, float]:
    t0 = time.perf_counter()
    preds = []
    for s in samples:
        cats: set[str] = set()
        for cat, rx in _REGEX_ONLY_RULES:
            if rx.search(s["text"]):
                cats.add(cat)
        preds.append(cats)
    elapsed = (time.perf_counter() - t0) * 1000
    return score(samples, preds), elapsed / len(samples)

# ─── MODEL 3: Microsoft Presidio ─────────────────────────────────────────────

_PRESIDIO_MAP = {
    "EMAIL_ADDRESS":              "email",
    "PHONE_NUMBER":               "phone-in",
    "CREDIT_CARD":                "credit-card",
    "IN_AADHAAR":                 "aadhaar",
    "IN_PAN":                     "pan",
    "IN_PASSPORT":                "passport-in",
    "IN_VOTER":                   "voter-id",
    "IN_VEHICLE_REGISTRATION":    "vehicle-reg",
    "US_SSN":                     "ssn",
    "IP_ADDRESS":                 "ipv4",
    "DATE_TIME":                  "dob",
    "IN_GST_NO":                  "gstin",
    "IFSC_CODE":                  "ifsc",
}

def run_presidio(samples: list[dict]) -> tuple[dict | None, float | str]:
    try:
        from presidio_analyzer import AnalyzerEngine
        analyzer = AnalyzerEngine()
        t0 = time.perf_counter()
        preds = []
        for s in samples:
            results = analyzer.analyze(text=s["text"], language="en")
            cats: set[str] = set()
            for r in results:
                mapped = _PRESIDIO_MAP.get(r.entity_type)
                if mapped:
                    cats.add(mapped)
            preds.append(cats)
        elapsed = (time.perf_counter() - t0) * 1000
        return score(samples, preds), elapsed / len(samples)
    except Exception as e:
        return None, str(e)

# ─── MODEL 4: spaCy NER ──────────────────────────────────────────────────────

_SPACY_MAP = {
    "PERSON":       "full name",
    "DATE":         "dob",
}

def run_spacy(samples: list[dict]) -> tuple[dict | None, float | str]:
    try:
        import spacy
        try:
            nlp = spacy.load("en_core_web_sm")
        except OSError:
            subprocess.run(
                [sys.executable, "-m", "spacy", "download", "en_core_web_sm"],
                check=True, capture_output=True
            )
            nlp = spacy.load("en_core_web_sm")

        t0 = time.perf_counter()
        preds = []
        for s in samples:
            doc = nlp(s["text"])
            cats: set[str] = set()
            for ent in doc.ents:
                mapped = _SPACY_MAP.get(ent.label_)
                if mapped:
                    cats.add(mapped)
            # spaCy doesn't detect email natively — add via regex
            if re.search(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b', s["text"]):
                cats.add("email")
            preds.append(cats)
        elapsed = (time.perf_counter() - t0) * 1000
        return score(samples, preds), elapsed / len(samples)
    except Exception as e:
        return None, str(e)

# ─── MODEL 5: Flair NER ──────────────────────────────────────────────────────

_FLAIR_MAP = {
    "PER":  "full name",
}

def run_flair(samples: list[dict]) -> tuple[dict | None, float | str]:
    try:
        from flair.data import Sentence
        from flair.models import SequenceTagger

        tagger = SequenceTagger.load("flair/ner-english-ontonotes-large")

        t0 = time.perf_counter()
        preds = []
        for s in samples:
            sentence = Sentence(s["text"])
            tagger.predict(sentence)
            cats: set[str] = set()
            for entity in sentence.get_spans("ner"):
                mapped = _FLAIR_MAP.get(entity.tag)
                if mapped:
                    cats.add(mapped)
            if re.search(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b', s["text"]):
                cats.add("email")
            preds.append(cats)
        elapsed = (time.perf_counter() - t0) * 1000
        return score(samples, preds), elapsed / len(samples)
    except Exception as e:
        return None, str(e)

# ─── report ──────────────────────────────────────────────────────────────────

def bar(v: float, width: int = 20) -> str:
    filled = round(v * width)
    return "█" * filled + "░" * (width - filled)

def print_row(name: str, metrics: dict, latency: float):
    p, r, f = metrics["precision"], metrics["recall"], metrics["f1"]
    print(
        f"  {name:<34}  "
        f"P={p*100:5.1f}%  R={r*100:5.1f}%  F1={f*100:5.1f}%  "
        f"[{bar(f)}]  "
        f"~{latency:6.3f} ms/sample  "
        f"(TP={metrics['tp']} FP={metrics['fp']} FN={metrics['fn']})"
    )

def main():
    samples = load_corpus()
    n = len(samples)
    pos = sum(1 for s in samples if s["categories"])
    neg = n - pos
    print(f"\n{'='*90}")
    print("  Privacy Lens — PII Detection Model Comparison Benchmark")
    print(f"  Corpus: {n} samples  ({pos} with PII, {neg} negatives)")
    print(f"{'='*90}\n")

    all_results: list[tuple[str, dict | None, float | str]] = []

    print("  [1/5] Privacy Lens (regex + Verhoeff/Luhn checksums)...")
    m, lat = run_privacy_lens(samples)
    all_results.append(("Privacy Lens (regex + checksums)", m, lat))

    print("  [2/5] Regex-only baseline (no checksums)...")
    m, lat = run_regex_baseline(samples)
    all_results.append(("Regex-only (no checksums)", m, lat))

    print("  [3/5] Microsoft Presidio...")
    m, lat = run_presidio(samples)
    if m is None:
        print(f"         ⚠  Presidio not available: {lat}")
    all_results.append(("Microsoft Presidio", m, lat))

    print("  [4/5] spaCy NER (en_core_web_sm)...")
    m, lat = run_spacy(samples)
    if m is None:
        print(f"         ⚠  spaCy not available: {lat}")
    all_results.append(("spaCy NER (en_core_web_sm)", m, lat))

    print("  [5/5] Flair NER (ontonotes-large)...")
    m, lat = run_flair(samples)
    if m is None:
        print(f"         ⚠  Flair not available: {lat}")
    all_results.append(("Flair NER (ontonotes-large)", m, lat))

    print(f"\n{'─'*90}")
    print(f"  {'Model':<34}  {'Precision':>9}  {'Recall':>8}  {'F1':>6}  {'F1 bar':<22}  Latency")
    print(f"{'─'*90}")

    for name, metrics, latency in all_results:
        if metrics is None:
            print(f"  {name:<34}  {'UNAVAILABLE — not installed for Python 3.14'}")
        else:
            print_row(name, metrics, latency)

    print(f"{'─'*90}")

    valid = [(n, m, l) for n, m, l in all_results if m is not None]
    if valid:
        best = max(valid, key=lambda x: x[1]["f1"])
        fastest = min(valid, key=lambda x: x[2])
        print(f"\n  🏆  Highest F1   : {best[0]}  ({best[1]['f1']*100:.1f}%)")
        print(f"  ⚡  Fastest       : {fastest[0]}  (~{fastest[2]:.4f} ms/sample)")

    print(f"\n{'='*90}\n")

if __name__ == "__main__":
    main()
