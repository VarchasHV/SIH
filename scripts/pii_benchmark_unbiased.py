"""
pii_benchmark_unbiased.py — Independent adversarial PII benchmark.

Corpus design principles (NOT derived from pii-rules.mjs):
  1. True positives embedded in realistic, noisy sentence context.
  2. Adversarial false-positive traps: strings that structurally match the
     regex patterns but are NOT real PII (product codes, order IDs, etc.).
  3. False-negative traps: real PII that Privacy Lens structurally cannot
     detect (e.g. UPI VPAs whose bank handle isn't in the hardcoded list).
  4. Verhoeff-/Luhn-valid numbers are computed fresh — not copy-pasted from
     the project corpus.
  5. Near-miss numbers (fail Verhoeff/Luhn) to confirm checksum gating works.

Run: python3 scripts/pii_benchmark_unbiased.py
"""

from __future__ import annotations
import json, re, subprocess, sys, time
from pathlib import Path

ROOT = Path(__file__).parent.parent

# ═══════════════════════════════════════════════════════════════════════════
# Checksum helpers for GENERATING valid corpus values. Written here rather than
# imported, so the ground truth is independent of the detector under test.
# (The JS benchmark's independent generator lives in
#  eval/bench/lib/independent-validators.mjs — anchored to a published
#  known-answer vector.)
# ═══════════════════════════════════════════════════════════════════════════

_VD = [[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],
       [3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],
       [6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],
       [9,8,7,6,5,4,3,2,1,0]]
_VP = [[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],
       [8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],
       [2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]]

def _verhoeff_check(s: str) -> bool:
    s = re.sub(r"\D","",s)
    if len(s) != 12: return False
    c = 0
    for i, ch in enumerate(reversed(s)):
        c = _VD[c][_VP[i%8][int(ch)]]
    return c == 0

def _make_aadhaar(prefix11: str) -> str:
    """Compute check digit so the 12-digit number passes Verhoeff."""
    for d in range(10):
        if _verhoeff_check(prefix11 + str(d)):
            return prefix11 + str(d)
    raise ValueError(f"no valid check digit for {prefix11}")

def _luhn_check(s: str) -> bool:
    s = re.sub(r"\D","",s)
    if not (12 <= len(s) <= 19): return False
    total, dbl = 0, False
    for ch in reversed(s):
        d = int(ch)
        if dbl:
            d *= 2
            if d > 9: d -= 9
        total += d
        dbl = not dbl
    return total % 10 == 0

# Pre-generate Verhoeff-valid Aadhaar numbers from prefixes unrelated to the
# project corpus. Each is independently computed, not copied from pii-rules.
_A = {
    "a1": _make_aadhaar("11122233344"),  # generated fresh
    "a2": _make_aadhaar("55566677788"),
    "a3": _make_aadhaar("99900011122"),
    "a4": _make_aadhaar("44455566677"),
    "a5": _make_aadhaar("77788899900"),
    "a6": _make_aadhaar("12312312312"),
}
def _fmt(n: str) -> str:
    """Format 12-digit string as XXXX XXXX XXXX for Aadhaar readability."""
    return f"{n[:4]} {n[4:8]} {n[8:]}"

# ═══════════════════════════════════════════════════════════════════════════
# CORPUS  (built to be independent of and adversarial toward the rules)
# ═══════════════════════════════════════════════════════════════════════════
def build_corpus() -> list[dict]:
    a = _A  # shorthand
    corpus = [

        # ── EMAIL (true positives) ──────────────────────────────────────────
        {"text": f"Please send the invoice to priya.sharma@gmail.com by EOD.",            "categories": ["email"]},
        {"text": f"Two contacts: ravi.k@yahoo.co.in and suresh@company.org on the CC.",   "categories": ["email"]},
        {"text": f"Account linked to mohan_das@outlook.com — verify OTP.",                "categories": ["email"]},
        {"text": f"Support ticket raised by ankit+test@startup.io last night.",           "categories": ["email"]},
        {"text": f"Payroll notice emailed to hr-dept@bigcorp.net — check spam.",          "categories": ["email"]},
        {"text": f"Reply-to: no-reply@service.in. Do not respond to this address.",       "categories": ["email"]},

        # ── EMAIL (negatives — not emails) ──────────────────────────────────
        {"text": "Visit our portal at www.example.com for more details.",                  "categories": []},
        {"text": "Path: /var/log/nginx/access.log. Size: 2.1 GB.",                        "categories": []},
        {"text": "Domain transfer for example.co.in initiated by registrar.",              "categories": []},

        # ── PHONE-IN (true positives, varied formats) ────────────────────────
        {"text": "Helpdesk available at +91 9988776655 Mon–Sat 9am–6pm.",                 "categories": ["phone-in"]},
        {"text": "Emergency contact number: 8123456789 (call any time).",                  "categories": ["phone-in"]},
        {"text": "WhatsApp-only line 7700010203. Do not call.",                            "categories": ["phone-in"]},
        {"text": "On-call SRE reachable on 6543219870 during night shifts.",              "categories": ["phone-in"]},
        {"text": "Customer mobile 91-9000088800 verified via two-factor.",                 "categories": ["phone-in"]},

        # ── PHONE-IN (adversarial — 10-digit, starts 6-9, but NOT a phone) ──
        # Privacy Lens has NO way to distinguish these from real phone numbers.
        {"text": "Package barcode 9876543210 scanned at sorting facility.",                "categories": []},
        {"text": "Transaction ID 8001234567 approved by payment gateway.",                 "categories": []},
        {"text": "Catalogue item 7654320011 added to the seasonal collection.",            "categories": []},
        {"text": "Shipment tracking number 6999000111 is now out for delivery.",           "categories": []},

        # ── AADHAAR (true positives — Verhoeff-valid, freshly generated) ────
        {"text": f"Aadhaar {_fmt(a['a1'])} submitted for e-KYC verification.",            "categories": ["aadhaar"]},
        {"text": f"UID number {_fmt(a['a2'])} found on the scanned form. Please redact.", "categories": ["aadhaar"]},
        {"text": f"Account seeded with Aadhaar {_fmt(a['a3'])}.",                         "categories": ["aadhaar"]},
        {"text": f"e-sign initiated. Aadhaar OTP sent to mobile linked to {_fmt(a['a4'])}.", "categories": ["aadhaar"]},
        {"text": f"UIDAI record for {a['a5']} — dob mismatch detected.",                  "categories": ["aadhaar"]},
        {"text": f"Two UIDs on form: {_fmt(a['a1'])} and {_fmt(a['a6'])}.",              "categories": ["aadhaar"]},

        # ── AADHAAR (adversarial — fail Verhoeff, look like Aadhaar) ────────
        # These 12-digit numbers DO match the regex but fail the checksum.
        {"text": "Customer token 1234 5678 9013 printed on the receipt.",                  "categories": []},
        {"text": "Reference 9999 8888 7776 issued at the counter — note the space.",      "categories": []},
        {"text": "Order number 1111 2222 3334 confirmed via SMS.",                         "categories": []},
        {"text": "Slot booking ID 5555 4444 3331 expires in 15 minutes.",                  "categories": []},
        {"text": "Random 12-digit serial 2020 1010 5050 printed on back panel.",           "categories": []},

        # ── PAN (true positives) ─────────────────────────────────────────────
        {"text": "TDS deducted under PAN ABCPS1234K. Form 16 issued.",                    "categories": ["pan"]},
        {"text": "ITR-2 filed for PAN BCDQR5678M — AY 2024-25.",                         "categories": ["pan"]},
        {"text": "KYC complete. Bank linked to PAN holder CDERS9012N.",                   "categories": ["pan"]},
        {"text": "Advance tax challan raised under PAN GHIJK3456L.",                      "categories": ["pan"]},

        # ── PAN (adversarial — format AAAAA9999A, common in product codes) ──
        # 5 uppercase letters + 4 digits + 1 uppercase letter = valid PAN format.
        # Privacy Lens has NO checksum to disambiguate these.
        {"text": "Batch code XYZAB1234C cleared quality inspection on Day 3.",             "categories": []},
        {"text": "License key MNOPQ5678R is tied to one device only.",                    "categories": []},
        {"text": "Internal project code STUVW9012X — do not share externally.",            "categories": []},
        {"text": "Reagent lot ABCDE0001F used in trial batch #7.",                        "categories": []},
        {"text": "Firmware build ZZZZZ9999Z released to manufacturing line.",              "categories": []},

        # ── CREDIT CARD (true positives — Luhn-valid well-known test numbers) ─
        {"text": "Card 4111 1111 1111 1111 declined — try a different payment method.",   "categories": ["credit-card"]},
        {"text": "Recurring billing on Mastercard 5500 0000 0000 0004 processed.",        "categories": ["credit-card"]},
        {"text": "Refund to card 4532 0151 1283 0366 within 5 business days.",            "categories": ["credit-card"]},
        {"text": "Amex ending 3714 496353 98431 flagged for foreign transaction.",        "categories": ["credit-card"]},
        {"text": "Discover card 6011 0009 9013 9424 charged for subscription.",           "categories": ["credit-card"]},

        # ── CREDIT CARD (adversarial — Luhn invalid, same length/format) ───
        {"text": "Serial 4111 1111 1111 1112 stamped on the PCB — not a card number.",   "categories": []},
        {"text": "Part 5500 0000 0000 0005 ordered from supplier.",                       "categories": []},
        {"text": "Bin range 1234 5678 9012 3456 does not map to any known card scheme.", "categories": []},
        {"text": "Code 9999 8888 7777 6666 printed on packaging.",                        "categories": []},

        # ── IFSC (true positives) ─────────────────────────────────────────────
        {"text": "NEFT to HDFC0001234 (Koramangala branch) processed at 11:42.",         "categories": ["ifsc"]},
        {"text": "Vendor payment RTGS to SBIN0005678 — ₹2,50,000.",                      "categories": ["ifsc"]},
        {"text": "Receiving IFSC is ICIC0000901. Cross-checked with passbook.",           "categories": ["ifsc"]},
        {"text": "Salary credit via AXIS0001111 to beneficiary account.",                 "categories": ["ifsc"]},

        # ── IFSC (adversarial — 4-letter code + 0 + 6 alphanum = common format) ─
        # IFSC regex [A-Z]{4}0[A-Z0-9]{6} can match non-IFSC codes.
        {"text": "Server node SERV0000123 restarted at 03:14 UTC.",                       "categories": []},
        {"text": "Product model PROD0123456 dispatched from hub warehouse.",               "categories": []},
        {"text": "Process ID PROC0987654 terminated after timeout.",                       "categories": []},

        # ── UPI VPA (true positives — handles in the hardcoded whitelist) ───
        {"text": "Pay ₹500 to aditi@okhdfcbank for the shared meal.",                    "categories": ["upi-vpa"]},
        {"text": "Merchant VPA: store@okaxis. Scan and pay.",                             "categories": ["upi-vpa"]},
        {"text": "Send to rahul@paytm — he'll split it with everyone.",                  "categories": ["upi-vpa"]},

        # ── UPI VPA (FALSE NEGATIVES for Privacy Lens — real UPI, not in list) ─
        # The pii-rules.mjs whitelist only covers 10 specific bank handles.
        # These are legitimate UPI IDs that Privacy Lens WILL MISS.
        {"text": "My UPI ID is sunita.sharma@hdfcbank — send the rent there.",           "categories": ["upi-vpa"]},
        {"text": "Pay to priya@sbi. It's linked to my savings account.",                  "categories": ["upi-vpa"]},
        {"text": "Vendor UPI: supplier123@icicibank registered on portal.",               "categories": ["upi-vpa"]},
        {"text": "Use store@yesbank for UPI checkout on the website.",                    "categories": ["upi-vpa"]},
        {"text": "Business ID: company@kotak — preferred for B2B transfers.",            "categories": ["upi-vpa"]},
        {"text": "Registered UPI ID: freelancer@axisbank for payment.",                   "categories": ["upi-vpa"]},

        # ── GSTIN (true positives) ─────────────────────────────────────────────
        {"text": "GSTIN 29ABCDE1234F1Z5 on the B2B invoice — ITC eligible.",             "categories": ["gstin"]},
        {"text": "Vendor GSTIN: 07BCDGH5678J2Z3. Verify before booking.",                "categories": ["gstin"]},
        {"text": "E-way bill GSTIN: 27DEFPQ9012M3Z4. Movement within Maharashtra.",      "categories": ["gstin"]},

        # ── GSTIN (near-miss — one character off) ─────────────────────────────
        {"text": "Code 29ABCDE1234F1A5 not found — check if state code is correct.",     "categories": []},  # A not Z

        # ── SSN (true positives) ──────────────────────────────────────────────
        {"text": "W-9 on file. SSN 123-45-6789 verified by payroll.",                    "categories": ["ssn"]},
        {"text": "Benefit enrollment requires SSN 987-65-4321.",                          "categories": ["ssn"]},
        {"text": "US employee tax ID: 456-78-9012. Please encrypt before storing.",      "categories": ["ssn"]},

        # ── SSN (adversarial — pattern DDD-DD-DDDD matches non-SSN strings) ──
        {"text": "Tracking reference 123-45-6790 is out for last-mile delivery.",        "categories": []},
        {"text": "Part number 456-78-1234 on back-order until next quarter.",             "categories": []},
        {"text": "Phone-extension format 987-65-0001 shown on desk placard.",             "categories": []},

        # ── IPv4 (true positives) ─────────────────────────────────────────────
        {"text": "DB primary host: 192.168.10.5. Replica at 192.168.10.6.",              "categories": ["ipv4"]},
        {"text": "Intrusion attempt from 203.0.113.195 — block at firewall.",             "categories": ["ipv4"]},
        {"text": "Internal API gateway at 10.0.0.1:8080 serves all zone-A traffic.",     "categories": ["ipv4"]},
        {"text": "VPN tunnel established with peer 172.16.0.1.",                          "categories": ["ipv4"]},

        # ── IPv4 (negatives — version numbers, scores that look like IPs) ────
        {"text": "App version 1.2.3.4 available on the download page.",                   "categories": []},
        {"text": "Peer score: 9.5.3.1 — exceeds passing threshold.",                     "categories": []},
        {"text": "CSS colour 255.255.255.0 used for background.",                          "categories": []},  # 255.255.255.0 is actually a valid IP, but is a subnet mask typically

        # ── DOB (true positives) ──────────────────────────────────────────────
        {"text": "Applicant DOB: 14/03/1998. Age confirmed as 28 years.",                "categories": ["dob"]},
        {"text": "As per Aadhaar, date of birth is 25-12-1985. Senior citizen: No.",     "categories": ["dob"]},
        {"text": "Born on 01.01.2000 — eligible for the under-25 scholarship scheme.",   "categories": ["dob"]},
        {"text": "Patient record DOB 31/07/1975. Senior discount applied.",               "categories": ["dob"]},
        {"text": "Insurance nominee date of birth: 04/08/1990. Verified.",               "categories": ["dob"]},

        # ── DOB (adversarial — dates in non-DOB context, same DD/MM/YYYY format) ─
        # Privacy Lens flags ANY DD/MM/YYYY date, not just birth dates.
        {"text": "Version 14/03/2019 released to production environment.",               "categories": []},
        {"text": "File last modified on 01/06/2023. Upload before 15/08/2023.",          "categories": []},
        {"text": "Promotion valid from 25/12/2024 to 05/01/2025 only.",                  "categories": []},
        {"text": "Meeting on 10/10/2025 at 3pm in Conference Room B.",                   "categories": []},
        {"text": "Invoice date: 31/03/2024. Payment due: 30/04/2024.",                   "categories": []},

        # ── PASSPORT-IN (true positives) ─────────────────────────────────────
        {"text": "Passport P1234567 expires 2028. Renewal application submitted.",       "categories": ["passport-in"]},
        {"text": "ECNR passport R9876541 stamped with UAE work visa.",                   "categories": ["passport-in"]},
        {"text": "Travel document A1122334 — origin Mumbai PSK, issued 2022.",           "categories": ["passport-in"]},

        # ── VOTER-ID (true positives) ─────────────────────────────────────────
        {"text": "Voter ID ABC1234567 enrolled at booth 14, ward 7.",                    "categories": ["voter-id"]},
        {"text": "EPIC XYZ9876543 confirmed. Polling station: Govt High School.",        "categories": ["voter-id"]},
        {"text": "Name found in electoral roll for EPIC DEF2345678.",                    "categories": ["voter-id"]},

        # ── VOTER-ID (adversarial — [A-Z]{3}[0-9]{7} is an extremely common format) ─
        # Privacy Lens has NO checksum or prefix restriction — these WILL be flagged.
        {"text": "Product SKU SKU1234567 is back in stock — order now.",                 "categories": []},
        {"text": "Support ticket REF9876543 escalated to Tier 2 team.",                  "categories": []},
        {"text": "Invoice number INV2345678 sent to accounts payable.",                  "categories": []},
        {"text": "Error code ERR0001234 in the migration log — investigate.",            "categories": []},
        {"text": "Job posting JOB7654321 received 312 applications this week.",          "categories": []},
        {"text": "Container CNT1111111 arrived at JNPT ahead of schedule.",              "categories": []},
        {"text": "Serial SER8888888 registered for warranty on the portal.",             "categories": []},

        # ── VEHICLE-REG (true positives) ─────────────────────────────────────
        {"text": "Challan issued to KA01AB1234 for illegal parking near MG Road.",       "categories": ["vehicle-reg"]},
        {"text": "Registered owner of MH12XY5678 is Ms. Rekha Nair — PUC due.",         "categories": ["vehicle-reg"]},
        {"text": "DL9CAB3456 failed emission test — report to RTO within 7 days.",      "categories": ["vehicle-reg"]},

        # ── VEHICLE-REG (negatives) ─────────────────────────────────────────
        {"text": "Road widening on NH48 corridor approved for FY2025-26.",               "categories": []},
        {"text": "Zone 3B extends from sector 12 to sector 18.",                         "categories": []},

        # ── MULTI-PII sentences ────────────────────────────────────────────────
        {"text": f"KYC form: Name — Aditi Sharma. Aadhaar — {_fmt(a['a1'])}. Email — aditi@example.com.", "categories": ["aadhaar", "email"]},
        {"text": "Contact 9988776655 or email accounts@bank.co.in. IFSC HDFC0001234.",  "categories": ["phone-in", "email", "ifsc"]},
        {"text": "PAN ABCPS1234K. DOB 14/03/1998. Voter ID ABC1234567.",                "categories": ["pan", "dob", "voter-id"]},
        {"text": "Log: 192.168.10.5 tried SSN 123-45-6789 in a form field.",            "categories": ["ipv4", "ssn"]},
        {"text": "Card 4111 1111 1111 1111 billed. Backup UPI: store@okaxis.",          "categories": ["credit-card", "upi-vpa"]},
        {"text": f"Aadhaar {_fmt(a['a3'])} & PAN CDERS9012N linked. GSTIN 29ABCDE1234F1Z5.", "categories": ["aadhaar", "pan", "gstin"]},

        # ── GENERIC CLEAN NEGATIVES ───────────────────────────────────────────
        {"text": "Q3 earnings report will be published next Tuesday at 5pm IST.",        "categories": []},
        {"text": "Submit leave applications before the 5th of each month.",              "categories": []},
        {"text": "Planned maintenance window: Saturday 01:00–04:00 UTC.",                "categories": []},
        {"text": "All staff must complete compliance training by 30 September.",         "categories": []},
        {"text": "New cafeteria menu live from Monday. Feedback welcome.",               "categories": []},
        {"text": "Appraisal cycle opens next quarter. Ratings are 1–5.",                 "categories": []},
        {"text": "Please upgrade your browser for improved security.",                   "categories": []},
        {"text": "Project milestone 3 achieved — moving to UAT phase.",                  "categories": []},
        {"text": "The AGM is scheduled for 15 November 2025 at Taj Lands End.",         "categories": []},
        {"text": "Holiday list for FY2025-26 published on the intranet portal.",         "categories": []},
    ]
    return corpus

# ═══════════════════════════════════════════════════════════════════════════
# MODELS
# ═══════════════════════════════════════════════════════════════════════════

def prf(tp, fp, fn):
    p = tp/(tp+fp) if tp+fp else 1.0
    r = tp/(tp+fn) if tp+fn else 1.0
    f = 2*p*r/(p+r) if p+r else 0.0
    return dict(precision=p, recall=r, f1=f, tp=tp, fp=fp, fn=fn)

def score(samples, predictions):
    tp=fp=fn=0
    for s, pred in zip(samples, predictions):
        want = set(s["categories"])
        for g in pred:
            if g in want: tp+=1
            else: fp+=1
        for w in want:
            if w not in pred: fn+=1
    return prf(tp,fp,fn)

# ── Privacy Lens (THE canonical detector — client/lib/pii-rules.mjs) ─────────
#
# There is exactly one Privacy Lens PII detector: client/lib/pii-rules.mjs, the
# code the browser extension ships. We reach it from Python through the Node
# bridge eval/bench/detect-cli.mjs so this benchmark can never drift from what
# actually runs. No Python re-implementation.

import shutil
import sys

_NODE = shutil.which("node")
_DETECT_CLI = ROOT / "eval" / "bench" / "detect-cli.mjs"

def _run_js_detector(detector, texts):
    """Return (list[set[str]] predictions, mean_ms_per_sample). Raises on failure."""
    if not _NODE:
        raise RuntimeError("node not found on PATH — cannot run the Privacy Lens detector")
    proc = subprocess.run(
        [_NODE, str(_DETECT_CLI), "--detector", detector],
        input=json.dumps(texts), capture_output=True, text=True, cwd=str(ROOT),
    )
    if proc.returncode != 0:
        raise RuntimeError(f"detect-cli ({detector}) failed: {proc.stderr[:300]}")
    rows = json.loads(proc.stdout)
    preds = [set(r["categories"]) for r in rows]
    mean_ms = sum(r["ms"] for r in rows) / len(rows) if rows else 0.0
    return preds, mean_ms

def run_privacy_lens(samples):
    preds, ms = _run_js_detector("current", [s["text"] for s in samples])
    return score(samples, preds), ms, preds

# ── Regex-only baseline: same corpus, loose patterns, NO checksums/gating ────
# (eval/bench/detectors/naive-regex.mjs — shows what the engineering buys.)

def run_regex_baseline(samples):
    preds, ms = _run_js_detector("naive-regex", [s["text"] for s in samples])
    return score(samples, preds), ms

# ── Microsoft Presidio ──────────────────────────────────────────────────────

_PRESIDIO_MAP = {
    "EMAIL_ADDRESS": "email", "PHONE_NUMBER": "phone-in",
    "CREDIT_CARD": "credit-card", "IN_AADHAAR": "aadhaar",
    "IN_PAN": "pan", "IN_PASSPORT": "passport-in",
    "IN_VOTER": "voter-id", "IN_VEHICLE_REGISTRATION": "vehicle-reg",
    "US_SSN": "ssn", "IP_ADDRESS": "ipv4", "DATE_TIME": "dob",
    "IN_GST_NO": "gstin", "IFSC_CODE": "ifsc",
}

def run_presidio(samples):
    try:
        from presidio_analyzer import AnalyzerEngine
        analyzer = AnalyzerEngine()
        t0 = time.perf_counter()
        preds = []
        for s in samples:
            results = analyzer.analyze(text=s["text"], language="en")
            cats = set()
            for r in results:
                m = _PRESIDIO_MAP.get(r.entity_type)
                if m: cats.add(m)
            preds.append(cats)
        ms = (time.perf_counter()-t0)*1000/len(samples)
        return score(samples, preds), ms
    except Exception as e:
        return None, str(e)

# ── spaCy NER ───────────────────────────────────────────────────────────────

_SPACY_MAP = {"PERSON": "full name", "DATE": "dob"}

def run_spacy(samples):
    try:
        import spacy
        try: nlp = spacy.load("en_core_web_sm")
        except OSError:
            subprocess.run([sys.executable,"-m","spacy","download","en_core_web_sm"],check=True,capture_output=True)
            nlp = spacy.load("en_core_web_sm")
        t0 = time.perf_counter()
        preds = []
        for s in samples:
            doc = nlp(s["text"])
            cats = set()
            for ent in doc.ents:
                m = _SPACY_MAP.get(ent.label_)
                if m: cats.add(m)
            if re.search(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b', s["text"]):
                cats.add("email")
            preds.append(cats)
        ms = (time.perf_counter()-t0)*1000/len(samples)
        return score(samples, preds), ms
    except Exception as e:
        return None, str(e)

# ── Flair NER ───────────────────────────────────────────────────────────────

_FLAIR_MAP = {"PER": "full name"}

def run_flair(samples):
    try:
        from flair.data import Sentence
        from flair.models import SequenceTagger
        tagger = SequenceTagger.load("flair/ner-english-ontonotes-large")
        t0 = time.perf_counter()
        preds = []
        for s in samples:
            sent = Sentence(s["text"])
            tagger.predict(sent)
            cats = set()
            for ent in sent.get_spans("ner"):
                m = _FLAIR_MAP.get(ent.tag)
                if m: cats.add(m)
            if re.search(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b', s["text"]):
                cats.add("email")
            preds.append(cats)
        ms = (time.perf_counter()-t0)*1000/len(samples)
        return score(samples, preds), ms
    except Exception as e:
        return None, str(e)

# ═══════════════════════════════════════════════════════════════════════════
# ANALYSIS: per-category breakdown for Privacy Lens
# ═══════════════════════════════════════════════════════════════════════════

def per_category_breakdown(samples, pl_preds):
    cats = sorted(set(c for s in samples for c in s["categories"]))
    rows = []
    for cat in cats:
        tp=fp=fn=0
        for s, pred_set in zip(samples, pl_preds):
            want = cat in s["categories"]
            got = cat in pred_set
            if want and got:   tp+=1
            elif got and not want: fp+=1
            elif want and not got: fn+=1
        p = tp/(tp+fp) if tp+fp else 1.0
        r = tp/(tp+fn) if tp+fn else 1.0
        f = 2*p*r/(p+r) if p+r else 0.0
        rows.append((cat, tp, fp, fn, p, r, f))
    return rows

# ═══════════════════════════════════════════════════════════════════════════
# REPORT
# ═══════════════════════════════════════════════════════════════════════════

def bar(v, w=18): return "█"*round(v*w) + "░"*(w-round(v*w))

def main():
    samples = build_corpus()
    n = len(samples)
    pos = sum(1 for s in samples if s["categories"])
    neg = n - pos
    print(f"\n{'='*95}")
    print("  Privacy Lens — ADVERSARIAL PII Benchmark (independently generated corpus)")
    print(f"  {n} samples  ({pos} with PII  ·  {neg} clean negatives)")
    print(f"  Includes false-positive traps + false-negative traps for Privacy Lens")
    print(f"{'='*95}\n")

    print("  [1/5] Privacy Lens (client/lib/pii-rules.mjs via node bridge)...")
    pl_m, pl_lat, pl_preds = run_privacy_lens(samples)

    print("  [2/5] Regex-only baseline (no checksums)...")
    re_m, re_lat = run_regex_baseline(samples)

    print("  [3/5] Microsoft Presidio...")
    pr_m, pr_lat = run_presidio(samples)
    if pr_m is None: print(f"         ⚠  {pr_lat}")

    print("  [4/5] spaCy NER (en_core_web_sm)...")
    sp_m, sp_lat = run_spacy(samples)
    if sp_m is None: print(f"         ⚠  {sp_lat}")

    print("  [5/5] Flair NER (ontonotes-large)...")
    fl_m, fl_lat = run_flair(samples)
    if fl_m is None: print(f"         ⚠  {fl_lat}")

    all_results = [
        ("Privacy Lens (pii-rules.mjs)",     pl_m, pl_lat),
        ("Regex-only (no checksums)",        re_m, re_lat),
        ("Microsoft Presidio",               pr_m, pr_lat),
        ("spaCy NER (en_core_web_sm)",       sp_m, sp_lat),
        ("Flair NER (ontonotes-large)",      fl_m, fl_lat),
    ]

    print(f"\n{'─'*95}")
    print(f"  {'Model':<35}  {'Precision':>9}  {'Recall':>8}  {'F1':>6}  {'[F1 bar]':<20}  {'Latency':>12}  TP  FP  FN")
    print(f"{'─'*95}")
    for name, m, lat in all_results:
        if m is None:
            print(f"  {name:<35}  UNAVAILABLE: {lat}")
        else:
            p,r,f = m['precision'],m['recall'],m['f1']
            print(f"  {name:<35}  {p*100:>8.1f}%  {r*100:>7.1f}%  {f*100:>5.1f}%  [{bar(f)}]  {lat:>9.3f} ms  {m['tp']:>2}  {m['fp']:>2}  {m['fn']:>2}")
    print(f"{'─'*95}")

    # per-category breakdown for Privacy Lens
    print(f"\n  Privacy Lens — per-category breakdown (honest):")
    print(f"  {'Category':<18}  {'P':>7}  {'R':>7}  {'F1':>7}  TP  FP  FN  Note")
    print(f"  {'─'*80}")
    for cat, tp, fp, fn, p, r, f in per_category_breakdown(samples, pl_preds):
        note = ""
        if fp > 0: note = f"⚠  {fp} false positive(s)"
        if fn > 0: note += f"{'  ' if note else ''}⚠  {fn} missed"
        print(f"  {cat:<18}  {p*100:>6.0f}%  {r*100:>6.0f}%  {f*100:>6.0f}%   {tp:>1}   {fp:>1}   {fn:>1}  {note}")

    unavailable = [n for n, m, _ in all_results if m is None]
    if unavailable:
        print(f"\n  Not measured this run (package not installed): {', '.join(unavailable)}")
    print("\n  NOTE: latency is per-sample detection time only. The Node-bridge figure for")
    print("  Privacy Lens excludes process startup; cross-tool latency is not directly")
    print("  comparable here — see the dedicated latency harness (Phase 12).")

    print(f"\n{'='*95}\n")

if __name__ == "__main__":
    main()
