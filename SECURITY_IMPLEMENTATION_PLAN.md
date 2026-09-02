# Security Implementation Plan

**Base commit `e920f14` · branch `working`**

Per the execution rules: audit → existing architecture → duplication → gaps →
plan → incremental build. The audit is `AUDIT.md`; the threat model is
`SECURITY_THREAT_MODEL.md`. This file is step 5 (the plan).

---

## A. What already exists (do not rewrite)

| Capability | Lives in | State |
|---|---|---|
| PII detection (span-level, context-gated, Unicode-normalised) | `client/lib/pii-rules.mjs` | **solid** — F1 91% measured, sole detector |
| Prompt-injection detection | `client/lib/adversarial-guard.mjs` (+ `.js` for content script) | **partial** — patterns + leetspeak + zero-width + hidden-style + attribute scan; tested |
| Egress PII gate | `client/lib/egress-guard.mjs` (`assertNoSensitivePayload`) | **new this cycle** — profile match + structural detect, block/redact, metadata-only findings |
| Detection fusion + per-item privacy risk | `client/lib/merge.mjs` | **new this cycle** — base risk + corroboration + conflict de-rating, `{privacyRisk, redact, reason}` |
| Screenshot redaction | `client/lib/redact.mjs` (pixel), `client/dom-redactor.js` (DOM text) | works; `leakScore` is weak |
| Redaction leakage benchmark (vs ground truth) | `eval/bench/redaction.mjs` | **new this cycle** — measures leakage/IoU/over-redaction |
| DLP field classifier + paragraph/goal sanitiser | `client/lib/dlp-heuristics.mjs`, `dlp-sanitizer.mjs`, `dlp-content-script.js` | works; goal sanitiser hardened this cycle |
| Sensitive-category taxonomy | `client/lib/sensitive-fields.mjs` (`RESTRICTED_PII_CATEGORIES`, `PROFILE_PII_CATEGORIES`) | works — reuse everywhere |
| TLS / insecure-origin warning | `client/agent-bridge.js` (`INSECURE_TLS_WARNING`) | basic |
| Credential-field isolation (force-censor password inputs) | `client/agent-bridge.js` | works |
| VLM-response validation (actions must target known ids) | `client/lib/agent-client.mjs` (`validatePlan`) | works |
| Human gate (send / submit) | `client/background.js` (`waitForGate`) + `client/popup.js` (`#gate`) | basic — no risk explanation |
| DPDP compliance audit report | `client/lib/dpdp-audit.mjs` | works |
| Security alerts channel | `securityAlerts[]` in `agent-bridge.js` → `background.js` → popup | ad-hoc, not structured |
| Adversarial test page | `fixtures/adversarial-attack.html` | 1 page — seed for `security-lab/` |

**The one network egress:** `client/lib/agent-client.mjs` `fetch('/agent/step')`.
Plus `popup.js` `fetch('/health')`. No WebSocket / XHR / beacon / `webRequest`.
This is the choke point — the policy engine goes here.

---

## B. Gaps (the 25 phases mapped)

| # | Phase | Status | Where it goes | Notes |
|---|---|---|---|---|
| 1 | Threat model | ✅ done | `SECURITY_THREAT_MODEL.md` | — |
| 2 | PII exfiltration firewall / `SecurityPolicyEngine` | **extend** | `client/lib/security-policy.mjs` (new) wrapping `egress-guard` + new engines; called from `background.js` step 5b and `executor.js` | generalise the egress gate into ALLOW/SANITIZE/BLOCK/REQUIRE_APPROVAL |
| 3 | Secret scanner | **new** | `client/lib/secret-scanner.mjs` | patterns + entropy + context + confidence; feeds the policy engine |
| 4 | `PromptInjectionDetector` (SAFE/SUSPICIOUS/MALICIOUS) | **extend** | `client/lib/adversarial-guard.mjs` — add a `classifyContent()` wrapper returning the graded verdict + indicators + affected element + recommended action; add comment/`<meta>` scan |
| 5 | Indirect-injection adversarial pages | **new** | `security-lab/*.html` | 12 pages incl. comment/meta/alt/aria variants |
| 6 | Agent action firewall (LOW/MED/HIGH/CRITICAL) | **new** | `client/lib/action-firewall.mjs`; called in `background.js` before `send(PL_EXECUTE)` | classify each action by resolved control semantics + argument content + destination |
| 7 | Human approval gate w/ explanation | **extend** | `background.js` `waitForGate` + `popup.js` `#gate` — add a `kind:"approval"` with a structured reason block (categories, not values) | |
| 8 | Malicious URL / phishing engine | **new** | `client/lib/url-risk.mjs`; called in `agent-bridge.js prepare()` + `action-firewall` for `navigate` | homograph / punycode / IP-URL / TLD / lookalike / login-form-on-unrelated-domain; **heuristics only, no reputation feed** |
| 9 | Form security (what vs whom) | **new** | `client/lib/form-analyzer.mjs`; `agent-bridge.js prepare()` reads `<form action>` + field categories | sensitive fields + off-origin/suspicious action → policy |
| 10 | Sensitive-document detection + 2nd pass | **extend** | `client/lib/vision-pipeline.mjs` — add doc-type heuristics (Aadhaar/passport/card layout via OCR keywords + aspect), QR/barcode note; **re-run OCR/detect on the redacted canvas** |
| 11 | Redaction verification hard gate | **new** | `client/lib/redaction-verify.mjs`; `vision-pipeline.mjs` after `redactCanvas` → if residual PII, `REDACTION_FAILED` → `background.js` blocks egress | |
| 12 | Network egress monitor / policy layer | **extend** | `security-policy.mjs` classifies every payload PUBLIC/INTERNAL/PERSONAL/SENSITIVE/SECRET; `agent-client.mjs` refuses to `fetch` an unclassified payload | |
| 13 | Data-exfiltration detection | **new** | part of `action-firewall.mjs` + `security-policy.mjs` — PII/secret pattern in a `navigate` URL / action arg / off-origin form → CRITICAL | |
| 14 | `PrivacyRiskEngine` (0–100, explainable) | **new** | `client/lib/risk-engine.mjs` — combines PII conf, secret conf, destination trust, injection score, action severity, data sensitivity → score + reasons + decision | the fusion brain |
| 15 | Security event log (metadata only) | **new** | `client/lib/security-events.mjs` (ring buffer in memory + `chrome.storage.session`); emitted to popup | structured events, no raw values |
| 16 | Canary / honeytoken mode | **new** | `client/lib/canary.mjs` + `security-lab/canary/*.html`; a test flag that seeds `CANARY-*` tokens and asserts they never egress | |
| 17 | `security-lab/` (12 pages) + benchmark | **new** | `security-lab/` + `eval/security/run.mjs` | detection / FP / blocked / leaked / latency |
| 18 | Security regression suite | **extend** | `tests/security-*.test.mjs` | IPv4/Aadhaar (done), egress block, redaction, injection-not-trusted, canary-not-egressed, form-to-suspicious-domain |
| 19 | Attack-success-rate metric | **new** | `eval/security/attack-suite.mjs` — per lab page: did injection influence? did data leave? did a dangerous action fire? → *tested* prevention rate | |
| 20 | Security dashboard | **extend** | `popup.html` / `popup.js` — a Security panel driven by `security-events` + `risk-engine` | |
| 21 | Performance harness (security overhead) | **extend** | `eval/security/latency.mjs` — reuse `benchEnv`; measure each engine + total security overhead; p50/p95/p99 | detector-only measurable headless; OCR/vision NOT MEASURED |
| 22 | Benchmark fairness | ✅ pattern set | reuse `eval/bench/competitors/` + NOT_EXECUTED convention | |
| 23 | Final architecture wiring | **extend** | `background.js` orchestrates: sensors → engines → risk-engine → policy → (VLM \| block) → action-firewall → (execute \| approval) | |
| 24 | Docs | **new** | `SECURITY_ARCHITECTURE.md`, `SECURITY_BENCHMARK.md`, `SECURITY_LAB.md`, `SECURITY_POLICY.md`, `SECURITY_LIMITATIONS.md`, `SIH_SECURITY_SCORECARD.md` | limitations mandatory |
| 25 | Positioning | **doc** | README + scorecard framing | "browser security gateway for AI agents" |

---

## C. New module layout

```
client/lib/
  security-policy.mjs      # the SecurityPolicyEngine — ALLOW/SANITIZE/BLOCK/REQUIRE_APPROVAL
  secret-scanner.mjs       # Phase 3
  url-risk.mjs             # Phase 8   (heuristics only)
  form-analyzer.mjs        # Phase 9
  action-firewall.mjs      # Phase 6 + 13
  risk-engine.mjs          # Phase 14  (0–100, reasons, decision)
  redaction-verify.mjs     # Phase 11
  security-events.mjs      # Phase 15  (metadata-only ring buffer)
  canary.mjs               # Phase 16
  (extend) adversarial-guard.mjs   # Phase 4 classifyContent()
  (extend) vision-pipeline.mjs     # Phase 10 doc-type + Phase 11 re-verify
  (reuse)  pii-rules.mjs, sensitive-fields.mjs, egress-guard.mjs, merge.mjs

security-lab/              # Phase 17 — 12 adversarial pages + a manifest of expected outcomes
eval/security/            # Phase 17/19/21 — run.mjs, attack-suite.mjs, latency.mjs
tests/security-*.test.mjs # Phase 18
```

Data-flow contract for every engine: `detect(input) -> [{ type, subtype,
confidence, source, risk, action, evidence /* redacted */ }]`. The risk engine
consumes these; the policy engine acts on the risk engine's decision.

---

## D. Build order (batches, same cadence as before)

- **S1 — Secret scanner + Policy Engine core.** `secret-scanner.mjs`,
  `security-policy.mjs` (wraps `egress-guard` + `pii-rules` + `secret-scanner`
  into one ALLOW/SANITIZE/BLOCK/REQUIRE_APPROVAL decision), wire into
  `background.js`. Canary mode (`canary.mjs`) + a canary test page. Tests.
- **S2 — Prompt-injection grading + indirect-injection lab.** `classifyContent()`
  in `adversarial-guard.mjs` (SAFE/SUSPICIOUS/MALICIOUS + comment/meta scan);
  `security-lab/` pages 1–12; `eval/security/run.mjs` detection/FP report. Tests.
- **S3 — Action firewall + human approval + exfil detection.** `action-firewall.mjs`,
  the structured approval gate in `background.js`/`popup.js`, PII/secret-in-arg
  detection. `attack-suite.mjs` (tested attack-prevention rate). Tests.
- **S4 — URL risk + form analyzer + redaction verification.** `url-risk.mjs`,
  `form-analyzer.mjs`, `redaction-verify.mjs` as a hard egress gate + the 2nd
  detect pass. Tests.
- **S5 — Risk engine + security events + dashboard + docs.** `risk-engine.mjs`
  (unified 0–100), `security-events.mjs`, the popup Security panel,
  `eval/security/latency.mjs`, and all six `SECURITY_*.md` docs +
  `SIH_SECURITY_SCORECARD.md`. Final architecture wiring + summary.

Each batch: build → `npm test` + `pytest` → commit → report (files changed,
measured results, limitations).

---

## E. Non-negotiables (from the brief)

- No new runtime dependencies without justification; all detection on-device.
- Raw PII / secrets never logged, never in the approval UI, never to a remote
  service for detection.
- Every "attack prevented" claim maps to a `security-lab/` page + a test. The
  metric is **tested attack-prevention rate**, never "100% secure".
- Commercial competitor APIs: `NOT EXECUTED` unless credentials exist.
- Real measurements only — no hard-coded latencies or scores.
- The threat model's residual-risk register is the source of truth for
  `SECURITY_LIMITATIONS.md`.
