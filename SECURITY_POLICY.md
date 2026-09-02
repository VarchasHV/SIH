# SECURITY_POLICY.md

The rules the security layer enforces. Two independent decision points:

1. **Egress policy** — everything leaving the browser (`SecurityPolicyEngine`,
   `client/lib/security-policy.mjs`).
2. **Action firewall** — every agent action before it touches the page
   (`client/lib/action-firewall.mjs`).

Both are **explainable** (reasons are returned) and **fail closed** on the
privacy-critical path. Neither ever emits, logs, or displays a raw sensitive value.

---

## 1. Egress policy — `classifyPayload(payload, ctx)`

### Signals

| Signal | Source |
|---|---|
| Structural PII (span-level, context-gated) | `pii-rules.mjs` `detectPII` |
| Secrets / credentials (pattern + entropy + context) | `secret-scanner.mjs` `scanSecrets` |
| Canary / honeytoken tokens | `canary.mjs` `findCanaries` |
| The user's own profile values (exact match) | `ctx.profile` |
| Page prompt-injection verdict | `ctx.pageThreats` (from `adversarial-guard.classifyContent`) |
| Destination trust `[0,1]` | `ctx.destinationTrust` (localhost = 1; else 0.6; url-risk in S4) |

### Data classification (most-severe wins)

`PUBLIC` → `INTERNAL` → `PERSONAL` → `SENSITIVE` → `SECRET`

- **SECRET**: any secret finding, canary, or a RESTRICTED profile value.
- **SENSITIVE**: RESTRICTED structural PII (password, aadhaar, PAN, card, SSN, CVV, bank, IFSC), or a MALICIOUS page.
- **PERSONAL**: email, phone, DOB, name, address.
- **INTERNAL**: other structural PII.
- **PUBLIC**: nothing.

### Decision

| Condition (checked top-down) | Decision |
|---|---|
| canary token in payload | **BLOCK** |
| secret finding with `action: "block"` (confidence ≥ 0.85) | **BLOCK** |
| RESTRICTED PII category | **BLOCK** |
| page graded MALICIOUS (agent-directed instructions) | **REQUIRE_APPROVAL** |
| secret finding with `action: "require_approval"` (0.6–0.85) | **REQUIRE_APPROVAL** |
| PERSONAL+ data **and** `destinationTrust < 0.5` | **REQUIRE_APPROVAL** |
| any other PII / profile-value match | **SANITIZE** (redact in place, send) |
| nothing | **ALLOW** |

`BLOCK` → the step stops, nothing is sent. `REQUIRE_APPROVAL` → structured
approval gate (categories only). `SANITIZE` → the redacted copy is sent and the
redaction is logged as metadata.

---

## 2. Action firewall — `classifyAction(action, ctx)`

### Risk levels

| Risk | Meaning | Autonomous? |
|---|---|---|
| **LOW** | non-mutating or trivial (scroll, wait, done, click "Next", type a plain value) | yes |
| **MEDIUM** | form submission, filling a sensitive field, off-site navigation, typing personal data | yes, **except** submit / upload / download → approval |
| **HIGH** | credential-form submit, payment / destructive / security-settings control, file upload/download, typing a secret | **no** — REQUIRE_APPROVAL |
| **CRITICAL** | sensitive value → cross-origin form; PII/secret in a navigation URL; executable download from a low-trust host; arbitrary script | **no** — BLOCK |

### Escalation rules

- A page graded **MALICIOUS** escalates every mutating action to at least HIGH
  (the page is actively trying to steer the agent).
- A **data-exfiltration** finding (`exfil` in the result) is always CRITICAL:
  - `type`/`select` of PII/secret into a form whose `action` is a different origin
  - `submit` of a form that posts to a different origin than the page
  - `click` of a link whose URL carries PII/secret
  - `navigate` to a URL carrying PII/secret

### Decision

`CRITICAL` → **BLOCK** (+ stop the run if it was an exfil attempt).
`HIGH` → **REQUIRE_APPROVAL**.
`MEDIUM` + (submit | upload | download) → **REQUIRE_APPROVAL**.
otherwise → **ALLOW**.

---

## 3. Human approval gate

Shown for every `REQUIRE_APPROVAL`. Contents:

```
⚠️ SECURITY APPROVAL REQUIRED
<what the agent wants to do — a short phrase, no values>
Risk: <LEVEL / classification>
Destination: <host>            (when applicable)
Detected: <category names>     (e.g. "aadhaar, credit-card" — never the numbers)
<one line per reason>
[ Approve ]  [ Block ]
```

Auto-**deny** after 90 s if the popup is closed. The raw value is never in the
DOM of the gate.

---

## 4. Configuration

Today the policy is fixed (privacy-first defaults). `chrome.storage.local` keys
that influence it:

| Key | Effect |
|---|---|
| `allowInsecureHttp` | suppress the `INSECURE_TLS_WARNING` for `http://` relays |
| `confirmBeforeSubmit` | extra manual gate on `submit` even when the firewall says ALLOW |
| `confirmEachSend` | manual gate on every `/agent/step` call |

A future `securityProfile` ("strict" / "balanced" / "permissive") would tune the
thresholds — not implemented; the current behaviour is "strict".

---

## 5. What the policy does NOT do

See `SECURITY_LIMITATIONS.md`. In short: it governs the **agent's** perception
and actions and the **agent's** one network egress. It cannot see or gate the
page's own `fetch`/XHR/WebSocket traffic, downloads the page triggers, the
clipboard, or other extensions.
