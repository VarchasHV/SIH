// On-device secret / credential scanner (Phase 3).
//
// Detects credential material in page text, DOM fields, task goals and outbound
// payloads. Three signals, combined into a confidence:
//
//   1. STRUCTURE   — a known vendor prefix / format (AKIA…, ghp_…, eyJ….eyJ…., PEM).
//                    High confidence on its own.
//   2. ENTROPY     — Shannon entropy per char over a candidate token. High
//                    entropy alone is NOT flagged (UUIDs, hashes, minified JS).
//   3. CONTEXT     — a keyword ("api key", "secret", "token", "authorization")
//                    within ~40 chars, or a DOM field whose semantics say secret
//                    (type=password, name~=/token|secret|key/).
//
// Entropy + context => flagged. Entropy alone => low confidence (below the
// default 0.5 threshold) so a "show everything" caller still sees it.
//
// Evidence in every finding is MASKED (first 4 + last 4, middle elided). The
// raw secret is never returned, logged, or shown.

import { isCanary } from "./canary.mjs";

// ── masking ──────────────────────────────────────────────────────────────
export function maskSecret(s) {
  const v = String(s);
  if (v.length <= 8) return "*".repeat(v.length);
  return `${v.slice(0, 4)}…${"*".repeat(Math.min(6, v.length - 8))}…${v.slice(-4)}`;
}

// ── Shannon entropy (bits per character) ─────────────────────────────────
export function shannonEntropy(s) {
  if (!s) return 0;
  const freq = {};
  for (const ch of s) freq[ch] = (freq[ch] || 0) + 1;
  let h = 0;
  const n = s.length;
  for (const k in freq) {
    const p = freq[k] / n;
    h -= p * Math.log2(p);
  }
  return h;
}

// ── structured vendor patterns ──────────────────────────────────────────
// Each: { subtype, re, confidence, risk }. `re` is applied with the `g` flag.
const PATTERNS = [
  { subtype: "canary", re: /\bCANARY-(?:AWS|PII|TOKEN|SECRET)-[A-Za-z0-9]{4,}\b/g, confidence: 1.0, risk: 1.0 },

  { subtype: "aws_access_key_id", re: /\b(?:AKIA|ASIA|AROA|AIDA|ANPA|ANVA)[0-9A-Z]{16}\b/g, confidence: 0.97, risk: 0.99 },
  { subtype: "aws_secret_access_key", re: /\baws_secret_access_key\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/gi, confidence: 0.95, risk: 0.99 },
  { subtype: "gcp_api_key", re: /\bAIza[0-9A-Za-z_\-]{35}\b/g, confidence: 0.95, risk: 0.9 },
  { subtype: "gcp_service_account", re: /"type"\s*:\s*"service_account"/g, confidence: 0.85, risk: 0.95 },
  { subtype: "github_token", re: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b/g, confidence: 0.97, risk: 0.95 },
  { subtype: "github_pat", re: /\bgithub_pat_[A-Za-z0-9_]{82}\b/g, confidence: 0.97, risk: 0.95 },
  { subtype: "gitlab_pat", re: /\bglpat-[A-Za-z0-9_-]{20}\b/g, confidence: 0.95, risk: 0.9 },
  { subtype: "slack_token", re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, confidence: 0.95, risk: 0.9 },
  { subtype: "slack_webhook", re: /https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9_]+\/B[A-Za-z0-9_]+\/[A-Za-z0-9_]+/g, confidence: 0.95, risk: 0.85 },
  { subtype: "stripe_secret_key", re: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b/g, confidence: 0.97, risk: 0.97 },
  { subtype: "openai_key", re: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}\b/g, confidence: 0.97, risk: 0.9 },
  { subtype: "sendgrid_key", re: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g, confidence: 0.96, risk: 0.9 },
  { subtype: "twilio_key", re: /\bSK[0-9a-fA-F]{32}\b/g, confidence: 0.85, risk: 0.85 },
  { subtype: "npm_token", re: /\bnpm_[A-Za-z0-9]{36}\b/g, confidence: 0.95, risk: 0.85 },
  { subtype: "square_token", re: /\b(?:sq0atp|sq0csp|EAAA)[A-Za-z0-9\-_]{20,}\b/g, confidence: 0.9, risk: 0.85 },
  { subtype: "private_key_pem", re: /-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----/g, confidence: 0.99, risk: 1.0 },
  { subtype: "jwt", re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, confidence: 0.9, risk: 0.8 },
  { subtype: "db_connection_string", re: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^\s:@/]+:[^\s:@/]+@[^\s/]+/gi, confidence: 0.92, risk: 0.95 },
  { subtype: "authorization_header", re: /\bauthorization\s*[:=]\s*(?:Bearer|Basic|Token)\s+[A-Za-z0-9\-._~+/]{16,}=*/gi, confidence: 0.9, risk: 0.9 },
  { subtype: "bearer_token", re: /\bBearer\s+[A-Za-z0-9\-._~+/]{24,}=*/g, confidence: 0.6, risk: 0.8 },
  { subtype: "generic_api_key_kv", re: /\b(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret|secret[_-]?key|private[_-]?token)\s*[=:]\s*['"]?([A-Za-z0-9\-_./+=]{16,})['"]?/gi, confidence: 0.8, risk: 0.9 },
];

// ── context ─────────────────────────────────────────────────────────────
const SECRET_CONTEXT = /\b(api[_\s-]?key|secret|token|credential|password|passwd|bearer|authorization|auth[_\s-]?token|access[_\s-]?key|client[_\s-]?secret|private[_\s-]?key|session[_\s-]?id|sid|oauth|webhook|connection[_\s-]?string|dsn)\b/i;
const NEGATIVE_CONTEXT = /\b(example|sample|dummy|placeholder|your[_\s-]?key[_\s-]?here|xxx+|redacted|\bdocs?\b|tutorial)\b/i;

const ENTROPY_MIN = 3.6;          // bits/char — below this it's not a random secret
const ENTROPY_LEN_MIN = 20;

// candidate high-entropy tokens: long runs of base64-ish chars
const TOKEN_RE = /\b[A-Za-z0-9+/_=-]{20,120}\b/g;

/**
 * @param {string} text
 * @param {{ source?: string, fieldSecret?: boolean, minConfidence?: number }} [opts]
 *   fieldSecret: the DOM field this text came from is credential-typed
 *   (type=password or name/id ~ token|secret|key). Raises entropy-hit confidence.
 * @returns {Array<{type:'secret',subtype,confidence,risk,action,source,start,end,evidence,entropy?}>}
 */
export function scanSecrets(text, opts = {}) {
  if (!text || typeof text !== "string") return [];
  const source = opts.source || "text";
  const minConfidence = opts.minConfidence ?? 0.5;
  const out = [];
  const seen = new Set(); // dedupe by span

  const add = (f) => {
    const key = `${f.start}:${f.end}:${f.subtype}`;
    if (seen.has(key)) return;
    seen.add(key);
    f.action = f.confidence >= 0.85 ? "block" : f.confidence >= 0.6 ? "require_approval" : "flag";
    out.push(f);
  };

  // 1. structured patterns
  for (const p of PATTERNS) {
    p.re.lastIndex = 0;
    let m;
    while ((m = p.re.exec(text)) !== null) {
      if (m.index === p.re.lastIndex) p.re.lastIndex++;
      const raw = m[1] || m[0];
      const start = m[1] ? m.index + m[0].indexOf(m[1]) : m.index;
      const end = start + raw.length;
      const before = text.slice(Math.max(0, start - 40), start);
      let confidence = p.subtype === "canary" ? 1.0 : p.confidence;
      if (NEGATIVE_CONTEXT.test(before) && p.subtype !== "canary" && p.subtype !== "private_key_pem") {
        confidence = Math.min(confidence, 0.35);
      }
      add({
        type: "secret", subtype: p.subtype, confidence: +confidence.toFixed(2),
        risk: p.risk, source, start, end, evidence: maskSecret(raw),
      });
    }
  }

  // 2. entropy + context for anything the patterns missed
  TOKEN_RE.lastIndex = 0;
  let t;
  while ((t = TOKEN_RE.exec(text)) !== null) {
    const tok = t[0];
    if (tok.length < ENTROPY_LEN_MIN) continue;
    if (isCanary(tok)) continue; // handled above
    if (out.some((f) => t.index < f.end && f.start < t.index + tok.length)) continue; // covered
    const h = shannonEntropy(tok);
    if (h < ENTROPY_MIN) continue;
    // reject obvious non-secrets: pure hex (hash/uuid), pure digits, a URL path
    if (/^[0-9a-f]{32,}$/i.test(tok) || /^\d+$/.test(tok)) continue;
    const around = text.slice(Math.max(0, t.index - 40), t.index) + " " + text.slice(t.index + tok.length, t.index + tok.length + 20);
    const hasCtx = SECRET_CONTEXT.test(around) || opts.fieldSecret === true;
    if (NEGATIVE_CONTEXT.test(around)) continue;
    let confidence = hasCtx ? 0.7 : 0.3;
    if (hasCtx && h >= 4.2 && tok.length >= 32) confidence = 0.8;
    add({
      type: "secret", subtype: hasCtx ? "high_entropy_with_context" : "high_entropy",
      confidence: +confidence.toFixed(2), risk: hasCtx ? 0.85 : 0.4,
      source, start: t.index, end: t.index + tok.length, evidence: maskSecret(tok),
      entropy: +h.toFixed(2),
    });
  }

  return out.filter((f) => f.confidence >= minConfidence).sort((a, b) => a.start - b.start);
}

export default { scanSecrets, shannonEntropy, maskSecret };
