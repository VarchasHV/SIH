// Agent Action Firewall (Phases 6 + 13).
//
// Before an agent action executes, classify its risk and decide whether it may
// run, needs the user, or is blocked. Least privilege: the burden of proof is
// on the action, not the user.
//
//   classifyAction(action, ctx) -> {
//     risk: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
//     decision: "ALLOW" | "REQUIRE_APPROVAL" | "BLOCK",
//     reasons: string[],            // explainable, no raw values
//     exfil: null | { channel, categories }   // data-exfiltration finding
//   }
//
// action:  { action, targetId, literalValue?, piiCategory?, fillToken? }
// ctx:
//   targetNode      the resolved skeleton node (type/role/isCensored/text/href/
//                   formAction/formOrigin/formCrossOrigin/...)
//   resolvedValue   the actual string about to be typed (checked for PII/secret)
//   pageOrigin      location.origin of the page
//   pageMalicious   true if the page classified MALICIOUS (adversarial-guard)
//   destinationTrust in [0,1] for a navigate/download target (url-risk, S4)

import { detectPII } from "./pii-rules.mjs";
import { scanSecrets } from "./secret-scanner.mjs";
import { isRestrictedCategory } from "./sensitive-fields.mjs";

const EXECUTABLE_EXT = /\.(exe|scr|bat|cmd|com|msi|dll|ps1|vbs|js|jar|apk|dmg|pkg|app|deb|rpm|sh|run)(\?|#|$)/i;
const RISK_RANK = { LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 };
const worse = (a, b) => (RISK_RANK[a] >= RISK_RANK[b] ? a : b);

function valueSensitivity(value) {
  if (!value || typeof value !== "string") return { pii: [], secrets: [], restricted: false };
  const pii = [...new Set(detectPII(value).map((h) => h.category))];
  const secrets = [...new Set(scanSecrets(value, { minConfidence: 0.6 }).map((s) => s.subtype))];
  return { pii, secrets, restricted: pii.some(isRestrictedCategory) };
}

function urlSensitivity(url) {
  if (!url || typeof url !== "string") return { pii: [], secrets: [] };
  // check the whole URL — query strings are the classic PII-exfil channel
  const decoded = (() => { try { return decodeURIComponent(url); } catch { return url; } })();
  return {
    pii: [...new Set(detectPII(decoded).map((h) => h.category))],
    secrets: [...new Set(scanSecrets(decoded, { minConfidence: 0.6 }).map((s) => s.subtype))],
  };
}

const isOffOrigin = (url, pageOrigin) => {
  if (!url || !pageOrigin) return false;
  try { return new URL(url).origin !== pageOrigin; } catch { return false; }
};

const PAYMENT_RE = /\b(pay|payment|checkout|purchase|buy\s+now|place\s+order|donate|transfer|send\s+money|confirm\s+(?:payment|order))\b/i;
const DESTRUCTIVE_RE = /\b(delete|remove|close\s+account|deactivate|wipe|erase|permanently)\b/i;
const SECURITY_SETTINGS_RE = /\b(change\s+password|security\s+settings|2fa|two-factor|recovery\s+(?:email|phone)|api\s+key|disable\s+security|trusted\s+devices?)\b/i;

export function classifyAction(action, ctx = {}) {
  const a = action || {};
  const node = ctx.targetNode || {};
  const reasons = [];
  let risk = "LOW";
  let exfil = null;

  const bump = (r, why) => { risk = worse(risk, r); if (why) reasons.push(why); };

  const nodeText = (node.text || node.label || "").toString();
  const nodeSensitive = node.isCensored || isRestrictedCategory(node.piiCategory) || /password|otp|cvv|card|aadhaar|ssn|pan/i.test(nodeText + " " + (node.name || ""));

  switch (a.action) {
    case "wait":
    case "scroll":
    case "done":
      return { risk: "LOW", decision: "ALLOW", reasons: ["non-mutating action"], exfil: null };

    case "type":
    case "select": {
      const v = valueSensitivity(ctx.resolvedValue ?? a.literalValue);
      if (v.secrets.length) bump("HIGH", `typing credential material (${v.secrets.join(", ")})`);
      else if (v.restricted) bump("MEDIUM", `typing restricted PII (${v.pii.join(", ")})`);
      else if (v.pii.length) bump("MEDIUM", `typing personal data (${v.pii.join(", ")})`);
      else if (nodeSensitive) bump("MEDIUM", "filling a sensitive field");

      // exfiltration: sensitive value into a field whose form posts off-origin / low-trust
      if ((v.pii.length || v.secrets.length) && node.formCrossOrigin) {
        exfil = { channel: "cross_origin_form", categories: [...v.pii, ...v.secrets] };
        bump("CRITICAL", `sensitive value into a form that submits to ${safeHost(node.formOrigin)} (different site)`);
      }
      break;
    }

    case "submit": {
      bump("MEDIUM", "form submission");
      const formHasSecrets = /password|api[_-]?key|token|secret/i.test((node.name || "") + " " + nodeText);
      if (nodeSensitive || formHasSecrets) bump("HIGH", "submitting a form with credential / restricted fields");
      if (node.formCrossOrigin) {
        exfil = { channel: "cross_origin_form_submit", categories: ["form-data"] };
        bump("CRITICAL", `form submits to ${safeHost(node.formOrigin)} (a different site than the page)`);
      }
      if (PAYMENT_RE.test(nodeText)) bump("HIGH", "payment / money-movement control");
      break;
    }

    case "click": {
      // a click on a link is really a navigation or a download
      const href = node.href;
      if (href) {
        const off = isOffOrigin(href, ctx.pageOrigin);
        const us = urlSensitivity(href);
        if (node.downloadAttr || EXECUTABLE_EXT.test(href)) {
          bump("HIGH", "triggers a file download");
          if (EXECUTABLE_EXT.test(href)) bump("CRITICAL", `download is an executable (${extOf(href)})`);
          if (off && (ctx.destinationTrust ?? 1) < 0.6) bump("CRITICAL", `executable from a low-trust host ${safeHost(href)}`);
        } else if (off) {
          bump("MEDIUM", `navigates to another site (${safeHost(href)})`);
        }
        if (us.pii.length || us.secrets.length) {
          exfil = { channel: "url", categories: [...us.pii, ...us.secrets] };
          bump("CRITICAL", `the link URL carries ${[...us.pii, ...us.secrets].join(", ")} to ${safeHost(href)}`);
        }
      }
      if (PAYMENT_RE.test(nodeText)) bump("HIGH", "payment / money-movement control");
      if (DESTRUCTIVE_RE.test(nodeText)) bump("HIGH", "destructive action (delete / deactivate)");
      if (SECURITY_SETTINGS_RE.test(nodeText)) bump("HIGH", "changes a security / account setting");
      if (node.isSubmit && nodeSensitive) bump("HIGH", "submit button on a sensitive form");
      break;
    }

    // primitives the executor doesn't expose today — classified defensively
    case "navigate":
    case "open_tab": {
      const us = urlSensitivity(a.literalValue || a.targetId);
      bump("MEDIUM", "navigation");
      if (isOffOrigin(a.literalValue, ctx.pageOrigin)) bump("HIGH", "navigates off-site");
      if (us.pii.length || us.secrets.length) { exfil = { channel: "navigate_url", categories: [...us.pii, ...us.secrets] }; bump("CRITICAL", "navigation URL carries sensitive data"); }
      break;
    }
    case "download": bump("HIGH", "file download"); if (EXECUTABLE_EXT.test(a.literalValue || "")) bump("CRITICAL", "executable download"); break;
    case "upload": bump("HIGH", "file upload"); break;
    case "copy": case "paste": bump("HIGH", "clipboard access"); break;
    case "execute_script": bump("CRITICAL", "arbitrary script execution"); break;

    default:
      bump("MEDIUM", `unrecognised action "${a.action}"`);
  }

  // a MALICIOUS page turns any mutating action into at least an approval
  if (ctx.pageMalicious && ["type", "select", "submit", "click", "navigate", "download", "upload"].includes(a.action)) {
    bump("HIGH", "the page contains prompt-injection content trying to steer the agent");
  }

  const decision =
    risk === "CRITICAL" ? "BLOCK"
    : risk === "HIGH" ? "REQUIRE_APPROVAL"
    : risk === "MEDIUM" && ["submit", "upload", "download"].includes(a.action) ? "REQUIRE_APPROVAL"
    : "ALLOW";

  return { risk, decision, reasons, exfil };
}

function safeHost(u) { try { return new URL(u).host; } catch { return String(u || "").slice(0, 40); } }
function extOf(u) { const m = String(u).match(EXECUTABLE_EXT); return m ? m[1] : "?"; }

export default { classifyAction };
