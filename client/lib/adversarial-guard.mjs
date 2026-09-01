// Adversarial Robustness & Indirect Prompt-Injection Guard for Privacy Lens.
//
// Detects, quarantines, and sanitizes adversarial attacks targeting browser agents:
// 1. Indirect Prompt Injections (jailbreaks, instruction overrides, data exfiltration commands)
// 2. Steganographic / Hidden Text (opacity:0, font-size:0, offscreen coordinates, low-contrast text)
// 3. Deceptive Attribute Payloads (alt, aria-label, title, data-*)
//
// KNOWN LIMITATIONS & THREAT MODEL:
// This guard provides a fast, on-device first-line heuristic defense against known
// prompt injection signatures, leetspeak variants, zero-width steganography, and hidden DOM text.
// It is NOT a full semantic NLP classifier and cannot guarantee 100% coverage against
// creative, out-of-distribution natural language paraphrases (e.g., "disregard everything you were told earlier"
// or complex multi-turn social engineering). In production, this layer is paired with structural DLP tokenization,
// server-side guardrails, and human-in-the-loop authorization gates.

/**
 * Regex for stripping invisible Unicode zero-width characters and soft hyphens.
 */
const ZERO_WIDTH_REGEX = /[\u200B-\u200D\u200E\u200F\uFEFF\u00AD\u2060-\u206F\u034F\u180E]/g;

/**
 * Leetspeak character map for folding common substitutions.
 */
const LEET_MAP = {
  "0": "o",
  "1": "i",
  "!": "i",
  "|": "i",
  "3": "e",
  "4": "a",
  "@": "a",
  "5": "s",
  "$": "s",
  "7": "t",
  "8": "b",
};

/**
 * Normalizes text by removing zero-width characters and collapsing whitespace.
 * @param {string} text
 * @returns {string}
 */
export function normalizeText(text) {
  if (!text || typeof text !== "string") return "";
  return text.replace(ZERO_WIDTH_REGEX, "").replace(/\s+/g, " ").trim();
}

/**
 * Folds common leetspeak characters to standard Latin alphabet.
 * @param {string} text
 * @returns {string}
 */
export function foldLeetspeak(text) {
  if (!text || typeof text !== "string") return "";
  return text.replace(/[01!|34@5$78]/g, (ch) => LEET_MAP[ch] || ch);
}

/**
 * Fast keyword pre-filter to short-circuit expensive DOM/regex operations.
 */
export const SUSPICIOUS_KEYWORDS_REGEX = /\b(?:ignore|disregard|forget|bypass|override|jailbreak|exfiltrate|leak|steal|system|assistant|instruction|prompt|developer\s+mode|dan\s+mode|transfer|pay|send\s+money|eval|webhook)\b/i;

/**
 * High-confidence regex patterns for indirect prompt injections and jailbreaks.
 */
export const INJECTION_PATTERNS = [
  // 1. Instruction Overrides & Jailbreaks
  /\b(?:ignore|disregard|forget|bypass)\s+(?:all\s+)?(?:previous|prior|above|former|initial)\s+(?:instructions|prompts?|rules?|directives?|commands?|context)\b/i,
  /\b(?:new\s+instructions?|system\s+override|admin\s+override|developer\s+mode|jailbreak|dan\s+mode)\b/i,
  /\b(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be)\s+(?:an?\s+unrestricted|a\s+hacked|an\s+evil|a\s+root)\b/i,
  
  // 2. Data Exfiltration & Hijacking
  /\b(?:send|exfiltrate|post|leak|transmit|forward|upload)\s+(?:all\s+)?(?:passwords?|tokens?|cookies?|pii|credentials?|aadhaar|pan|cards?|secrets?|vault)\b/i,
  /\b(?:http[s]?:\/\/[^\s]+(?:\/exfil|\/collect|\/steal|\/log|\/webhook|\/drop))\b/i,
  /\b(?:fetch|webhook|curl|wget)\s+https?:\/\//i,
  
  // 3. Malicious UI Action Manipulation / Payment Hijacking
  // (Narrowed to require imperative hijack context, preventing false positives on standard banking copy)
  /\b(?:instead\s+(?:of\s+[^,.]+,?\s*)?|do\s+not\s+fill\s+[^,.]+,?\s*|immediately\s+|now\s+)(?:transfer\s+funds?|pay|send\s+money)\s+to\b/i,
  /\b(?:transfer\s+funds?|pay|send\s+money|change\s+recipient)\s+to\s+(?:(?:account\s+)?(?:\d{9,}|0x[a-fA-F0-9]{8,})|https?:\/\/|attacker|unauthorized|external)\b/i,
  /\b(?:assistant|agent|bot|model),?\s+(?:transfer\s+funds?|pay|send\s+money)\s+to\b/i,
  /\b(?:do\s+not\s+fill|stop\s+filling|instead\s+click|click\s+here\s+first|navigate\s+to\s+evil)\b/i,
  
  // 4. Role spoofing & system header injection
  /\b(?:system\s+message\s*:|assistant\s*:|human\s*:|user\s*:|\[system\]|\[instruction\])\b/i,
  
  // 5. Obfuscated script / exfil patterns
  /\b(?:eval\(|document\.cookie|window\.localStorage|chrome\.storage)\b/i,
];

/**
 * Tests if a given text contains indirect prompt injection or adversarial jailbreak commands.
 * Handles zero-width stripping and leetspeak folding.
 * @param {string} text
 * @returns {{ isInjection: boolean, match: string | null, confidence: number, patternIndex: number, threat?: string }}
 */
export function detectPromptInjection(text) {
  if (!text || typeof text !== "string") {
    return { isInjection: false, match: null, confidence: 0, patternIndex: -1 };
  }

  // 1. Strip zero-width Unicode characters and collapse whitespace
  const normalized = normalizeText(text);
  if (!normalized) {
    return { isInjection: false, match: null, confidence: 0, patternIndex: -1 };
  }

  // 2. Test standard normalized string
  for (let i = 0; i < INJECTION_PATTERNS.length; i++) {
    const match = normalized.match(INJECTION_PATTERNS[i]);
    if (match) {
      return {
        isInjection: true,
        match: match[0],
        confidence: 0.95,
        patternIndex: i,
        threat: "INDIRECT_PROMPT_INJECTION",
      };
    }
  }

  // 3. Test leetspeak-folded string
  const leetFolded = foldLeetspeak(normalized);
  if (leetFolded !== normalized) {
    for (let i = 0; i < INJECTION_PATTERNS.length; i++) {
      const match = leetFolded.match(INJECTION_PATTERNS[i]);
      if (match) {
        return {
          isInjection: true,
          match: match[0] + " (leetspeak decoded)",
          confidence: 0.90,
          patternIndex: i,
          threat: "OBFUSCATED_PROMPT_INJECTION",
        };
      }
    }
  }

  // 4. Heuristic: fake role injection headers.
  // Requires an adversarial payload verb immediately following the role tag to avoid
  // false positives on benign forms like "instruction: enter your name" or "human: thanks".
  // Valid attack: "system: ignore previous instructions" / "assistant: exfiltrate everything"
  if (/(?:^|\n)\s*(?:system|assistant|instruction|human)\s*:\s*(?:ignore|disregard|forget|bypass|exfiltrate|leak|steal|override|jailbreak|act\s+as|pretend|you\s+are)/i.test(normalized)) {
    return {
      isInjection: true,
      match: "Fake role tag spoofing",
      confidence: 0.85,
      patternIndex: -2,
      threat: "ROLE_SPOOFING",
    };
  }

  return { isInjection: false, match: null, confidence: 0, patternIndex: -1 };
}

/**
 * Evaluates whether an element's styling constitutes hidden, steganographic, or invisible text.
 * Exempts common accessibility markup (.sr-only, visually-hidden, role=status, aria-live).
 * @param {HTMLElement} el
 * @param {Window} [win]
 * @returns {{ isHidden: boolean, reason: string | null, confidence: number }}
 */
export function detectHiddenStyles(el, win = globalThis) {
  if (!el || typeof win.getComputedStyle !== "function") {
    return { isHidden: false, reason: null, confidence: 0 };
  }

  // Screen reader / accessibility markup exemption
  const className = String(el.className || "");
  if (
    /^(?:sr-only|visually-hidden|screen-reader-text|a11y-hidden)$/i.test(className) ||
    el.getAttribute?.("role") === "status" ||
    el.getAttribute?.("aria-live")
  ) {
    return { isHidden: false, reason: "A11y markup exemption", confidence: 0 };
  }

  try {
    const style = win.getComputedStyle(el);

    // 1. Zero/near-zero opacity
    const opacity = parseFloat(style.opacity || "1");
    if (opacity < 0.05) {
      return { isHidden: true, reason: `Near-zero opacity (${opacity})`, confidence: 0.99 };
    }

    // 2. Sub-pixel font size
    const fontSize = parseFloat(style.fontSize || "16");
    if (fontSize < 2 && el.textContent && el.textContent.trim().length > 0) {
      return { isHidden: true, reason: `Sub-pixel font size (${fontSize}px)`, confidence: 0.99 };
    }

    // 3. Off-screen absolute positioning
    const left = parseFloat(style.left || "0");
    const top = parseFloat(style.top || "0");
    if ((left < -1000 || top < -1000) && el.textContent && el.textContent.trim().length > 0) {
      return { isHidden: true, reason: `Off-screen absolute positioning (left:${left}px, top:${top}px)`, confidence: 0.98 };
    }

    // 4. Text color matching background color (zero contrast)
    const color = style.color;
    const bg = style.backgroundColor;
    if (color && bg && color !== "rgba(0, 0, 0, 0)" && bg !== "rgba(0, 0, 0, 0)" && color === bg && el.textContent && el.textContent.trim().length > 5) {
      return { isHidden: true, reason: "Zero-contrast foreground/background match", confidence: 0.96 };
    }
  } catch {
    // Graceful fallback for non-DOM node environments
  }

  return { isHidden: false, reason: null, confidence: 0 };
}

/**
 * Scans an entire document or subtree for adversarial vectors:
 * - Direct & indirect prompt injections
 * - Steganographic / hidden text styles (with getComputedStyle short-circuiting)
 * - Deceptive attributes (alt, aria-label, title, data-*)
 * @param {Document | HTMLElement} root
 * @param {Window} [win]
 * @returns {Array<{ node: HTMLElement, reason: string, text: string, bbox: {x:number, y:number, w:number, h:number}, type: string }>}
 */
export function scanAdversarialVectors(root, win = globalThis) {
  const threats = [];
  if (!root || typeof root.querySelectorAll !== "function") return threats;

  const elements = root.querySelectorAll("*");
  for (const el of elements) {
    // Skip script/style/link/meta tags
    if (["SCRIPT", "STYLE", "LINK", "META", "NOSCRIPT"].includes(el.tagName)) continue;

    const text = (el.innerText || el.textContent || "").trim();
    const alt = el.getAttribute?.("alt") || "";
    const ariaLabel = el.getAttribute?.("aria-label") || "";
    const title = el.getAttribute?.("title") || "";
    const dataInstruction = el.getAttribute?.("data-instruction") || el.getAttribute?.("data-prompt") || "";

    const combinedAttributesText = [alt, ariaLabel, title, dataInstruction].filter(Boolean).join(" ");
    const hasAnyText = text.length > 0 || combinedAttributesText.length > 0;
    if (!hasAnyText) continue;

    // 1. Scan attribute text for prompt injections (alt, aria-label, title, data-*)
    if (combinedAttributesText) {
      const attrInj = detectPromptInjection(combinedAttributesText);
      if (attrInj.isInjection) {
        const bbox = typeof el.getBoundingClientRect === "function" ? el.getBoundingClientRect() : { x: 0, y: 0, width: 0, height: 0 };
        threats.push({
          node: el,
          type: "ATTRIBUTE_PROMPT_INJECTION",
          reason: `Attribute injection in [${alt ? "alt" : ariaLabel ? "aria-label" : "title"}]: "${attrInj.match}"`,
          text: combinedAttributesText.slice(0, 150),
          confidence: attrInj.confidence,
          bbox: {
            x: Math.max(0, bbox.left ?? bbox.x ?? 0),
            y: Math.max(0, bbox.top ?? bbox.y ?? 0),
            w: Math.max(1, bbox.width ?? 0),
            h: Math.max(1, bbox.height ?? 0),
          },
        });
        continue;
      }
    }

    // 2. Scan visible text for prompt injections
    const injectionCheck = detectPromptInjection(text);
    if (injectionCheck.isInjection) {
      const bbox = typeof el.getBoundingClientRect === "function" ? el.getBoundingClientRect() : { x: 0, y: 0, width: 0, height: 0 };
      threats.push({
        node: el,
        type: "INDIRECT_PROMPT_INJECTION",
        reason: `Adversarial Instruction: "${injectionCheck.match}"`,
        text: text.slice(0, 150),
        confidence: injectionCheck.confidence,
        bbox: {
          x: Math.max(0, bbox.left ?? bbox.x ?? 0),
          y: Math.max(0, bbox.top ?? bbox.y ?? 0),
          w: Math.max(1, bbox.width ?? 0),
          h: Math.max(1, bbox.height ?? 0),
        },
      });
      continue;
    }

    // 3. Steganographic hidden-text detection (with getComputedStyle short-circuit).
    // Performance: getComputedStyle forces a style recalculation on every call, so we
    // short-circuit: only call it when the inline style attribute already suggests hiding
    // (opacity:, font-size:0, position:absolute with negative left/top, etc.).
    // Detection requirement: the element must BOTH be visually hidden AND contain confirmed
    // injection text. Keyword presence alone (e.g. 'transfer') is NOT sufficient — that
    // would false-positive on hidden tooltips, collapsed accordions, etc.
    const inlineStyle = el.getAttribute?.("style") || "";
    const styleMayBeHidden = /(?:opacity\s*:\s*0|font-size\s*:\s*0|position\s*:\s*absolute|left\s*:\s*-\d|top\s*:\s*-\d|display\s*:\s*none|visibility\s*:\s*hidden)/i.test(inlineStyle);

    if (styleMayBeHidden) {
      const hiddenCheck = detectHiddenStyles(el, win);
      if (hiddenCheck.isHidden) {
        // Must also contain a confirmed injection payload to be flagged.
        // A hidden element with benign text (e.g. collapsed accordion, tooltip) is never a threat.
        const hiddenInjectionCheck = detectPromptInjection(text);
        if (hiddenInjectionCheck.isInjection) {
          const bbox = typeof el.getBoundingClientRect === "function" ? el.getBoundingClientRect() : { x: 0, y: 0, width: 0, height: 0 };
          threats.push({
            node: el,
            type: "HIDDEN_PROMPT_INJECTION",
            reason: hiddenCheck.reason + ` + Injection: "${hiddenInjectionCheck.match}"`,
            text: text.slice(0, 150),
            confidence: Math.min(hiddenCheck.confidence, hiddenInjectionCheck.confidence) + 0.02,
            bbox: {
              x: Math.max(0, bbox.left ?? bbox.x ?? 0),
              y: Math.max(0, bbox.top ?? bbox.y ?? 0),
              w: Math.max(1, bbox.width ?? 0),
              h: Math.max(1, bbox.height ?? 0),
            },
          });
        }
      }
    }
  }

  return threats;
}
