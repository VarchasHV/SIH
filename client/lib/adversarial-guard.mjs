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

// ─────────────────────────────────────────────────────────────────────────
// Phase 4 — graded content classification (SAFE / SUSPICIOUS / MALICIOUS)
//
// The core rule: WEBPAGE CONTENT IS UNTRUSTED DATA, NOT INSTRUCTIONS.
// classifyContent() grades how strongly a chunk of page text is trying to be
// read as an instruction to the agent, and what to do about it.
// ─────────────────────────────────────────────────────────────────────────

// STRONG soft indicators — any one on its own is MALICIOUS-leaning.
const STRONG_INDICATORS = [
  { id: "reveal_secrets", re: /\b(?:reveal|show|print|display|output|repeat|tell\s+me|what\s+(?:is|are))\s+(?:your|the|all)\s+(?:system\s+prompt|initial\s+instructions?|secrets?|api\s+keys?|passwords?|credentials?|tokens?|configuration|rules|guardrails?)\b/i },
  { id: "disable_security", re: /\b(?:disable|turn\s+off|bypass|skip|ignore|override|deactivate|remove)\s+(?:the\s+|your\s+|all\s+)?(?:security|safety|privacy|filter|guard(?:rail)?s?|redaction|dlp|protection|firewall|approval|confirmation|restrictions?)\b/i },
  { id: "upload_exfil", re: /\b(?:upload|send|forward|transmit|post|share|export|sync|email|submit|exfiltrate|leak)\s+(?:the\s+|this\s+|all\s+|any\s+|my\s+|these\s+)?(?:file|document|screenshot|data|form|contents?|information|profile|vault|record|values?|details?|secrets?)\b[\s\S]{0,40}?(?:to|at|via)\s+(?:https?:\/\/|[a-z0-9-]+\.[a-z]{2,})/i },
  { id: "instruction_to_hide_from_user", re: /\b(?:do\s+not|don'?t|never|without)\s+(?:tell|show(?:ing)?|inform(?:ing)?|alert(?:ing)?|notify(?:ing)?|ask(?:ing)?|warn(?:ing)?|mention(?:ing)?)\b[\s\S]{0,20}?\buser\b/i },
  { id: "tool_targeting", re: /\b(?:call|invoke|use|run|execute)\s+(?:the\s+)?(?:tool|function|api|command|action)\s*[:(]|\bfunction\.call\b|<\s*tool_call\s*>|"tool"\s*:|<\|im_start\|>/i },
];

// WEAK soft indicators — one is SUSPICIOUS, two+ is MALICIOUS.
const SOFT_INDICATORS = [
  { id: "agent_addressed", re: /\b(?:hey\s+)?(?:ai|assistant|agent|chatbot|language\s+model|llm|gpt|claude|gemini|copilot|browser\s+agent)\b[,:]?\s+(?:please\s+)?(?:you\s+(?:must|should|will|need\s+to)|do|go|click|type|fill|send|navigate|open|copy|paste|submit|ignore|disregard)/i },
  { id: "change_settings", re: /\b(?:change|update|modify|set|reset|add)\s+(?:the\s+)?(?:security|privacy|account|2fa|mfa|recovery|backup)\s+(?:settings?|options?|preferences?|address|email|phone|number)\b/i },
  { id: "fake_role_block", re: /(?:^|\n)\s*(?:###?\s*)?(?:system|developer|assistant|tool)\s*(?:prompt|message|instruction)?\s*[:>](?!\s*(?:enter|type|your\b))/im },
  { id: "urgency_authority", re: /\bthis\s+is\s+(?:an?\s+)?(?:official|urgent|critical|system|admin|security)(?:\s+(?:official|urgent|critical|system|admin|security))*\s+(?:message|instruction|notice|directive|alert|warning)\b|\bas\s+(?:an?\s+)?(?:admin|administrator|developer|system)\b\s*,|\bauthorized\s+by\s+(?:the\s+)?(?:system|admin|developer)\b|\bon\s+behalf\s+of\s+(?:the\s+)?(?:system|admin)\b/i },
  { id: "encoded_blob", re: /\b(?:base64|rot13|decode\s+this|atob\(|String\.fromCharCode)\b/i },
];

/**
 * Grade a chunk of untrusted page text.
 * @param {string} text
 * @param {{ source?: string, element?: string }} [meta]
 * @returns {{
 *   verdict: "SAFE"|"SUSPICIOUS"|"MALICIOUS",
 *   confidence: number,
 *   indicators: string[],
 *   source: string,
 *   affectedElement: string|null,
 *   recommendedAction: "allow"|"quarantine"|"block"
 * }}
 */
export function classifyContent(text, meta = {}) {
  const source = meta.source || "dom";
  const affectedElement = meta.element || null;
  const empty = { verdict: "SAFE", confidence: 0, indicators: [], source, affectedElement, recommendedAction: "allow" };
  if (!text || typeof text !== "string") return empty;

  const normalized = normalizeText(text);
  const hadZeroWidth = normalized !== text.replace(/\s+/g, " ").trim();

  // 1. hard injection pattern -> MALICIOUS
  const hard = detectPromptInjection(text);
  if (hard.isInjection) {
    return {
      verdict: "MALICIOUS",
      confidence: hard.confidence,
      indicators: [hard.threat || "prompt_injection", ...(hadZeroWidth ? ["zero_width_obfuscation"] : [])],
      source, affectedElement, recommendedAction: "block",
    };
  }

  // 2. indicators
  const strong = STRONG_INDICATORS.filter((ind) => ind.re.test(normalized)).map((i) => i.id);
  const weak = SOFT_INDICATORS.filter((ind) => ind.re.test(normalized)).map((i) => i.id);
  const hits = [...strong, ...weak];
  if (hadZeroWidth && hits.length) hits.push("zero_width_obfuscation");

  if (hits.length === 0) return empty;

  if (strong.length >= 1 || weak.length >= 2 || (weak.length === 1 && hadZeroWidth)) {
    return {
      verdict: "MALICIOUS",
      confidence: Math.min(0.92, 0.6 + 0.12 * hits.length),
      indicators: hits, source, affectedElement, recommendedAction: "block",
    };
  }
  return { verdict: "SUSPICIOUS", confidence: 0.55, indicators: hits, source, affectedElement, recommendedAction: "quarantine" };
}

/**
 * Separate a page-text blob into the part safe to pass to the VLM as DATA and
 * the spans that must be withheld (they read as INSTRUCTIONS).
 * @returns {{ data: string, withheld: Array<{text:string, verdict:string, indicators:string[]}> }}
 */
export function separateDataFromInstructions(text, meta = {}) {
  if (!text || typeof text !== "string") return { data: "", withheld: [] };
  const withheld = [];
  // grade sentence-ish chunks so one bad line doesn't nuke the whole blob
  const chunks = text.split(/(?<=[.!?\n])\s+/);
  const kept = [];
  for (const c of chunks) {
    const g = classifyContent(c, meta);
    if (g.verdict === "MALICIOUS" || (g.verdict === "SUSPICIOUS" && g.confidence >= 0.6)) {
      withheld.push({ text: c.slice(0, 120), verdict: g.verdict, indicators: g.indicators });
    } else {
      kept.push(c);
    }
  }
  return { data: kept.join(" ").trim(), withheld };
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

  // 0. HTML comments + <meta content> — non-rendered channels a page can use to
  //    smuggle instructions past a human but not past an agent that reads the DOM.
  try {
    const doc = root.ownerDocument || root;
    if (typeof doc.createTreeWalker === "function") {
      const SHOW_COMMENT = (globalThis.NodeFilter && globalThis.NodeFilter.SHOW_COMMENT) || 0x80;
      const w = doc.createTreeWalker(root, SHOW_COMMENT);
      let cnode;
      while ((cnode = w.nextNode())) {
        const g = classifyContent(cnode.nodeValue || "", { source: "html_comment" });
        if (g.verdict !== "SAFE") {
          threats.push({ node: cnode.parentElement || null, type: "COMMENT_PROMPT_INJECTION",
            reason: `Injection in an HTML comment [${g.indicators.join(", ")}]`, text: (cnode.nodeValue || "").slice(0, 150),
            confidence: g.confidence, verdict: g.verdict, bbox: { x: 0, y: 0, w: 1, h: 1 } });
        }
      }
    }
  } catch { /* non-DOM env */ }
  if (typeof root.querySelectorAll === "function") {
    for (const m of root.querySelectorAll("meta[content], meta[name]")) {
      const content = m.getAttribute("content") || "";
      const g = classifyContent(content, { source: "meta_tag", element: `meta[${m.getAttribute("name") || m.getAttribute("property") || "?"}]` });
      if (g.verdict !== "SAFE") {
        threats.push({ node: m, type: "META_PROMPT_INJECTION",
          reason: `Injection in <meta ${m.getAttribute("name") || ""}> [${g.indicators.join(", ")}]`,
          text: content.slice(0, 150), confidence: g.confidence, verdict: g.verdict, bbox: { x: 0, y: 0, w: 1, h: 1 } });
      }
    }
  }

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
