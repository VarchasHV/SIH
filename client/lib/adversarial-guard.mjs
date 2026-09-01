// Adversarial Robustness & Indirect Prompt-Injection Guard for Privacy Lens.
//
// Detects, quarantines, and sanitizes adversarial attacks targeting browser agents:
// 1. Indirect Prompt Injections (jailbreaks, instruction overrides, data exfiltration commands)
// 2. Steganographic / Hidden Text (opacity:0, font-size:0, offscreen coordinates, low-contrast text)
// 3. Fake System Prompts and Deceptive UI Chrome

/**
 * High-confidence regex patterns for indirect prompt injections and jailbreaks.
 */
export const INJECTION_PATTERNS = [
  // Instruction Overrides & Jailbreaks
  /\b(?:ignore|disregard|forget|bypass)\s+(?:all\s+)?(?:previous|prior|above|former)\s+(?:instructions|prompts?|rules?|directives?|commands?)\b/i,
  /\b(?:new\s+instructions?|system\s+override|admin\s+override|developer\s+mode|jailbreak|dan\s+mode)\b/i,
  /\b(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be)\s+(?:an?\s+unrestricted|a\s+hacked|an\s+evil|a\s+root)\b/i,
  
  // Data Exfiltration & Hijacking
  /\b(?:send|exfiltrate|post|leak|transmit|forward|upload)\s+(?:all\s+)?(?:passwords?|tokens?|cookies?|pii|credentials?|aadhaar|pan|cards?|secrets?|vault)\b/i,
  /\b(?:http[s]?:\/\/[^\s]+(?:\/exfil|\/collect|\/steal|\/log|\/webhook|\/drop))\b/i,
  /\b(?:fetch|webhook|curl|wget)\s+https?:\/\//i,
  
  // Malicious UI Action Manipulation
  /\b(?:do\s+not\s+fill|stop\s+filling|instead\s+click|click\s+here\s+first|navigate\s+to\s+evil)\b/i,
  /\b(?:transfer\s+funds?\s+to|pay\s+to|send\s+money\s+to|change\s+recipient\s+to)\b/i,
  /\b(?:system\s+message\s*:|assistant\s*:|human\s*:|user\s*:|\[system\]|\[instruction\])\b/i,
  
  // Base64 & obfuscated script patterns
  /\b(?:eval\(|document\.cookie|window\.localStorage|chrome\.storage)\b/i,
];

/**
 * Tests if a given text contains indirect prompt injection or adversarial jailbreak commands.
 * @param {string} text
 * @returns {{ isInjection: boolean, match: string | null, confidence: number, patternIndex: number }}
 */
export function detectPromptInjection(text) {
  if (!text || typeof text !== "string") {
    return { isInjection: false, match: null, confidence: 0, patternIndex: -1 };
  }

  const normalized = text.trim();
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

  // Heuristic: check for repetitive command overrides or fake role tags
  if (/(?:^|\n)\s*(?:system|assistant|instruction|human)\s*:\s*\w+/i.test(normalized)) {
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
 * @param {HTMLElement} el
 * @param {Window} [win]
 * @returns {{ isHidden: boolean, reason: string | null, confidence: number }}
 */
export function detectHiddenStyles(el, win = globalThis) {
  if (!el || typeof win.getComputedStyle !== "function") {
    return { isHidden: false, reason: null, confidence: 0 };
  }

  try {
    const style = win.getComputedStyle(el);
    const rect = typeof el.getBoundingClientRect === "function" ? el.getBoundingClientRect() : { width: 0, height: 0, top: 0, left: 0 };

    // 1. Zero/near-zero opacity
    const opacity = parseFloat(style.opacity || "1");
    if (opacity < 0.05) {
      return { isHidden: true, reason: `Near-zero opacity (${opacity})`, confidence: 0.99 };
    }

    // 2. Zero/near-zero font size
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

    // 4. Zero dimensions with hidden overflow
    if (style.overflow === "hidden" && (rect.width <= 1 || rect.height <= 1) && el.textContent && el.textContent.trim().length > 5) {
      return { isHidden: true, reason: "Zero-box clipping with hidden overflow", confidence: 0.95 };
    }

    // 5. Explicit visibility: hidden or display: none but containing text
    if ((style.visibility === "hidden" || style.display === "none") && el.textContent && el.textContent.trim().length > 0) {
      return { isHidden: true, reason: `Hidden visibility (${style.visibility || style.display})`, confidence: 0.90 };
    }

    // 6. Text color matching background color (white-on-white, black-on-black)
    const color = style.color;
    const bg = style.backgroundColor;
    if (color && bg && color !== "rgba(0, 0, 0, 0)" && bg !== "rgba(0, 0, 0, 0)" && color === bg) {
      return { isHidden: true, reason: "Zero-contrast foreground/background match", confidence: 0.96 };
    }
  } catch {
    // Graceful fallback for non-DOM node environments
  }

  return { isHidden: false, reason: null, confidence: 0 };
}

/**
 * Scans an entire document or subtree for adversarial vectors (injections + hidden text).
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
    if (!text) continue;

    // 1. Check for hidden text styles
    const hiddenCheck = detectHiddenStyles(el, win);
    if (hiddenCheck.isHidden) {
      const injectionCheck = detectPromptInjection(text);
      const bbox = typeof el.getBoundingClientRect === "function" ? el.getBoundingClientRect() : { x: 0, y: 0, width: 0, height: 0 };
      threats.push({
        node: el,
        type: injectionCheck.isInjection ? "HIDDEN_PROMPT_INJECTION" : "STEGANOGRAPHIC_HIDDEN_TEXT",
        reason: hiddenCheck.reason + (injectionCheck.isInjection ? ` + Prompt Injection: "${injectionCheck.match}"` : ""),
        text: text.slice(0, 150),
        confidence: hiddenCheck.confidence,
        bbox: {
          x: Math.max(0, bbox.left ?? bbox.x ?? 0),
          y: Math.max(0, bbox.top ?? bbox.y ?? 0),
          w: Math.max(1, bbox.width ?? 0),
          h: Math.max(1, bbox.height ?? 0),
        },
      });
      continue;
    }

    // 2. Check for visible prompt injection / jailbreak text
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
    }
  }

  return threats;
}
