// IIFE bundle of adversarial-guard for content scripts
(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory();
  } else {
    root.AdversarialGuard = factory();
  }
})(typeof self !== "undefined" ? self : this, function () {
  const INJECTION_PATTERNS = [
    /\b(?:ignore|disregard|forget|bypass)\s+(?:all\s+)?(?:previous|prior|above|former)\s+(?:instructions|prompts?|rules?|directives?|commands?)\b/i,
    /\b(?:new\s+instructions?|system\s+override|admin\s+override|developer\s+mode|jailbreak|dan\s+mode)\b/i,
    /\b(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be)\s+(?:an?\s+unrestricted|a\s+hacked|an\s+evil|a\s+root)\b/i,
    /\b(?:send|exfiltrate|post|leak|transmit|forward|upload)\s+(?:all\s+)?(?:passwords?|tokens?|cookies?|pii|credentials?|aadhaar|pan|cards?|secrets?|vault)\b/i,
    /\b(?:http[s]?:\/\/[^\s]+(?:\/exfil|\/collect|\/steal|\/log|\/webhook|\/drop))\b/i,
    /\b(?:fetch|webhook|curl|wget)\s+https?:\/\//i,
    /\b(?:do\s+not\s+fill|stop\s+filling|instead\s+click|click\s+here\s+first|navigate\s+to\s+evil)\b/i,
    /\b(?:transfer\s+funds?\s+to|pay\s+to|send\s+money\s+to|change\s+recipient\s+to)\b/i,
    /\b(?:system\s+message\s*:|assistant\s*:|human\s*:|user\s*:|\[system\]|\[instruction\])\b/i,
    /\b(?:eval\(|document\.cookie|window\.localStorage|chrome\.storage)\b/i,
  ];

  function detectPromptInjection(text) {
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

  function detectHiddenStyles(el, win = (typeof window !== "undefined" ? window : globalThis)) {
    if (!el || typeof win.getComputedStyle !== "function") {
      return { isHidden: false, reason: null, confidence: 0 };
    }
    try {
      const style = win.getComputedStyle(el);
      const rect = typeof el.getBoundingClientRect === "function" ? el.getBoundingClientRect() : { width: 0, height: 0, top: 0, left: 0 };

      const opacity = parseFloat(style.opacity || "1");
      if (opacity < 0.05) {
        return { isHidden: true, reason: `Near-zero opacity (${opacity})`, confidence: 0.99 };
      }

      const fontSize = parseFloat(style.fontSize || "16");
      if (fontSize < 2 && el.textContent && el.textContent.trim().length > 0) {
        return { isHidden: true, reason: `Sub-pixel font size (${fontSize}px)`, confidence: 0.99 };
      }

      const left = parseFloat(style.left || "0");
      const top = parseFloat(style.top || "0");
      if ((left < -1000 || top < -1000) && el.textContent && el.textContent.trim().length > 0) {
        return { isHidden: true, reason: `Off-screen absolute positioning (left:${left}px, top:${top}px)`, confidence: 0.98 };
      }

      if (style.overflow === "hidden" && (rect.width <= 1 || rect.height <= 1) && el.textContent && el.textContent.trim().length > 5) {
        return { isHidden: true, reason: "Zero-box clipping with hidden overflow", confidence: 0.95 };
      }

      if ((style.visibility === "hidden" || style.display === "none") && el.textContent && el.textContent.trim().length > 0) {
        return { isHidden: true, reason: `Hidden visibility (${style.visibility || style.display})`, confidence: 0.90 };
      }

      const color = style.color;
      const bg = style.backgroundColor;
      if (color && bg && color !== "rgba(0, 0, 0, 0)" && bg !== "rgba(0, 0, 0, 0)" && color === bg) {
        return { isHidden: true, reason: "Zero-contrast foreground/background match", confidence: 0.96 };
      }
    } catch {}
    return { isHidden: false, reason: null, confidence: 0 };
  }

  function scanAdversarialVectors(root, win = (typeof window !== "undefined" ? window : globalThis)) {
    const threats = [];
    if (!root || typeof root.querySelectorAll !== "function") return threats;

    const elements = root.querySelectorAll("*");
    for (const el of elements) {
      if (["SCRIPT", "STYLE", "LINK", "META", "NOSCRIPT"].includes(el.tagName)) continue;
      const text = (el.innerText || el.textContent || "").trim();
      if (!text) continue;

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

  return {
    INJECTION_PATTERNS,
    detectPromptInjection,
    detectHiddenStyles,
    scanAdversarialVectors,
  };
});
