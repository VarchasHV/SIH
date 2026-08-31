// Privacy Lens — DOM Text Redactor (Project Antigravity)
//
// Scans all visible text nodes for PII values using Tier 1 regex patterns
// (Aadhaar, PAN, phone, SSN, credit-card, email) and replaces them with
// visible redaction tokens so the user can verify protection.
//
// A MutationObserver watches for dynamic DOM changes (SPA frameworks like
// React/Vue injecting content after initial load) and instantly redacts
// any new PII that appears.
//
// This is a plain-JS content script (MV3 cannot import ESM in content
// scripts), so Tier 1 patterns and checksum functions are inlined.

(function () {
  if (window.__plDomRedactorLoaded) return;
  window.__plDomRedactorLoaded = true;

  // ═══════════════════════════════════════════════════════════════════════
  // Inline Verhoeff checksum (mirrors tier1-fastpath.mjs / pii-rules.mjs)
  // ═══════════════════════════════════════════════════════════════════════

  const VD = [
    [0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],
    [3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],
    [6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],
    [9,8,7,6,5,4,3,2,1,0],
  ];
  const VP = [
    [0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],
    [8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],
    [2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8],
  ];

  function verhoeffValid(digits) {
    const s = String(digits).replace(/\D/g, "");
    if (s.length !== 12) return false;
    let c = 0;
    const rev = s.split("").reverse();
    for (let i = 0; i < rev.length; i++) c = VD[c][VP[i % 8][Number(rev[i])]];
    return c === 0;
  }

  // ═══════════════════════════════════════════════════════════════════════
  // Inline Luhn checksum
  // ═══════════════════════════════════════════════════════════════════════

  function luhnValid(digits) {
    const s = String(digits).replace(/\D/g, "");
    if (s.length < 12 || s.length > 19) return false;
    let sum = 0, dbl = false;
    for (let i = s.length - 1; i >= 0; i--) {
      let d = Number(s[i]);
      if (dbl) { d *= 2; if (d > 9) d -= 9; }
      sum += d; dbl = !dbl;
    }
    return sum % 10 === 0;
  }

  // ═══════════════════════════════════════════════════════════════════════
  // Tier 1 redaction patterns — category, regex, optional validator, token
  // ═══════════════════════════════════════════════════════════════════════

  const REDACTION_RULES = [
    {
      category: "aadhaar",
      re: /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g,
      validate: (m) => verhoeffValid(m.replace(/[\s-]/g, "")),
      token: "████████████",
    },
    {
      category: "pan",
      re: /\b[A-Z]{5}[0-9]{4}[A-Z]\b/g,
      validate: null,
      token: "██████████",
    },
    {
      category: "phone-in",
      re: /(?<!\d)(?:\+?91[\s-]?)?[6-9]\d{9}\b/g,
      validate: null,
      token: "██████████",
    },
    {
      category: "ssn",
      re: /(?<!(?:order|ref|id|batch|serial|part)[:\s-]*)\b\d{3}-\d{2}-\d{4}\b/gi,
      validate: (m) => {
        const parts = m.match(/^(\d{3})-(\d{2})-(\d{4})$/);
        if (!parts) return false;
        const [, a, g, s] = parts;
        const A = +a, G = +g, S = +s;
        return A !== 0 && A !== 666 && A < 900 && G !== 0 && S !== 0;
      },
      token: "███████████",
    },
    {
      category: "credit-card",
      re: /\b(?:\d[\s-]?){12,19}\b/g,
      validate: (m) => luhnValid(m),
      token: "████████████████",
    },
    {
      category: "email",
      re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
      validate: null,
      token: "████████████████",
    },
  ];

  // ═══════════════════════════════════════════════════════════════════════
  // Tags to skip during TreeWalker traversal
  // ═══════════════════════════════════════════════════════════════════════

  const SKIP_TAGS = new Set([
    "SCRIPT", "STYLE", "NOSCRIPT", "TEXTAREA", "INPUT", "CODE", "PRE",
  ]);

  // Marker attribute to prevent double-processing
  const REDACTED_ATTR = "data-pl-redacted";

  // ═══════════════════════════════════════════════════════════════════════
  // Core: scan a text node and replace PII matches with redaction tokens
  // ═══════════════════════════════════════════════════════════════════════

  function redactSingleTextNode(textNode) {
    if (!textNode || textNode.nodeType !== Node.TEXT_NODE) return false;

    const parent = textNode.parentElement;
    if (!parent) return false;

    // Skip if parent is a tag we shouldn't touch, or already redacted
    if (SKIP_TAGS.has(parent.tagName)) return false;
    if (parent.hasAttribute(REDACTED_ATTR)) return false;

    // Skip nodes inside inputs/textareas (contenteditable)
    if (parent.closest("script, style, noscript, textarea")) return false;

    let text = textNode.nodeValue;
    if (!text || text.trim().length < 3) return false;

    // Collect all matches across all rules, with their positions
    const allMatches = [];

    for (const rule of REDACTION_RULES) {
      rule.re.lastIndex = 0;
      let m;
      while ((m = rule.re.exec(text)) !== null) {
        const value = m[0];
        if (rule.validate && !rule.validate(value)) continue;
        allMatches.push({
          start: m.index,
          end: m.index + value.length,
          token: rule.token,
          category: rule.category,
        });
        // Guard against zero-length match infinite loop
        if (m.index === rule.re.lastIndex) rule.re.lastIndex++;
      }
    }

    if (allMatches.length === 0) return false;

    // Sort by start position, then by longest match (for overlap resolution)
    allMatches.sort((a, b) => a.start - b.start || (b.end - b.start) - (a.end - a.start));

    // Remove overlapping matches (keep earliest, then longest)
    const resolved = [];
    for (const match of allMatches) {
      if (!resolved.some((r) => match.start < r.end && r.start < match.end)) {
        resolved.push(match);
      }
    }

    // Apply replacements right-to-left to preserve character offsets
    let result = text;
    for (let i = resolved.length - 1; i >= 0; i--) {
      const { start, end, token } = resolved[i];
      result = result.slice(0, start) + token + result.slice(end);
    }

    textNode.nodeValue = result;
    parent.setAttribute(REDACTED_ATTR, "1");
    return true;
  }

  // ═══════════════════════════════════════════════════════════════════════
  // TreeWalker: scan all text nodes under a root element
  // ═══════════════════════════════════════════════════════════════════════

  function redactTextNodes(root) {
    if (!root || root.nodeType === Node.TEXT_NODE) {
      // Directly process a single text node
      return redactSingleTextNode(root) ? 1 : 0;
    }

    const walker = document.createTreeWalker(
      root,
      NodeFilter.SHOW_TEXT,
      {
        acceptNode(node) {
          const parent = node.parentElement;
          if (!parent) return NodeFilter.FILTER_REJECT;
          if (SKIP_TAGS.has(parent.tagName)) return NodeFilter.FILTER_REJECT;
          if (parent.hasAttribute(REDACTED_ATTR)) return NodeFilter.FILTER_REJECT;
          return NodeFilter.FILTER_ACCEPT;
        },
      },
      false
    );

    // Collect nodes first (modifying the DOM during traversal is unsafe)
    const textNodes = [];
    let node;
    while ((node = walker.nextNode())) {
      textNodes.push(node);
    }

    let count = 0;
    for (const tn of textNodes) {
      if (redactSingleTextNode(tn)) count++;
    }

    return count;
  }

  // ═══════════════════════════════════════════════════════════════════════
  // Initial scan
  // ═══════════════════════════════════════════════════════════════════════

  let initialCount = 0;
  if (document.body) {
    initialCount = redactTextNodes(document.body);
  }

  // ═══════════════════════════════════════════════════════════════════════
  // MutationObserver for SPA / dynamic content
  // ═══════════════════════════════════════════════════════════════════════

  let mutationTimer = null;
  const pendingNodes = new Set();

  function processPendingMutations() {
    mutationTimer = null;
    for (const node of pendingNodes) {
      // Check the node is still in the document
      if (node.isConnected) {
        redactTextNodes(node);
      }
    }
    pendingNodes.clear();
  }

  const observer = new MutationObserver((mutations) => {
    let needsWork = false;

    for (const record of mutations) {
      if (record.type === "childList") {
        for (const added of record.addedNodes) {
          if (added.nodeType === Node.ELEMENT_NODE) {
            // Skip our own overlay / redacted markers
            if (added.id === "__pl_overlay") continue;
            pendingNodes.add(added);
            needsWork = true;
          } else if (added.nodeType === Node.TEXT_NODE) {
            pendingNodes.add(added);
            needsWork = true;
          }
        }
      } else if (record.type === "characterData") {
        const target = record.target;
        if (target.nodeType === Node.TEXT_NODE) {
          // Clear the redacted flag so we can re-process
          const parent = target.parentElement;
          if (parent && parent.hasAttribute(REDACTED_ATTR)) {
            parent.removeAttribute(REDACTED_ATTR);
          }
          pendingNodes.add(target);
          needsWork = true;
        }
      }
    }

    if (needsWork && !mutationTimer) {
      mutationTimer = setTimeout(processPendingMutations, 150);
    }
  });

  if (document.body) {
    observer.observe(document.body, {
      childList: true,
      subtree: true,
      characterData: true,
    });
  }

  // ═══════════════════════════════════════════════════════════════════════
  // Message listener — allow background/popup to trigger a full re-scan
  // ═══════════════════════════════════════════════════════════════════════

  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (msg.action === "PL_REDACT_SCAN") {
      const count = document.body ? redactTextNodes(document.body) : 0;
      sendResponse({ ok: true, redactedNodes: count });
      return true;
    }
  });

  // Expose for testing / other content scripts
  window.__PL = window.__PL || {};
  window.__PL.redactTextNodes = redactTextNodes;
  window.__PL.redactStats = { initialCount };
})();
