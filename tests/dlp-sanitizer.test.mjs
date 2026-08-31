import test from "node:test";
import assert from "node:assert/strict";

import {
  classifyFieldHeuristics,
  sanitizeParagraphText,
  isSensitiveMedia,
} from "../client/lib/dlp-heuristics.mjs";

import {
  DLPSanitizer,
  resolveFieldLabel,
} from "../client/lib/dlp-sanitizer.mjs";

// ═══════════════════════════════════════════════════════════════════════════
// Mock DOM Implementation for Node test environment
// ═══════════════════════════════════════════════════════════════════════════

class MockNode {
  constructor(nodeType, nodeValue = null) {
    this.nodeType = nodeType;
    this.nodeValue = nodeValue;
    this.parentElement = null;
    this.childNodes = [];
    this.attributes = {};
  }
  get textContent() {
    if (this.nodeType === 3) return this.nodeValue || "";
    return this.childNodes.map((c) => c.textContent).join("");
  }
  set textContent(val) {
    if (this.nodeType === 3) {
      this.nodeValue = val;
    } else {
      this.childNodes = [new MockNode(3, String(val))];
      this.childNodes[0].parentElement = this;
    }
  }
  appendChild(child) {
    child.parentElement = this;
    this.childNodes.push(child);
    return child;
  }
  getAttribute(name) {
    return this.attributes[name] || null;
  }
  setAttribute(name, value) {
    this.attributes[name] = String(value);
  }
  hasAttribute(name) {
    return name in this.attributes;
  }
  removeAttribute(name) {
    delete this.attributes[name];
  }
  closest(selector) {
    const sel = selector.toUpperCase();
    let cur = this;
    while (cur) {
      if (cur.tagName && cur.tagName === sel) return cur;
      cur = cur.parentElement;
    }
    return null;
  }
  cloneNode(deep = true) {
    const clone = new MockElement(this.tagName);
    clone.attributes = { ...this.attributes };
    if (deep) {
      for (const c of this.childNodes) {
        if (c.nodeType === 3) {
          clone.appendChild(new MockNode(3, c.nodeValue));
        } else {
          clone.appendChild(c.cloneNode(true));
        }
      }
    }
    return clone;
  }
  get previousElementSibling() {
    if (!this.parentElement) return null;
    const siblings = this.parentElement.childNodes.filter((n) => n.nodeType === 1);
    const idx = siblings.indexOf(this);
    return idx > 0 ? siblings[idx - 1] : null;
  }
  remove() {
    if (this.parentElement) {
      const idx = this.parentElement.childNodes.indexOf(this);
      if (idx !== -1) this.parentElement.childNodes.splice(idx, 1);
    }
  }
}

class MockElement extends MockNode {
  constructor(tagName) {
    super(1);
    this.tagName = tagName.toUpperCase();
    this.value = "";
    this.checked = false;
    this.options = [];
  }
  querySelector(sel) {
    const tag = sel.split(/[\s,]+/)[0].toUpperCase();
    function find(node) {
      if (node.tagName === tag) return node;
      for (const c of node.childNodes || []) {
        const res = find(c);
        if (res) return res;
      }
      return null;
    }
    return find(this);
  }
  querySelectorAll(sel) {
    const tags = sel.toUpperCase().split(/,\s*/);
    const results = [];
    function collect(node) {
      if (node.tagName && tags.includes(node.tagName)) results.push(node);
      for (const c of node.childNodes || []) collect(c);
    }
    collect(this);
    return results;
  }
}

class MockDocument {
  constructor() {
    this.body = new MockElement("BODY");
  }
  createElement(tag) {
    return new MockElement(tag);
  }
  createTextNode(text) {
    return new MockNode(3, text);
  }
  getElementById(id) {
    function find(node) {
      if (node.getAttribute?.("id") === id) return node;
      for (const c of node.childNodes || []) {
        const res = find(c);
        if (res) return res;
      }
      return null;
    }
    return find(this.body);
  }
  querySelector(sel) {
    const forMatch = sel.match(/label\[for="([^"]+)"\]/);
    if (forMatch) {
      const forId = forMatch[1];
      function findLabel(node) {
        if (node.tagName === "LABEL" && node.getAttribute("for") === forId) return node;
        for (const c of node.childNodes || []) {
          const res = findLabel(c);
          if (res) return res;
        }
        return null;
      }
      return findLabel(this.body);
    }
    return this.body.querySelector(sel);
  }
  querySelectorAll(sel) {
    return this.body.querySelectorAll(sel);
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// 1. Heuristics & Tokenization Tests
// ═══════════════════════════════════════════════════════════════════════════

test("DLP Heuristics - accurately classifies and maps PII fields to semantic tokens", () => {
  const fields = [
    { signals: { id: "cc_number", type: "text" }, expectedCategory: "credit_card", expectedToken: "[TOKEN_CREDIT_CARD]" },
    { signals: { id: "cvv2", type: "text" }, expectedCategory: "cvv", expectedToken: "[TOKEN_CVV]" },
    { signals: { name: "user_password", type: "password" }, expectedCategory: "password", expectedToken: "[TOKEN_PASSWORD]" },
    { signals: { name: "ssn_val", placeholder: "Social Security Number" }, expectedCategory: "ssn", expectedToken: "[TOKEN_SSN]" },
    { signals: { id: "user_dob", labelText: "Date of Birth" }, expectedCategory: "dob", expectedToken: "[TOKEN_DOB]" },
    { signals: { id: "phone_num", labelText: "Cell Phone" }, expectedCategory: "phone", expectedToken: "[TOKEN_PHONE]" },
    { signals: { name: "email_address", type: "email" }, expectedCategory: "email", expectedToken: "[TOKEN_EMAIL]" },
    { signals: { id: "company_name", labelText: "Company" }, expectedCategory: "company", expectedToken: "[TOKEN_COMPANY]" },
  ];

  for (const f of fields) {
    const res = classifyFieldHeuristics(f.signals);
    assert.equal(res.isSensitive, true, `Field ${JSON.stringify(f.signals)} should be sensitive`);
    assert.equal(res.category, f.expectedCategory);
    assert.equal(res.token, f.expectedToken);
  }
});

test("DLP Heuristics - does NOT flag non-PII fields", () => {
  const safe = [
    { id: "search_query", placeholder: "Search store..." },
    { name: "promo_code", labelText: "Promo Code" },
    { id: "quantity_select", labelText: "Quantity" },
  ];

  for (const s of safe) {
    const res = classifyFieldHeuristics(s);
    assert.equal(res.isSensitive, false);
    assert.equal(res.token, null);
  }
});

test("DLP Text Sanitizer - redacts raw PII strings in paragraph text", () => {
  const rawText = "Your verification code was sent to user@example.com and SSN 123-45-6789 with card 4111 2222 3333 4444.";
  const sanitized = sanitizeParagraphText(rawText);

  assert.match(sanitized, /\[TOKEN_EMAIL\]|\[TEXT_REDACTED\]/);
  assert.match(sanitized, /\[TOKEN_SSN\]|\[TEXT_REDACTED\]/);
  assert.match(sanitized, /\[TOKEN_CREDIT_CARD\]|\[TEXT_REDACTED\]/);
  assert.equal(sanitized.includes("user@example.com"), false);
  assert.equal(sanitized.includes("123-45-6789"), false);
  assert.equal(sanitized.includes("4111 2222 3333 4444"), false);
});

test("DLP Media Quarantine - flags base64 data URIs and identity photo contexts", () => {
  assert.equal(isSensitiveMedia({ src: "data:image/png;base64,iVBORw0KGgoAAA..." }), true);
  assert.equal(isSensitiveMedia({ alt: "Passport Photo Upload", nearbyText: "Please upload your ID" }), true);
  assert.equal(isSensitiveMedia({ src: "https://example.com/logo.png", alt: "Brand Logo" }), false);
});

// ═══════════════════════════════════════════════════════════════════════════
// 2. DOM Traversal & Label Resolution Tests
// ═══════════════════════════════════════════════════════════════════════════

test("Label Resolver - resolves explicit label for attribute", () => {
  const doc = new MockDocument();
  const label = doc.createElement("LABEL");
  label.setAttribute("for", "card-num");
  label.textContent = "Credit Card Number";
  doc.body.appendChild(label);

  const input = doc.createElement("INPUT");
  input.setAttribute("id", "card-num");
  doc.body.appendChild(input);

  const resolved = resolveFieldLabel(input, doc);
  assert.equal(resolved, "Credit Card Number");
});

test("Label Resolver - resolves enclosing label text", () => {
  const doc = new MockDocument();
  const label = doc.createElement("LABEL");
  label.textContent = "Password";

  const input = doc.createElement("INPUT");
  input.setAttribute("type", "password");
  label.appendChild(input);
  doc.body.appendChild(label);

  const resolved = resolveFieldLabel(input, doc);
  assert.equal(resolved, "Password");
});

test("Label Resolver - resolves preceding sibling proximity", () => {
  const doc = new MockDocument();
  const span = doc.createElement("SPAN");
  span.textContent = "Billing Address";
  doc.body.appendChild(span);

  const input = doc.createElement("INPUT");
  input.setAttribute("id", "addr_1");
  doc.body.appendChild(input);

  const resolved = resolveFieldLabel(input, doc);
  assert.equal(resolved, "Billing Address");
});

// ═══════════════════════════════════════════════════════════════════════════
// 3. Full DOM Sanitizer & Payload Generation Tests
// ═══════════════════════════════════════════════════════════════════════════

test("DLPSanitizer - completely strips sensitive values and generates zero-PII payload", () => {
  const doc = new MockDocument();

  // Create Form with sensitive fields
  const form = doc.createElement("FORM");
  form.setAttribute("id", "checkout-form");

  const ccLabel = doc.createElement("LABEL");
  ccLabel.setAttribute("for", "cc-field");
  ccLabel.textContent = "Card Number";
  form.appendChild(ccLabel);

  const ccInput = doc.createElement("INPUT");
  ccInput.setAttribute("id", "cc-field");
  ccInput.setAttribute("name", "cardNumber");
  ccInput.value = "4111222233334444"; // Real secret user data
  form.appendChild(ccInput);

  const ssnInput = doc.createElement("INPUT");
  ssnInput.setAttribute("id", "ssn-field");
  ssnInput.setAttribute("placeholder", "Enter SSN");
  ssnInput.value = "999-00-1234"; // Real secret user data
  form.appendChild(ssnInput);

  const searchInput = doc.createElement("INPUT");
  searchInput.setAttribute("id", "query-field");
  searchInput.setAttribute("placeholder", "Search items");
  searchInput.value = "mechanical keyboard";
  form.appendChild(searchInput);

  // Add sensitive image
  const img = doc.createElement("IMG");
  img.setAttribute("src", "data:image/jpeg;base64,deadbeef...");
  img.setAttribute("alt", "Driver License Upload");
  form.appendChild(img);

  doc.body.appendChild(form);

  // 1. Extract sanitized structural tree
  const tree = DLPSanitizer.extractSanitizedTree(doc.body);
  assert.equal(tree.forms.length, 1);
  const fields = tree.forms[0].fields;

  // CC Field check
  const ccField = fields.find((f) => f.id === "cc-field");
  assert.equal(ccField.isSensitive, true);
  assert.equal(ccField.value, "[TOKEN_CREDIT_CARD]");
  assert.equal(ccField.label, "Card Number");

  // SSN Field check
  const ssnField = fields.find((f) => f.id === "ssn-field");
  assert.equal(ssnField.isSensitive, true);
  assert.equal(ssnField.value, "[TOKEN_SSN]");

  // Non-sensitive query field check
  const qField = fields.find((f) => f.id === "query-field");
  assert.equal(qField.isSensitive, false);

  // Image check
  assert.equal(tree.images[0].isSensitive, true);
  assert.equal(tree.images[0].src, "[SENSITIVE_IMAGE_REDACTED]");

  // 2. Extract clean minified HTML string for LLM
  const cleanHtml = DLPSanitizer.toCleanHtml(doc.body);
  assert.match(cleanHtml, /value="\[TOKEN_CREDIT_CARD\]"/);
  assert.match(cleanHtml, /value="\[TOKEN_SSN\]"/);
  assert.match(cleanHtml, /\[SENSITIVE_IMAGE_REDACTED\]/);

  // Absolute zero leak guarantee: real secret values are nowhere in the output!
  assert.equal(cleanHtml.includes("4111222233334444"), false);
  assert.equal(cleanHtml.includes("999-00-1234"), false);
  assert.equal(cleanHtml.includes("deadbeef"), false);
});
