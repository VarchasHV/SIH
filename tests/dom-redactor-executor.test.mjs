import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const redactorCode = fs.readFileSync(path.join(__dirname, "../client/dom-redactor.js"), "utf8");
const executorCode = fs.readFileSync(path.join(__dirname, "../client/executor.js"), "utf8");

// Minimal DOM mock sufficient to test TreeWalker + MutationObserver + Executor
class MockNode {
  constructor(nodeType, nodeValue = null) {
    this.nodeType = nodeType;
    this.nodeValue = nodeValue;
    this.parentElement = null;
    this.childNodes = [];
    this.attributes = {};
    this._listeners = {};
  }
  get isConnected() { return true; }
  get textContent() {
    if (this.nodeType === 3) return this.nodeValue;
    return this.childNodes.map(c => c.textContent).join("");
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
  getAttribute(name) { return this.attributes[name] || null; }
  setAttribute(name, value) { this.attributes[name] = String(value); }
  hasAttribute(name) { return name in this.attributes; }
  removeAttribute(name) { delete this.attributes[name]; }
  addEventListener(evt, fn) {
    this._listeners[evt] = this._listeners[evt] || [];
    this._listeners[evt].push(fn);
  }
  dispatchEvent(event) {
    const list = this._listeners[event.type] || [];
    for (const fn of list) fn(event);
    return true;
  }
  closest(selector) {
    const tags = selector.toUpperCase().split(/,\s*/);
    let cur = this;
    while (cur) {
      if (cur.tagName && tags.includes(cur.tagName)) return cur;
      cur = cur.parentElement;
    }
    return null;
  }
}

class MockElement extends MockNode {
  constructor(tagName) {
    super(1);
    this.tagName = tagName.toUpperCase();
    this.value = "";
    this.options = [];
  }
  focus() {}
  blur() {}
  scrollIntoView() {}
}

class MockDocument {
  constructor() {
    this.body = new MockElement("BODY");
  }
  createElement(tag) { return new MockElement(tag); }
  createTextNode(text) { return new MockNode(3, text); }
  createTreeWalker(root, whatToShow, filter) {
    const nodes = [];
    function collect(n) {
      if (n.nodeType === 3) {
        if (!filter || filter.acceptNode(n) === 1) nodes.push(n);
      }
      for (const c of n.childNodes) collect(c);
    }
    collect(root);
    let idx = 0;
    return {
      nextNode() {
        return idx < nodes.length ? nodes[idx++] : null;
      }
    };
  }
  querySelector(sel) {
    // Basic [data-pl-id="..."] selector support
    const m = sel.match(/\[data-pl-id="([^"]+)"\]/);
    if (m) {
      const targetId = m[1];
      function find(node) {
        if (node.getAttribute?.("data-pl-id") === targetId) return node;
        for (const c of node.childNodes || []) {
          const found = find(c);
          if (found) return found;
        }
        return null;
      }
      return find(this.body);
    }
    return null;
  }
}

function setupContext() {
  const document = new MockDocument();
  const window = {
    document,
    Node: { ELEMENT_NODE: 1, TEXT_NODE: 3 },
    NodeFilter: { SHOW_TEXT: 4, FILTER_ACCEPT: 1, FILTER_REJECT: 2 },
    Event: class { constructor(type) { this.type = type; } },
    KeyboardEvent: class { constructor(type) { this.type = type; } },
    InputEvent: class { constructor(type) { this.type = type; } },
    MutationObserver: class {
      constructor(cb) { this.cb = cb; }
      observe() {}
      disconnect() {}
    },
    CSS: { escape: (s) => s },
    chrome: {
      runtime: {
        onMessage: { addListener: () => {} },
        sendMessage: () => {}
      }
    },
    HTMLTextAreaElement: class {},
    HTMLSelectElement: MockElement,
    HTMLInputElement: MockElement,
    __PL: {},
  };

  const fnRedactor = new Function("window", "document", "Node", "NodeFilter", "MutationObserver", "chrome", redactorCode);
  fnRedactor(window, document, window.Node, window.NodeFilter, window.MutationObserver, window.chrome);

  const fnExecutor = new Function("window", "document", "CSS", "Event", "KeyboardEvent", "InputEvent", "HTMLTextAreaElement", "HTMLSelectElement", "HTMLInputElement", executorCode);
  fnExecutor(window, document, window.CSS, window.Event, window.KeyboardEvent, window.InputEvent, window.HTMLTextAreaElement, window.HTMLSelectElement, window.HTMLInputElement);

  return { window, document, __PL: window.__PL };
}

test("DOM Redactor - scans and redacts text nodes with solid black boxes", () => {
  const { document, __PL } = setupContext();

  const p1 = document.createElement("P");
  const tn1 = document.createTextNode("Aadhaar: 2345 6789 0124 and PAN ABCDE1234F verified.");
  p1.appendChild(tn1);
  document.body.appendChild(p1);

  const p2 = document.createElement("P");
  const tn2 = document.createTextNode("Phone: +91 9876543210, SSN: 123-45-6789, Card: 4111 1111 1111 1111, Email: test@privacylens.local");
  p2.appendChild(tn2);
  document.body.appendChild(p2);

  const count = __PL.redactTextNodes(document.body);
  assert.equal(count, 2);

  assert.equal(tn1.nodeValue, "Aadhaar: ████████████ and PAN ██████████ verified.");
  assert.equal(tn2.nodeValue, "Phone: ██████████, SSN: ███████████, Card: ████████████████, Email: ████████████████");
});

test("Executor - handles <select> dropdown by selecting index 1 and firing events", async () => {
  const { document, __PL } = setupContext();

  const select = document.createElement("SELECT");
  select.setAttribute("data-pl-id", "state-sel");
  select.options = [
    { value: "", textContent: "-- Select State --" },
    { value: "KA", textContent: "Karnataka" },
    { value: "MH", textContent: "Maharashtra" }
  ];
  document.body.appendChild(select);

  let inputFired = false;
  let changeFired = false;
  select.addEventListener("input", () => { inputFired = true; });
  select.addEventListener("change", () => { changeFired = true; });

  const res = await __PL.executeAction({ action: "select", targetId: "state-sel" }, null);
  assert.equal(res.ok, true);
  assert.equal(select.value, "KA");
  assert.equal(inputFired, true);
  assert.equal(changeFired, true);
});

test("Executor - handles <select> fuzzy matching with preference", async () => {
  const { document, __PL } = setupContext();

  const select = document.createElement("SELECT");
  select.setAttribute("data-pl-id", "state-sel");
  select.options = [
    { value: "", textContent: "-- Select State --" },
    { value: "KA", textContent: "Karnataka" },
    { value: "MH", textContent: "Maharashtra" }
  ];
  document.body.appendChild(select);

  const res = await __PL.executeAction({ action: "select", targetId: "state-sel" }, "Maharashtra");
  assert.equal(res.ok, true);
  assert.equal(select.value, "MH");
});

test("Executor - directly types resolved value into non-sensitive input field", async () => {
  const { document, __PL } = setupContext();

  const input = document.createElement("INPUT");
  input.setAttribute("data-pl-id", "email-field");
  document.body.appendChild(input);

  await __PL.executeAction({ action: "type", targetId: "email-field" }, "user@example.com");
  assert.equal(input.value, "user@example.com");
});

test("Executor - strictly blocks filling into censored/sensitive fields", async () => {
  const { document, __PL } = setupContext();

  const sensitiveFields = ["aadhaar", "PAN", "credit-card", "cvv", "ssn", "password", "bank account information"];
  for (const cat of sensitiveFields) {
    const input = document.createElement("INPUT");
    input.setAttribute("data-pl-id", `field-${cat}`);
    input.setAttribute("data-pl-pii", cat);
    document.body.appendChild(input);

    const res = await __PL.executeAction({ action: "type", targetId: `field-${cat}`, piiCategory: cat }, "1234567890");
    assert.equal(res.ok, false);
    assert.match(res.note, /Blocked/);
    assert.equal(input.value, ""); // input was never filled
  }
});
