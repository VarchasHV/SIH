// Phase 8 — synthetic screen corpus with ground-truth bounding boxes.
//
//   node eval/screens/gen-screens.mjs --seed 20260902 [--n 12]
//
// IMPORTANT — what this is and is NOT:
//   * Each screen is a LAYOUT SPEC: a list of text/field elements with a bbox
//     (px, at the given viewport) and a ground-truth PII label. Boxes and text
//     are DECLARED — there is no real browser render and no real OCR pass in
//     this environment (no headless Chromium / Playwright installed).
//   * score.mjs treats the declared text as a perfect OCR read (the optimistic
//     ceiling) and the declared field types as the DOM channel, then runs the
//     REAL detectPII + mergeDetections + redaction-region logic and scores the
//     geometry against the ground-truth boxes.
//   * Real end-to-end numbers would be LOWER: multiply by the OCR recall from
//     eval/bench (ASCII 91%, OCR-garbled 16%) and real ViT/face recall.
//   * This measures the FUSION + REDACTION GEOMETRY honestly; it does not
//     measure OCR or rendering. Those are marked NOT EXECUTED.

import { writeFileSync, mkdirSync } from "node:fs";
import { execSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import {
  makeRng, genAadhaar, genCard, genPAN, genSSN, genIFSC, genIPv4,
} from "../bench/lib/independent-validators.mjs";

const arg = (k, d) => { const i = process.argv.indexOf(`--${k}`); return i > -1 ? process.argv[i + 1] : d; };
const SEED = Number(arg("seed", 20260902));
const HERE = dirname(fileURLToPath(import.meta.url));
const rng = makeRng(SEED);
const ri = (n) => Math.floor(rng() * n);
const pick = (a) => a[ri(a.length)];
const grp4 = (s) => s.replace(/(\d{4})(?=\d)/g, "$1 ");

const NAMES = ["Aditi Sharma", "Rahul Verma", "Meera Iyer", "Arjun Nair", "Sana Khan"];
const EMAILS = ["aditi.sharma@example.com", "r.verma@mail.co.in", "meera@acme.io"];
const PHONES = () => "+91 " + (6 + ri(4)) + String(ri(1e9)).padStart(9, "0");
const ADDR = ["42 Nehru Road, Bengaluru 560001", "7B Park Street, Kolkata 700016"];

// element helpers: {id, kind, text, bbox, pii}
// kind: "label" | "field" (a form input; contributes to the DOM channel) | "static" | "image"
// pii:  null | { category, value }
let eid = 0;
const el = (kind, text, x, y, w, h, pii = null) => ({ id: `e${++eid}`, kind, text, bbox: { x, y, w, h }, pii });

function loginScreen(theme) {
  const vw = 1280, vh = 800;
  const els = [
    el("static", "Sign in to your account", 480, 120, 320, 32),
    el("label", "Email", 490, 200, 80, 20),
    el("field", pick(EMAILS), 490, 224, 300, 40, { category: "email", value: null }),
    el("label", "Password", 490, 284, 100, 20),
    el("field", "••••••••••", 490, 308, 300, 40, { category: "password", value: "S3cr3tPass!" }),
    el("static", "Forgot password?", 490, 364, 140, 18),
  ];
  els[2].pii.value = els[2].text;
  return { name: `login-${theme}`, type: "login", viewport: { w: vw, h: vh }, theme, fontScale: 1, elements: els };
}

function bankingScreen(theme, scale) {
  const acc = String(ri(1e10)).padStart(11, "0");
  const els = [
    el("static", "Account overview", 60, 60, 300, 30),
    el("label", "Account holder", 60, 130, 160, 20),
    el("static", pick(NAMES), 260, 130, 240, 20, { category: "name", value: null }),
    el("label", "Account number", 60, 170, 160, 20),
    el("static", acc, 260, 170, 240, 20, { category: "bank-account", value: acc }),
    el("label", "IFSC", 60, 210, 160, 20),
    el("static", genIFSC(rng), 260, 210, 200, 20, { category: "ifsc", value: null }),
    el("label", "Registered mobile", 60, 250, 200, 20),
    el("static", PHONES(), 260, 250, 240, 20, { category: "phone-in", value: null }),
    el("static", "Available balance ₹ 84,210.55", 60, 320, 380, 24),
    el("static", `Last login from ${genIPv4(rng)}`, 60, 360, 420, 20), // adversarial: IPv4, not PII to redact
  ];
  els[2].pii.value = els[2].text;
  els[6].pii.value = els[6].text;
  els[8].pii.value = els[8].text;
  return { name: `banking-${theme}`, type: "banking", viewport: { w: 1280, h: 900 }, theme, fontScale: scale, elements: els };
}

function checkoutScreen() {
  const card = genCard(rng);
  const els = [
    el("static", "Payment details", 400, 80, 260, 28),
    el("label", "Cardholder name", 400, 150, 180, 20),
    el("field", pick(NAMES), 400, 174, 320, 40, { category: "name", value: null }),
    el("label", "Card number", 400, 234, 180, 20),
    el("field", grp4(card), 400, 258, 320, 40, { category: "credit-card", value: grp4(card) }),
    el("label", "CVV", 400, 318, 80, 20),
    el("field", String(100 + ri(900)), 400, 342, 90, 40, { category: "cvv", value: null }),
    el("label", "Billing address", 400, 402, 180, 20),
    el("field", pick(ADDR), 400, 426, 320, 60, { category: "address", value: null }),
    el("static", "Order #ORD-2026-778120", 400, 500, 260, 18), // adversarial: order id
  ];
  els[2].pii.value = els[2].text;
  els[6].pii.value = els[6].text;
  els[8].pii.value = els[8].text;
  return { name: "checkout-payment", type: "checkout", viewport: { w: 1280, h: 800 }, theme: "light", fontScale: 1, elements: els };
}

function kycScreen(scale) {
  const aad = genAadhaar(rng), pan = genPAN(rng);
  const els = [
    el("static", "KYC verification", 60, 50, 260, 28),
    el("label", "Full name", 60, 120, 140, 20),
    el("field", pick(NAMES), 220, 120, 280, 36, { category: "name", value: null }),
    el("label", "Aadhaar number", 60, 172, 160, 20),
    el("field", grp4(aad), 220, 172, 280, 36, { category: "aadhaar", value: grp4(aad) }),
    el("label", "PAN", 60, 224, 140, 20),
    el("field", pan, 220, 224, 280, 36, { category: "pan", value: pan }),
    el("label", "Date of birth", 60, 276, 160, 20),
    el("field", `${1 + ri(28)}/${1 + ri(12)}/199${ri(9)}`, 220, 276, 200, 36, { category: "dob", value: null }),
    el("image", "[uploaded ID photo]", 60, 340, 220, 140, { category: "id-document", value: null }),
    el("image", "[applicant selfie — face]", 300, 340, 160, 140, { category: "face", value: null }),
  ];
  els[2].pii.value = els[2].text;
  els[8].pii.value = els[8].text;
  return { name: "kyc-onboarding", type: "government-form", viewport: { w: 1280, h: 900 }, theme: "light", fontScale: scale, elements: els };
}

function invoiceScreen() {
  const els = [
    el("static", "TAX INVOICE", 60, 40, 200, 26),
    el("static", "Bill to:", 60, 100, 100, 18),
    el("static", pick(NAMES), 60, 122, 240, 18, { category: "name", value: null }),
    el("static", pick(ADDR), 60, 144, 320, 18, { category: "address", value: null }),
    el("static", "Invoice No: INV-778/2026-27", 700, 100, 260, 18),  // adversarial
    el("static", "GSTIN: 29ABCDE1234F1Z5", 700, 122, 260, 18, { category: "gstin", value: "29ABCDE1234F1Z5" }),
    el("static", "SKU ECI-1462280 x 3", 60, 220, 220, 18),  // adversarial
    el("static", "Amount due ₹ 12,499.00", 60, 260, 240, 20),
    el("static", `Support: ${EMAILS[0]}`, 60, 300, 320, 18, { category: "email", value: EMAILS[0] }),
  ];
  els[2].pii.value = els[2].text;
  els[3].pii.value = els[3].text;
  return { name: "invoice", type: "invoice", viewport: { w: 1024, h: 768 }, theme: "light", fontScale: 1, elements: els };
}

function profileScreen(theme) {
  // mobile viewport: single column, everything within 375px
  const els = [
    el("static", "My profile", 16, 40, 200, 28),
    el("label", "Name", 16, 100, 120, 18),
    el("static", pick(NAMES), 16, 120, 340, 22, { category: "name", value: null }),
    el("label", "Email", 16, 160, 120, 18),
    el("static", pick(EMAILS), 16, 180, 340, 22, { category: "email", value: null }),
    el("label", "Phone", 16, 220, 120, 18),
    el("static", PHONES(), 16, 240, 340, 22, { category: "phone-in", value: null }),
    el("label", "Member since", 16, 280, 140, 18),
    el("static", "March 2021", 16, 300, 200, 20),  // not PII
    el("static", "Theme preference: " + theme, 16, 340, 300, 18),  // not PII
  ];
  els[2].pii.value = els[2].text;
  els[4].pii.value = els[4].text;
  els[6].pii.value = els[6].text;
  return { name: `profile-${theme}`, type: "profile", viewport: { w: 375, h: 812 }, theme, fontScale: 1, elements: els };
}

function cleanScreen() {
  return {
    name: "dashboard-clean", type: "dashboard", viewport: { w: 1280, h: 800 }, theme: "dark", fontScale: 1,
    elements: [
      el("static", "Weekly metrics", 60, 60, 240, 28),
      el("static", "Active users: 12,480", 60, 120, 240, 20),
      el("static", "Revenue: ₹ 4.2L", 60, 150, 240, 20),
      el("static", "Deploys this week: 7", 60, 180, 240, 20),
      el("static", "Build 20260902.3 · region asia-south1", 60, 220, 360, 18),
      el("static", "Next review: Tuesday 3pm", 60, 260, 300, 18),
    ],
  };
}

const screens = [
  loginScreen("light"), loginScreen("dark"),
  bankingScreen("light", 1), bankingScreen("dark", 1.25),
  checkoutScreen(),
  kycScreen(1), kycScreen(1.4),
  invoiceScreen(),
  profileScreen("light"), profileScreen("dark"),
  cleanScreen(),
];

// verify every declared box is inside its viewport and text is non-empty
let boxErr = 0;
for (const s of screens) for (const e of s.elements) {
  if (!e.text || e.bbox.x < 0 || e.bbox.y < 0 || e.bbox.x + e.bbox.w > s.viewport.w + 1 || e.bbox.y + e.bbox.h > s.viewport.h + 1) boxErr++;
}

mkdirSync(HERE, { recursive: true });
const OUT = join(HERE, "screens.jsonl");
writeFileSync(OUT, screens.map((s) => JSON.stringify(s)).join("\n") + "\n");

let gitCommit = null;
try { gitCommit = execSync("git rev-parse --short HEAD", { cwd: HERE }).toString().trim(); } catch {}
const piiEls = screens.reduce((n, s) => n + s.elements.filter((e) => e.pii).length, 0);
writeFileSync(join(HERE, "screens.manifest.json"), JSON.stringify({
  seed: SEED, generatedAt: new Date().toISOString(), gitCommit, nodeVersion: process.version,
  screens: screens.length,
  screenTypes: [...new Set(screens.map((s) => s.type))],
  elements: screens.reduce((n, s) => n + s.elements.length, 0),
  piiElements: piiEls,
  themes: [...new Set(screens.map((s) => s.theme))],
  viewports: [...new Set(screens.map((s) => `${s.viewport.w}x${s.viewport.h}`))],
  boxErrors: boxErr,
  disclaimer: "Layout specs only. No real browser render, no real OCR in this environment. score.mjs measures fusion + redaction geometry, not OCR or rendering.",
}, null, 2) + "\n");

console.log(`wrote ${screens.length} screens (${piiEls} PII elements) -> ${OUT}`);
console.log(`box errors: ${boxErr}`);
if (boxErr) process.exit(1);
