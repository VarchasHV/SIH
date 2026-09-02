import test from "node:test";
import assert from "node:assert/strict";
import { detectPII, verhoeffValid, luhnValid, cardIinOk, normalize } from "../client/lib/pii-rules.mjs";

const has = (t, c, opts) => detectPII(t, opts).some((h) => h.category === c);
const DEVA = "०१२३४५६७८९"; // 0-9 in Devanagari
const dev = (s) => s.replace(/[0-9]/g, (d) => DEVA[+d]);

// ---- checksums --------------------------------------------------------
test("verhoeff validates a known-good Aadhaar and rejects a bad one", () => {
  assert.equal(verhoeffValid("234567890124"), true);
  assert.equal(verhoeffValid("234567890123"), false);
  assert.equal(verhoeffValid("1234"), false);
});

test("luhn + IIN prefix", () => {
  assert.equal(luhnValid("4111 1111 1111 1111"), true);
  assert.equal(luhnValid("4111111111111112"), false);
  assert.equal(cardIinOk("4111111111111111"), true);   // Visa 16
  assert.equal(cardIinOk("378282246310005"), true);    // Amex 15
  assert.equal(cardIinOk("490154203237518"), false);   // 15 digits, not Amex -> IMEI-shaped
});

// ---- normalization ---------------------------------------------------
test("normalize folds unicode digits / dashes and keeps an offset map", () => {
  const orig = "id " + dev("1231") + "–" + "x";  // en-dash
  const { norm, map, mapEnd } = normalize(orig);
  assert.equal(norm, "id 1231-x");
  assert.equal(map.length, norm.length);
  assert.equal(mapEnd.length, norm.length);
  const i = norm.indexOf("1");
  assert.equal(orig.slice(map[i], mapEnd[i]), DEVA[1]);
});

test("Phase 6: normalize() folds every non-ASCII digit system + invisible separators", () => {
  const ARAB = "٠١٢٣٤٥٦٧٨٩", PERS = "۰۱۲۳۴۵۶۷۸۹", FW = "０１２３４５６７８９";
  const m = (map) => (s) => s.replace(/[0-9]/g, (d) => map[+d]);
  const cases = [
    [m(ARAB)("2345 6789 0124"), "arabic-indic"],
    [m(PERS)("2345 6789 0124"), "persian"],
    [m(FW)("2345 6789 0124"), "fullwidth"],
    ["2345​6789​0124", "zero-width space between digits"],
    ["2345 6789 0124", "nbsp separators"],
    ["2345‑6789‑0124", "non-breaking hyphen"],
  ];
  for (const [val, label] of cases) {
    const folded = normalize(`aadhaar ${val} ok`).norm.replace(/[\s-]/g, "");
    assert.equal(folded, "aadhaar234567890124ok", `normalize ${label}`);
    assert.ok(has(`aadhaar ${val} ok`, "aadhaar"), `detect ${label}`);
  }
});

test("Phase 6: a detector WITHOUT normalization cannot see non-ASCII digits (attribution check)", () => {
  // raw regex on the ORIGINAL string — no fold. Proves the normalize() stage,
  // not the pattern, is what recovers non-ASCII input.
  const ARAB = "٠١٢٣٤٥٦٧٨٩";
  const arabVal = ARAB.replace ? "٢٣٤٥ ٦٧٨٩ ٠١٢٤" : "";
  const rawRegex = /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/;
  assert.equal(rawRegex.test(arabVal), false, "raw ASCII-digit regex must not match Arabic digits");
  assert.equal(normalize(arabVal).norm.replace(/\s/g, ""), "234567890124");
});

test("Aadhaar detected regardless of separator", () => {
  for (const v of ["2345 6789 0124", "2345-6789-0124", "2345.6789.0124", "2345  6789  0124", "2345 - 6789 - 0124"]) {
    assert.ok(has(`my aadhaar is ${v}`, "aadhaar"), v);
  }
  assert.ok(has("aadhaar " + dev("2345 6789 0124") + " linked", "aadhaar"), "devanagari digits");
});

// ---- brief regression cases ----------------------------------------
test("REGRESSION: a 16-digit card is never partially matched as Aadhaar", () => {
  // first 12 digits pass Verhoeff; full 16 pass Luhn (Visa)
  const h = detectPII("card number 4263 9826 4026 9299 charged");
  assert.equal(h.some((x) => x.category === "aadhaar"), false);
});

test("REGRESSION (Phase 3): IPv4 dotted quads are never numeric PII (Aadhaar/card)", () => {
  // The exact case from the brief.
  const h = detectPII("IP address 164.154.182.151 server host");
  assert.equal(h.some((x) => x.category === "aadhaar"), false, "164.154.182.151 must not be aadhaar");
  assert.equal(h.some((x) => x.category === "credit-card"), false);

  const ips = [
    "10.0.0.1", "192.168.1.1", "172.16.254.3", "8.8.8.8", "1.1.1.1",
    "255.255.255.255", "203.0.113.7", "100.64.0.1", "169.254.0.1",
  ];
  for (const ip of ips) {
    for (const wrap of [`${ip}`, `connect to ${ip} now`, `host=${ip}`, `see ${ip}.`]) {
      const cats = detectPII(wrap).map((x) => x.category);
      assert.equal(cats.includes("aadhaar"), false, `${wrap}: aadhaar`);
      assert.equal(cats.includes("credit-card"), false, `${wrap}: card`);
      assert.equal(cats.includes("phone-in"), false, `${wrap}: phone`);
    }
  }
});

test("REGRESSION (Phase 3): IPv4-shaped-but-invalid, versions, ports, timestamps are not PII", () => {
  const notPii = [
    "999.999.999.999",        // octets > 255 — invalid IPv4, also not aadhaar/card
    "1.2.3.4.5",              // five groups
    "version 10.0.19045.3803", // Windows build
    "upgraded to v4.12.0.1",   // semver-ish
    "listening on 127.0.0.1:8080", // ip + port
    "2001:db8::8a2e:370:7334",  // IPv6
    "epoch 1698765432100 logged", // ms timestamp (13 digits)
    "build 20260902 shipped",
    "invoice INV-2024-000123",
  ];
  for (const t of notPii) {
    const cats = detectPII(t).map((x) => x.category);
    assert.equal(cats.includes("aadhaar"), false, `${t}: aadhaar`);
    assert.equal(cats.includes("credit-card"), false, `${t}: card`);
  }
});

test("Phase 3: dot-GROUPED Aadhaar (1234.5678.9012) is still detected", () => {
  // must not be swallowed by the IPv4 exclusion — 4-digit groups, only 3 groups
  assert.ok(has("Aadhaar 2345.6789.0124 on file", "aadhaar"));
});

test("REGRESSION: DOB requires date-of-birth context; bare dates are not flagged", () => {
  assert.ok(has("born on 14/03/1998", "dob"));
  assert.ok(has("date of birth: 03-11-2001", "dob"));
  assert.equal(has("the deadline is 14/03/1998", "dob"), false);
  assert.equal(has("meeting on 03/04/2025", "dob"), false);
});

test("REGRESSION: SSN requires positive context, not a blocklist of ID prefixes", () => {
  assert.ok(has("SSN 123-45-6789 on file", "ssn"));
  for (const p of ["case", "claim", "docket", "voucher", "manifest", "coupon", "invoice", "ticket", "PO", "confirmation"]) {
    assert.equal(has(`${p} 123-45-6789 closed`, "ssn"), false, p);
  }
});

test("REGRESSION: UPI recognises handles beyond the old 10-entry whitelist", () => {
  for (const h of ["sbi", "icici", "hdfcbank", "kotak", "yesbank", "unionbank", "airtel"]) {
    assert.ok(has(`pay to rahul@${h}`, "upi-vpa"), h);
  }
});

test("REGRESSION: IFSC validates the bank-code prefix", () => {
  assert.ok(has("IFSC SBIN0001234 for NEFT", "ifsc"));
  assert.equal(has("ref ZZZZ0001234 in manifest", "ifsc"), false);
});

test("PAN: structural 4th-char check + soft context", () => {
  assert.ok(has("PAN ABCPS1234K", "pan"));
  assert.equal(has("code ABCDS1234K exported", "pan"), false);       // 'D' not a holder type
  assert.equal(has("licence key ABCPS1234K issued", "pan"), false);  // negative context
});

test("credit card: IMEI / order numbers are not cards", () => {
  assert.equal(has("IMEI 490154203237518 blacklisted", "credit-card"), false);
  assert.equal(has("Order #4532015112830366 shipped", "credit-card"), false);
  assert.ok(has("paid with card 4111 1111 1111 1111", "credit-card"));
});

test("phone: needs +91 / leading-0 / context, not any bare 10-digit run", () => {
  assert.ok(has("call me on +91 98765 43210", "phone-in"));
  assert.ok(has("mobile 09876543210", "phone-in"));
  assert.equal(has("AWB 9876543210 dispatched", "phone-in"), false);
  assert.equal(has("transaction 12987654321098 settled", "phone-in"), false);
});

test("minConfidence:0 surfaces context-less shape matches for a 'show everything' caller", () => {
  assert.equal(has("id ABX1234567 here", "voter-id"), false);
  assert.ok(has("id ABX1234567 here", "voter-id", { minConfidence: 0 }));
});

test("returns [] for empty / non-string", () => {
  assert.deepEqual(detectPII(""), []);
  assert.deepEqual(detectPII(null), []);
});
