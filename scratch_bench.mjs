import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { classifySignals } from "./client/lib/field-classifier.mjs";
import { detectPII } from "./client/lib/pii-rules.mjs";
import { mergeDetections } from "./client/lib/merge.mjs";
import { redactCanvas } from "./client/lib/redact.mjs";
import { validatePlan, validateAction } from "./client/lib/agent-client.mjs";

const FIXTURES = ["job-application.html", "checkout.html", "kyc.html", "hostile-form.html"];

function extractFields(html) {
  const fields = [];
  const tagRe = /<(input|select|textarea)\b([^>]*)>/gi;
  let m, i = 0;
  while ((m = tagRe.exec(html))) {
    const attrs = {};
    for (const a of m[2].matchAll(/([\w-]+)\s*=\s*"([^"]*)"/g)) attrs[a[1].toLowerCase()] = a[2];
    const before = html.slice(0, m.index);
    const lbl = before.match(/<label[^>]*>([^<]*)<[^>]*$/i);
    const caps = [...before.matchAll(/>\s*([A-Za-z][^<>]{1,58}?)\s*<\/(?:div|td|th|label|span|dt|p)>/g)];
    const labelText = (lbl && lbl[1].trim()) || (caps.length ? caps[caps.length - 1][1].trim() : "");
    fields.push({
      id: `el-${++i}`,
      tagName: m[1].toLowerCase(),
      type: attrs.type || "",
      name: attrs.name || "",
      idAttr: attrs.id || "",
      autocomplete: attrs.autocomplete || "",
      placeholder: attrs.placeholder || "",
      ariaLabel: attrs["aria-label"] || "",
      labelText,
      gt: attrs["data-gt"] || "",
    });
  }
  return fields;
}

async function benchmark() {
  console.log("=== PRIVACY LENS INSTRUMENTATION & BENCHMARK SUITE ===");
  
  // 1. DOM Skeleton & Classifier benchmark
  console.log("\n--- 1. DOM Skeleton & Field Classification Timing ---");
  for (const f of FIXTURES) {
    const html = await readFile(join("fixtures", f), "utf8");
    const fields = extractFields(html);
    const times = [];
    for (let r = 0; r < 200; r++) {
      const t0 = performance.now();
      for (const field of fields) {
        classifySignals(field);
      }
      times.push(performance.now() - t0);
    }
    const avg = times.reduce((a, b) => a + b, 0) / times.length;
    console.log(`  ${f.padEnd(22)} (${fields.length} fields): avg ${avg.toFixed(3)}ms (min ${Math.min(...times).toFixed(3)}ms, max ${Math.max(...times).toFixed(3)}ms)`);
  }

  // 2. PII Rules / Regex Detection Timing
  console.log("\n--- 2. On-device Regex & PII Rules Timing ---");
  const testTexts = [
    "Contact: Aditi Sharma, Phone: +91 9876543210, Email: aditi.sharma@example.com",
    "Aadhaar: 2345 6789 0124, PAN: ABCPS1234K, DOB: 14/03/1998, Address: 42 Nehru Road",
    "Card: 4111 1111 1111 1111, CVV: 123, SSN: 123-45-6789, IFSC: SBIN0001234",
  ];
  for (let i = 0; i < testTexts.length; i++) {
    const txt = testTexts[i];
    const times = [];
    for (let r = 0; r < 500; r++) {
      const t0 = performance.now();
      detectPII(txt);
      times.push(performance.now() - t0);
    }
    const avg = times.reduce((a, b) => a + b, 0) / times.length;
    console.log(`  Sample ${i+1} (${txt.length} chars): avg ${avg.toFixed(4)}ms`);
  }

  // 3. Plan Validation Timing
  console.log("\n--- 3. Plan Validation Timing ---");
  const sampleActions = [
    { action: "type", targetId: "el-1", piiCategory: "full name" },
    { action: "type", targetId: "el-2", piiCategory: "email" },
    { action: "type", targetId: "el-3", piiCategory: "phone number" },
    { action: "type", targetId: "el-4", piiCategory: "address" },
  ];
  const knownIds = new Set(["el-1", "el-2", "el-3", "el-4", "el-5"]);
  const valTimes = [];
  for (let r = 0; r < 500; r++) {
    const t0 = performance.now();
    validatePlan(sampleActions, knownIds);
    valTimes.push(performance.now() - t0);
  }
  console.log(`  validatePlan (4 actions): avg ${(valTimes.reduce((a,b)=>a+b,0)/valTimes.length).toFixed(4)}ms`);
}

benchmark();
