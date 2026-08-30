import test from "node:test";
import assert from "node:assert/strict";
import { classifySignals } from "../client/lib/field-classifier.mjs";

const sig = (o) => ({ tagName: "INPUT", type: "text", name: "", id: "", autocomplete: "", placeholder: "", ariaLabel: "", labelText: "", nearbyText: "", ...o });

test("conventional signals classify with high confidence", () => {
  assert.equal(classifySignals(sig({ type: "email", autocomplete: "email", name: "email" })).category, "email");
  assert.equal(classifySignals(sig({ name: "aadhaar_number" })).category, "Aadhaar");
});

test("obfuscated / truncated name attrs still match (fuzzy pass)", () => {
  assert.equal(classifySignals(sig({ name: "02frstname" })).category, "first name");
  assert.equal(classifySignals(sig({ name: "04lastname" })).category, "last name");
  assert.equal(classifySignals(sig({ name: "24emailadr" })).category, "email");
  assert.equal(classifySignals(sig({ name: "41ccnumber" })).category, "credit/debit card number");
  assert.equal(classifySignals(sig({ name: "61pers_ssn" })).category, "SSN");
  assert.equal(classifySignals(sig({ name: "23cellphon" })).category, "phone number");
  assert.equal(classifySignals(sig({ name: "62driv_lic" })).category, "government ID");
});

test("spatial caption classifies when the name is opaque", () => {
  assert.equal(classifySignals(sig({ name: "01___title_x", labelText: "First Name" })).category, "first name");
  assert.equal(classifySignals(sig({ name: "f_44", labelText: "Card User Name" })).category, "card user name");
  assert.equal(classifySignals(sig({ name: "05_company", labelText: "Company" })).category, "company");
  assert.equal(classifySignals(sig({ name: "13adr_city", labelText: "City" })).category, "city");
});

test("non-PII fields stay unclassified", () => {
  assert.equal(classifySignals(sig({ name: "q", labelText: "Search" })), null);
  assert.equal(classifySignals(sig({ name: "promo_code", labelText: "Promo Code" })), null);
  assert.equal(classifySignals(sig({ name: "quantity", labelText: "Quantity" })), null);
});
