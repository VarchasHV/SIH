// Adversarial PII benchmark corpus generator (large).
//
// Mirrors the interface of an external `independent_pii_benchmark.py`:
//   node eval/bench/gen-corpus.mjs --n-per-category 200 --n-clean 700 --n-composite 300 --seed 20260830
//
// Methodology / bias controls (also in bench/README.md):
//  - LABELS come only from generation parameters. A detector is NEVER run to
//    label anything.
//  - Every category gets BOTH:
//      * positives in ~10 surface forms (plain / space / double-space / hyphen /
//        dot / NBSP / en-dash / Devanagari digits / OCR-confusion / prefixed),
//        AND in both keyworded and keyword-free contexts (so context gating is
//        tested for recall damage, not just precision gain).
//      * hard negatives: same-SHAPE strings that are NOT that PII — SKUs, order
//        IDs, case numbers, version strings, IMEIs, coupon codes — placed with
//        misleading non-PII keywords ("order", "invoice", "case", "ref").
//  - "aadhaar-substring" regression: 16-digit cards whose first 12 digits pass
//    Verhoeff by coincidence are emitted labelled `credit-card` only.
//  - DETERMINISTIC: everything flows from --seed.
//
// Output: eval/bench/corpus.jsonl  — {id, text, spans:[{category,value,start,end}], kind}

import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { verhoeffValid, luhnValid } from "../../client/lib/pii-rules.mjs";

// ---- args ------------------------------------------------------------
const arg = (k, d) => {
  const i = process.argv.indexOf(`--${k}`);
  return i > -1 ? process.argv[i + 1] : d;
};
const N_CAT = Number(arg("n-per-category", 200));
const N_CLEAN = Number(arg("n-clean", 700));
const N_COMPOSITE = Number(arg("n-composite", 300));
const SEED = Number(arg("seed", 20260830));
const OUT = join(dirname(fileURLToPath(import.meta.url)), "corpus.jsonl");

// ---- seeded PRNG ----------------------------------------------------
function mulberry32(seed) {
  return function () {
    seed |= 0; seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const rnd = mulberry32(SEED);
const ri = (n) => Math.floor(rnd() * n);
const pick = (a) => a[ri(a.length)];
const chance = (p) => rnd() < p;
const digits = (n) => Array.from({ length: n }, () => ri(10)).join("");
const shuffle = (a) => { for (let i = a.length - 1; i > 0; i--) { const j = ri(i + 1); [a[i], a[j]] = [a[j], a[i]]; } return a; };
const LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const L = () => LETTERS[ri(26)];
const Ls = (n) => Array.from({ length: n }, L).join("");

// ---- checksums ----------------------------------------------------
const VD = [[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]];
const VP = [[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]];
const VINV = [0,4,3,2,1,5,6,7,8,9];
function verhoeffCheck(numStr) {
  let c = 0;
  const rev = ("0" + numStr).split("").reverse();
  for (let i = 0; i < rev.length; i++) c = VD[c][VP[i % 8][Number(rev[i])]];
  return VINV[c];
}
function validAadhaar() {
  const body = String(2 + ri(8)) + digits(10);
  const full = body + verhoeffCheck(body);
  return verhoeffValid(full) ? full : validAadhaar();
}
function verhoeffFail12() {
  let n; do { n = String(2 + ri(8)) + digits(11); } while (verhoeffValid(n));
  return n;
}
function luhnCheck(numNoCheck) {
  let sum = 0, dbl = true;
  for (let i = numNoCheck.length - 1; i >= 0; i--) {
    let d = Number(numNoCheck[i]); if (dbl) { d *= 2; if (d > 9) d -= 9; } sum += d; dbl = !dbl;
  }
  return (10 - (sum % 10)) % 10;
}
const CARD_IINS = [
  () => ["4" + digits(14), 16], () => ["4" + digits(11), 13],
  () => [String(51 + ri(5)) + digits(13), 16], () => [String(2221 + ri(499)) + digits(11), 16],
  () => [pick(["34", "37"]) + digits(12), 15], () => ["6011" + digits(11), 16],
  () => [pick(["60", "6521", "81", "508"]) + digits(12), 16], () => [pick(["36", "38"]) + digits(11), 14],
];
function validCard() {
  const [raw, len] = pick(CARD_IINS)();
  const body = raw.slice(0, len - 1);
  return body + luhnCheck(body);
}
function luhnValidNonCard(len = 15) {
  const body = pick(["1", "7", "8", "9"]) + digits(len - 2);
  const full = body + luhnCheck(body);
  return luhnValid(full) && !/^(4|5[1-5]|3[47]|6011|60|65|81|508|2[2-7])/.test(full) ? full : luhnValidNonCard(len);
}
// a real 16-digit card, formatted "XXXX XXXX XXXX XXXX", whose first 12 digits
// coincidentally pass Verhoeff (the aadhaar-substring regression)
function cardWithVerhoeff12Prefix() {
  for (let tries = 0; tries < 4000; tries++) {
    const c = validCard();
    if (c.length === 16 && verhoeffValid(c.slice(0, 12))) return c;
  }
  return null;
}

// ---- identifier builders ----------------------------------------
const STATE = ["01","02","03","06","07","08","09","10","19","21","22","24","27","29","32","33","36","37"];
const PAN_4TH = "ABCFGHLJPT"; // holder-type letters
const validPAN = () => Ls(3) + pick(PAN_4TH) + L() + digits(4) + L();
const nonPAN = () => Ls(3) + pick("DEIKMNOQRSUVWXYZ") + L() + digits(4) + L(); // invalid 4th char
const REAL_IFSC = ["SBIN","HDFC","ICIC","UTIB","PUNB","BARB","CNRB","IOBA","CBIN","UBIN","MAHB","KKBK","YESB","INDB","IDIB","IBKL","FDRL","RATN","DBSS","SCBL","CITI","HSBC","BKID","ANDB","CORP","SYNB","UCBA","PSIB","KARB","TMBL","DCBL","BDBL","AUBL","JAKA","SIBL","KVBL","ESFB","AIRP","PYTM","KOTA","BOTM","MSCI"];
const validIFSC = () => pick(REAL_IFSC) + "0" + (chance(0.5) ? digits(6) : Ls(2) + digits(4));
const fakeIFSC = () => { let p; do { p = Ls(4); } while (REAL_IFSC.includes(p)); return p + "0" + digits(6); };
const NPCI_HANDLES = ["oksbi","okhdfcbank","okicici","okaxis","paytm","ybl","apl","ibl","axl","upi","sbi","icici","hdfcbank","kotak","yesbank","idbi","unionbank","pnb","rbl","dbs","jio","airtel","axisbank","cnrb","indus","federal","barodampay","aubank","idfcbank","jupiteraxis","fbl","kbl","tapicici","waaxis","yapl"];
const validUPI = () => (pick(["rahul","aditi.sharma","priya93","s.kumar","meera-r","arjun","9845098450","shop.kirana","dr.rao"]) ) + "@" + pick(NPCI_HANDLES);
// non-UPI, non-email: a handle with no dotted TLD (so it is genuinely neither)
const nonUPI = () => pick(["rahul","aditya","the_team","user123","jdoe","ops"]) + "@" + pick(["github","slack","twitter","mastodon","teams","discord"]);
const validVoterId = () => Ls(3) + digits(7);
const validVehicle = () => pick(["KA","MH","DL","TN","UP","RJ","GJ","WB","AP","HR","PB","KL","OD","BR","MP"]) + String(1 + ri(38)).padStart(2, "0") + Ls(1 + ri(2)) + digits(4);
// Indian passport: [A-PR-WY] then 7 digits, 2nd char and last char non-zero
const validPassport = () => pick("ABCEFGHJKLMNPRTUVWY") + String(1 + ri(9)) + digits(5) + String(1 + ri(9));
function validSSN() {
  let a; do { a = 1 + ri(899); } while (a === 666);
  return `${String(a).padStart(3, "0")}-${String(1 + ri(99)).padStart(2, "0")}-${String(1 + ri(9999)).padStart(4, "0")}`;
}
const ssnShape = () => `${String(1 + ri(998)).padStart(3, "0")}-${String(ri(100)).padStart(2, "0")}-${String(ri(10000)).padStart(4, "0")}`;
const realIPv4 = () => `${pick([10, 172, 192, 1 + ri(223)])}.${ri(256)}.${ri(256)}.${1 + ri(254)}`;
const versionStr = () => pick([`${1 + ri(9)}.${ri(20)}.${ri(50)}.${ri(9)}`, `10.0.${10000 + ri(20000)}.${ri(999)}`, `${2 + ri(6)}.${ri(12)}.${ri(30)}.${1 + ri(200)}`]);
function validDOB() {
  const d = 1 + ri(28), m = 1 + ri(12), y = 1945 + ri(62), s = pick(["/", "-", "."]);
  return `${String(d).padStart(2, "0")}${s}${String(m).padStart(2, "0")}${s}${y}`;
}
const nonDOBDate = () => pick([`${1 + ri(12)}/${2024 + ri(5)}`, `${1 + ri(28)}/${1 + ri(12)}`, `${String(1 + ri(28)).padStart(2, "0")}-${String(1 + ri(12)).padStart(2, "0")}-${2025 + ri(4)}`]);
const validEmail = () => pick(["rahul.verma","aditi_s","p.nair24","team.hr","meera.iyer","s.k.rao","hello"]) + "@" + pick(["example.com","gmail.com","company.co.in","outlook.com","mail.org","acme.io"]);
const validGSTIN = () => pick(STATE) + validPAN() + String(1 + ri(9)) + "Z" + pick(LETTERS + "0123456789");
const gstinShape = () => pick(STATE) + nonPAN() + String(1 + ri(9)) + "Z" + pick(LETTERS + "0123456789");

// ---- surface-form rendering ------------------------------------
const DEV = "०१२३४५६७८९";
const toDev = (s) => s.replace(/[0-9]/g, (d) => DEV[+d]);
const OCR_SWAP = { "0": "O", "O": "0", "1": "I", "I": "1", "5": "S", "S": "5", "8": "B", "B": "8", "2": "Z" };
const ocrConfuse = (s) => s.replace(/[015O I58B2]/g, (c) => (chance(0.4) && OCR_SWAP[c]) ? OCR_SWAP[c] : c);
function grp(str, sizes) {
  const o = []; let i = 0;
  for (const s of sizes) { o.push(str.slice(i, i + s)); i += s; }
  if (i < str.length) o.push(str.slice(i));
  return o.filter(Boolean);
}
const SEP = { plain: "", space: " ", space2: "  ", hyphen: "-", dot: ".", nbsp: " ", endash: "–", thin: " " };
const NUM_FORMS = ["plain", "space", "space2", "hyphen", "dot", "nbsp", "endash", "deva", "ocr"];
function renderNum(d, sizes, form) {
  if (form === "deva") return toDev(grp(d, sizes).join(" "));
  if (form === "ocr") return ocrConfuse(grp(d, sizes).join(" "));
  return grp(d, sizes).join(SEP[form] ?? "");
}
const SIZES = { aadhaar: [4, 4, 4], card16: [4, 4, 4, 4], card15: [4, 6, 5], card14: [4, 6, 4], card13: [4, 4, 5], phone: [5, 5] };
const cardSizes = (n) => n === 15 ? SIZES.card15 : n === 14 ? SIZES.card14 : n === 13 ? SIZES.card13 : SIZES.card16;

// ---- contexts ---------------------------------------------------
// keyworded — a PII detector *should* be able to use these words
const KW = {
  aadhaar: ["My Aadhaar is {v}.", "Aadhaar No: {v}", "UIDAI number {v}", "aadhaar_number={v}", "link Aadhaar {v} to PAN", "{\"aadhaar\":\"{v}\"}"],
  pan: ["PAN {v} on the ITR", "Income-tax PAN: {v}", "pan_no={v}", "quote PAN {v}", "permanent account number {v}"],
  gstin: ["GSTIN {v} registered", "our GST number is {v}", "gstin: {v}", "tax invoice GSTIN {v}"],
  ifsc: ["IFSC {v} for NEFT", "branch IFSC code {v}", "beneficiary IFSC {v}", "RTGS to IFSC {v}"],
  "upi-vpa": ["pay me at UPI {v}", "UPI ID: {v}", "send via VPA {v}", "pay to {v} on GPay", "collect request to {v}"],
  "voter-id": ["EPIC {v} on the electoral roll", "Voter ID {v}", "elector photo identity card {v}", "voter {v} assigned to booth 12"],
  "vehicle-reg": ["vehicle registration {v}", "RC number {v}", "car reg {v} challan", "number plate {v}"],
  "passport-in": ["Passport {v} expires 2031", "passport no {v}", "travel document {v}", "submit passport {v} at PSK"],
  "credit-card": ["Card {v} charged Rs 4299", "pay with card {v}", "credit card number: {v}", "cc={v}", "{\"card\":\"{v}\"}"],
  "phone-in": ["call me on {v}", "mobile: {v}", "phone {v}", "WhatsApp {v}", "reach {v} anytime"],
  ssn: ["SSN {v} on file", "social security number {v}", "ssn: {v}"],
  ipv4: ["server IP {v} responded", "whitelist the IP address {v}", "host {v} is unreachable"],
  dob: ["born on {v} in Pune", "DOB {v}", "date of birth: {v}", "d.o.b {v}"],
  email: ["write to {v}", "email: {v}", "contact e-mail {v}"],
};
// keyword-FREE — the value dropped into neutral prose (tests recall of context gates)
const NOKW = ["Here it is: {v}", "Noted — {v} — thanks.", "{v}", "reference {v} for later", "see {v} below", "({v})", "value {v}"];

// ---- hard negatives per category -------------------------------
function negFor(cat) {
  const orderCtx = ["Order #{v} dispatched", "invoice {v} paid", "case file {v}", "claim {v} approved", "docket {v}", "voucher {v} redeemed", "manifest {v}", "coupon {v}", "PO {v}", "confirmation {v}", "ticket {v} closed", "SKU {v} in stock", "batch {v}", "serial {v}", "ref {v}"];
  const wrap = (v) => pick(orderCtx).replace("{v}", v);
  switch (cat) {
    case "aadhaar": return chance(0.5)
      ? wrap(renderNum(verhoeffFail12(), SIZES.aadhaar, pick(["space", "hyphen", "plain"])))
      : `shipment ${digits(13 + ri(3))} cleared customs`;
    case "credit-card": return chance(0.5)
      ? pick(["IMEI {v}", "device IMEI: {v}", "handset {v} blacklisted"]).replace("{v}", luhnValidNonCard(15))
      : wrap(digits(16).replace(/(\d{4})(\d{4})(\d{4})(\d{4})/, "$1 $2 $3 $4"));
    case "phone-in": return chance(0.4)
      ? wrap(String(6 + ri(4)) + digits(9))
      : `transaction ${digits(2)}${String(6 + ri(4))}${digits(9)} settled`;
    case "pan": return wrap(nonPAN());
    case "gstin": return wrap(gstinShape());
    case "ifsc": return wrap(fakeIFSC());
    case "upi-vpa": return pick(["mention @{v} in the thread", "handle {v}", "{v} on GitHub"]).replace("{v}", nonUPI());
    case "voter-id": return wrap(Ls(3) + digits(7));
    case "vehicle-reg": return wrap(Ls(2) + String(ri(99)).padStart(2, "0") + Ls(2) + digits(4));
    case "passport-in": return wrap(L() + digits(7));
    case "ssn": return wrap(ssnShape());
    case "ipv4": return pick(["upgraded to version {v}", "build {v}", "firmware {v}", "running {v} on prod"]).replace("{v}", versionStr());
    case "dob": return pick(["card expires {v}", "meeting on {v}", "deadline {v}", "fiscal year {v}", "due {v}", "released {v}"]).replace("{v}", nonDOBDate());
    case "email": return pick(["path is a@b", "see foo@bar in the log", "{v}"]).replace("{v}", pick(["not.an.email@", "@handle", "a@b"]));
    default: return "nothing to see here";
  }
}

// ---- clean sentences -----------------------------------------
const CLEAN = [
  "The quarterly review meeting is scheduled for next Tuesday afternoon.",
  "Please find the attached report and share your feedback by Friday.",
  "Our office will remain closed during the festival week.",
  "The shipment left the warehouse and should arrive within three days.",
  "She presented the product roadmap to the leadership team this morning.",
  "Total revenue grew by 12 percent compared to the previous year.",
  "Add two cups of flour and a pinch of salt, then mix well.",
  "The new bridge spans roughly 2 kilometres across the river.",
  "Chapter 7 covers the early history of the printing press.",
  "Room 214 is on the second floor near the elevator.",
  "Flight AI-302 was delayed by forty minutes due to weather.",
  "We onboarded 8 engineers and 3 designers this quarter.",
  "The invoice total came to 45000 rupees before tax.",
  "Version 3 of the mobile app ships to the store next month.",
  "The workshop runs from 10 am to 4 pm with a lunch break.",
  "Rainfall this month was well above the seasonal average.",
  "The library added 1,200 new titles to its catalogue.",
  "Turn left at the second signal and the cafe is on your right.",
  "The committee will reconvene after the budget is approved.",
  "Battery life improved by about 20 percent in the latest firmware.",
  "The marathon route passes three heritage sites downtown.",
  "Our support hours are 9 to 6 on weekdays.",
  "The prototype weighs under 500 grams including the casing.",
  "He scored 78 out of 100 on the practice test.",
  "The garden needs watering twice a week in summer.",
];

// ---- assembly ------------------------------------------------
let idc = 0;
const samples = [];
function emitPos(category, value, tpl, kind) {
  const marker = "";
  let text = tpl.replace("{v}", marker);
  const at = text.indexOf(marker);
  text = text.slice(0, at) + value + text.slice(at + 1);
  samples.push({ id: `s${++idc}`, text, spans: [{ category, value, start: at, end: at + value.length }], kind });
}
function emitNeg(kind, text) { samples.push({ id: `s${++idc}`, text, spans: [], kind }); }

const ALNUM_GEN = {
  pan: validPAN, gstin: validGSTIN, ifsc: validIFSC, "upi-vpa": validUPI,
  "voter-id": validVoterId, "vehicle-reg": validVehicle, "passport-in": validPassport,
  email: validEmail, ssn: validSSN, ipv4: realIPv4, dob: validDOB,
};

for (const cat of ["aadhaar", "credit-card", "phone-in", ...Object.keys(ALNUM_GEN)]) {
  const nPos = N_CAT;
  const nNeg = Math.round(N_CAT * 0.8);
  for (let k = 0; k < nPos; k++) {
    let value;
    if (cat === "aadhaar") value = renderNum(validAadhaar(), SIZES.aadhaar, pick(NUM_FORMS));
    else if (cat === "credit-card") { const c = validCard(); value = pick(NUM_FORMS) === "deva" ? toDev(c) : renderNum(c, cardSizes(c.length), pick(NUM_FORMS)); }
    else if (cat === "phone-in") {
      let p = renderNum(String(6 + ri(4)) + digits(9), SIZES.phone, pick(NUM_FORMS));
      if (chance(0.5)) p = pick(["+91 ", "+91-", "0", "91 ", "+91"]) + p;
      value = p;
    } else {
      value = ALNUM_GEN[cat]();
    }
    // ~15% of alphanumeric IDs get OCR-garbled (letter<->digit confusions) - a
    // real failure mode for a tool that reads screenshots. Tracked separately.
    let ocr = false;
    if (["pan", "voter-id", "passport-in", "ifsc", "gstin", "vehicle-reg"].includes(cat) && chance(0.15)) { value = ocrConfuse(value); ocr = true; }
    // ~78% of real-world PII appears near a category keyword or in a labelled
    // field; ~22% bare. Context-gated categories will legitimately miss most of
    // the bare set - that is the precision/recall trade the brief accepts.
    const kw = chance(0.78);
    const tpl = kw ? pick(KW[cat]) : pick(NOKW);
    emitPos(cat, value, tpl, `pos:${cat}:${ocr ? "ocr" : kw ? "kw" : "bare"}`);
  }
  for (let k = 0; k < nNeg; k++) emitNeg(`neg:${cat}`, negFor(cat));
}

// aadhaar-substring regression: cards with Verhoeff-passing 12-prefix
let subCount = 0;
for (let k = 0; k < 60; k++) {
  const c = cardWithVerhoeff12Prefix();
  if (!c) break;
  subCount++;
  emitPos("credit-card", grp(c, SIZES.card16).join(" "), pick(KW["credit-card"]), "pos:credit-card:verhoeff12-regression");
}

// composite / multi-PII
const MULTI = [
  "KYC for {p0}: Aadhaar {a}, PAN {p}, mobile {m}.",
  "Payment from card {c} to UPI {u}; receipt to {e}.",
  "Applicant {p0} — DOB {d}, phone {m}, email {e}.",
  "Bank details: IFSC {i}, and for UPI use {u}.",
  "Passport {pa} and Aadhaar {a} attached for {p0}.",
];
for (let k = 0; k < N_COMPOSITE; k++) {
  const tpl = pick(MULTI);
  const val = {
    p0: pick(["Aditi Sharma", "Rahul Verma", "Meera Iyer", "Arjun Nair", "S. K. Rao"]),
    a: renderNum(validAadhaar(), SIZES.aadhaar, pick(["space", "hyphen", "plain", "dot"])),
    p: validPAN(), m: (chance(0.5) ? "+91 " : "") + String(6 + ri(4)) + digits(9),
    c: grp(validCard(), SIZES.card16).join(pick([" ", "", "-"])), u: validUPI(), e: validEmail(),
    d: validDOB(), i: validIFSC(), pa: validPassport(),
  };
  const catOf = { a: "aadhaar", p: "pan", m: "phone-in", c: "credit-card", u: "upi-vpa", e: "email", d: "dob", i: "ifsc", pa: "passport-in" };
  let text = tpl;
  for (const key of Object.keys(val)) text = text.replace(`{${key}}`, val[key]);
  const spans = [];
  let cursor = 0;
  for (const key of Object.keys(val).sort((x, y) => tpl.indexOf(`{${x}}`) - tpl.indexOf(`{${y}}`))) {
    if (!catOf[key]) continue;
    const idx = text.indexOf(val[key], cursor);
    if (idx === -1) continue;
    spans.push({ category: catOf[key], value: val[key], start: idx, end: idx + val[key].length });
    cursor = idx + val[key].length;
  }
  samples.push({ id: `s${++idc}`, text, spans, kind: "pos:composite" });
}

// clean
for (let k = 0; k < N_CLEAN; k++) {
  const n = 1 + ri(3);
  emitNeg("neg:clean", Array.from({ length: n }, () => pick(CLEAN)).join(" "));
}

// ---- write --------------------------------------------------
shuffle(samples);
writeFileSync(OUT, samples.map((s) => JSON.stringify(s)).join("\n") + "\n");

const byCat = {};
for (const s of samples) for (const sp of s.spans) byCat[sp.category] = (byCat[sp.category] || 0) + 1;
const pos = samples.filter((s) => s.spans.length).length;
let offErr = 0;
for (const s of samples) for (const sp of s.spans) if (s.text.slice(sp.start, sp.end) !== sp.value) offErr++;
console.log(`seed=${SEED}  n-per-category=${N_CAT}  n-clean=${N_CLEAN}  n-composite=${N_COMPOSITE}`);
console.log(`wrote ${samples.length} samples → ${OUT}`);
console.log(`  positive lines ${pos} · negative lines ${samples.length - pos} · gold spans ${samples.reduce((n, s) => n + s.spans.length, 0)}`);
console.log(`  aadhaar-substring regression cards: ${subCount}`);
console.log(`  span offset errors: ${offErr}`);
console.log(`  gold spans / category:`, byCat);
