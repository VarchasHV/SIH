// Reversible tokenization + the local vault.
//
// Every real value the client knows about - the user's profile entries AND any
// PII detected on screen - is mapped to a stable placeholder like [AADHAAR_1].
// Only the placeholder + its category ever leave the machine. The reverse map
// (placeholder -> real value) stays in chrome.storage and is used locally to
// (a) redact text before it is sent and (b) resolve a token back to a value
// immediately before the executor types it into a field.

const CATEGORY_PREFIX = {
  "first name": "FIRSTNAME",
  "last name": "LASTNAME",
  "full name": "NAME",
  email: "EMAIL",
  "phone number": "PHONE",
  "phone-in": "PHONE",
  address: "ADDRESS",
  "postal/ZIP code": "PIN",
  "date of birth": "DOB",
  dob: "DOB",
  aadhaar: "AADHAAR",
  Aadhaar: "AADHAAR",
  pan: "PAN",
  PAN: "PAN",
  "passport number": "PASSPORT",
  "passport-in": "PASSPORT",
  ssn: "SSN",
  SSN: "SSN",
  "credit/debit card number": "CARD",
  "credit-card": "CARD",
  "CVV/security code": "CVV",
  "card expiry": "CARDEXP",
  "bank account information": "BANKACCT",
  ifsc: "IFSC",
  "upi-vpa": "UPI",
  "voter-id": "VOTERID",
  "vehicle-reg": "VEHICLE",
  gstin: "GSTIN",
  password: "PASSWORD",
  username: "USERNAME",
  "government ID": "GOVTID",
  ipv4: "IP",
  face: "FACE",
};

export function prefixFor(category) {
  return CATEGORY_PREFIX[category] || String(category || "PII").toUpperCase().replace(/[^A-Z0-9]+/g, "");
}

const norm = (v) => String(v).replace(/\s+/g, " ").trim().toLowerCase();

export class Vault {
  constructor() {
    /** @type {Map<string,{token:string,category:string,value:string,source:string}>} */
    this._byValue = new Map();
    /** @type {Map<string,{category:string,value:string,source:string}>} */
    this._byToken = new Map();
    this._counters = new Map();
  }

  _mint(category) {
    const p = prefixFor(category);
    const n = (this._counters.get(p) || 0) + 1;
    this._counters.set(p, n);
    return `[${p}_${n}]`;
  }

  /** Add one real value; returns its stable token. */
  add(value, category, source = "profile") {
    const v = String(value ?? "").trim();
    if (!v) return null;
    const key = norm(v);
    if (this._byValue.has(key)) return this._byValue.get(key).token;
    const token = this._mint(category);
    const rec = { token, category, value: v, source };
    this._byValue.set(key, rec);
    this._byToken.set(token, { category, value: v, source });
    return token;
  }

  /** Load a {category: value} profile object. */
  addProfile(profile = {}) {
    const out = {};
    for (const [category, value] of Object.entries(profile)) {
      if (value == null || value === "") continue;
      out[category] = this.add(value, category, "profile");
    }
    return out; // { category: token }
  }

  /** Load detector output: [{category, value, ...}]. */
  addDetections(detections = []) {
    for (const d of detections) {
      if (d.value) this.add(d.value, d.category, d.source || "screen");
    }
  }

  tokenForValue(value) {
    return this._byValue.get(norm(value))?.token || null;
  }

  resolve(token) {
    return this._byToken.get(token)?.value ?? null;
  }

  categoryOf(token) {
    return this._byToken.get(token)?.category ?? null;
  }

  /** Replace every known real value in `text` with its token. Longest first. */
  redactText(text) {
    if (!text) return text;
    let out = String(text);
    const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const recs = [...this._byValue.values()].sort((a, b) => b.value.length - a.value.length);
    for (const r of recs) {
      const compact = r.value.replace(/\s+/g, "");
      let pat;
      if (/^[0-9]{6,}$/.test(compact)) {
        // digit runs: tolerate any spacing between digits ("2345 6789 0124")
        pat = compact.split("").join("\\s*");
      } else {
        // other values: tolerate differing internal whitespace
        pat = esc(r.value).replace(/\s+/g, "\\s+");
      }
      out = out.replace(new RegExp(pat, "gi"), r.token);
    }
    return out;
  }

  /** Safe to transmit: token -> category only, never the value. */
  exportContext() {
    const map = {};
    for (const [token, rec] of this._byToken) map[token] = rec.category;
    return map;
  }

  /** Full serialization for chrome.storage (local only). */
  serialize() {
    return {
      byToken: [...this._byToken.entries()],
      counters: [...this._counters.entries()],
    };
  }

  static deserialize(data) {
    const v = new Vault();
    if (!data) return v;
    for (const [token, rec] of data.byToken || []) {
      v._byToken.set(token, rec);
      v._byValue.set(norm(rec.value), { token, ...rec });
    }
    for (const [k, n] of data.counters || []) v._counters.set(k, n);
    return v;
  }
}

export default { Vault, prefixFor };
