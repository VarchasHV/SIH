// Single source of truth for sensitive field categorization across the entire Privacy Lens pipeline.
//
// ARCHITECTURE & SCOPE ISOLATION:
// 1. RESTRICTED_PII_CATEGORIES (CENSORED_CATEGORIES): High-risk secrets (Aadhaar, PAN, SSN, Credit Cards, CVV,
//    Passwords, Credentials, 2FA/OTP, Auth Tokens, API Keys, SSH Keys, Bank Accounts, Passports).
//    These are marked `isCensored: true` and are STRICTLY BLOCKED from being sent to or filled by the LLM.
//
// 2. ALWAYS_REDACT_CATEGORIES: Credential and secret categories that must be unconditionally redacted in
//    both the visual channel (solid blackout on canvas) and the structural DOM/skeleton channel regardless
//    of classifier confidence score.
//
// 3. PROFILE_PII_CATEGORIES: Non-secret PII (Name, Email, Phone, Address, DOB, Gender, etc.).
//    - Real values are NEVER sent to the VLM (scrubbed from skeleton / blacked out in screenshot).
//    - The skeleton carries abstract piiCategory tags and hasFill indicators (or tokens).
//    - When the VLM returns an action (e.g. type targetId="inp1", piiCategory="first name"), the client extension
//      resolves the value LOCALLY from chrome.storage.local profile and types it directly in the browser!

export const RESTRICTED_PII_CATEGORIES = new Set([
  "password",
  "credential", "credentials", "autofill_credential", "autofill",
  "otp", "2fa", "mfa", "totp", "one-time-code",
  "auth_token", "api_key", "secret", "ssh_key", "session_token", "access_token", "security_key",
  "aadhaar", "Aadhaar",
  "pan", "PAN",
  "ssn", "SSN",
  "credit-card", "credit/debit card number", "credit_card", "debit_card", "card number",
  "cvv", "CVV/security code", "cvc", "security code",
  "card expiry", "expiration date", "card expiration", "expiry",
  "bank account information", "bank account", "account number", "routing number", "iban", "swift", "bic",
  "passport number", "passport", "passport-in",
  "government ID", "government_id", "govt_id", "national_id",
  "driver license", "driver's license", "drivers_license", "driving license",
  "ifsc", "IFSC",
  "upi-vpa", "upi",
  "gstin", "GSTIN",
  "sensitive",
  "adversarial_injection", "prompt_injection", "quarantined_threat", "steganographic_text",
]);

export const CENSORED_CATEGORIES = RESTRICTED_PII_CATEGORIES;

export const ALWAYS_REDACT_CATEGORIES = new Set([
  "password",
  "credential", "credentials", "autofill_credential", "autofill",
  "otp", "2fa", "mfa", "totp", "one-time-code",
  "auth_token", "api_key", "secret", "ssh_key", "session_token", "access_token", "security_key",
  "credit-card", "credit/debit card number", "credit_card", "debit_card", "card number",
  "cvv", "CVV/security code", "cvc", "security code",
  "aadhaar", "Aadhaar",
  "pan", "PAN",
  "ssn", "SSN",
  "bank account information", "bank account", "account number",
  "passport number", "passport", "passport-in",
]);

export const CREDENTIAL_CATEGORIES = new Set([
  "password",
  "credential", "credentials", "autofill_credential", "autofill",
  "otp", "2fa", "mfa", "totp", "one-time-code",
  "auth_token", "api_key", "secret", "ssh_key", "session_token", "access_token", "security_key",
]);

export const PROFILE_PII_CATEGORIES = new Set([
  "first name", "firstname",
  "middle initial", "middle name", "middle_name",
  "last name", "lastname", "surname", "family name",
  "full name", "fullname", "name",
  "date of birth", "dob", "birth date", "birthday",
  "age", "birth place", "place of birth",
  "sex / gender", "gender", "sex",
  "title", "salutation",
  "address", "street address", "address line 1", "address line 2",
  "city", "state", "province", "state/province", "region", "country",
  "postal/ZIP code", "zipcode", "zip code", "zip", "postal code", "pincode", "pin code", "postcode",
  "phone number", "phone", "mobile", "cell phone", "home phone", "work phone", "telephone", "fax", "phone-in",
  "email", "email address",
  "username", "user id", "login id",
  "web site", "website", "url",
  "company", "organization", "employer",
  "position", "job title", "occupation", "designation",
  "income", "salary",
]);

export const SENSITIVE_PATTERNS = new RegExp(
  [
    // Auth, Credentials & Session Secrets
    "password", "passcode", "passwd", "\\bpwd\\b",
    "credential", "credentials", "autofill",
    "\\botp\\b", "\\b2fa\\b", "\\bmfa\\b", "\\btotp\\b", "one[\\s_]?time[\\s_]?code", "auth[\\s_]?code", "verification[\\s_]?code",
    "auth[\\s_]?token", "api[\\s_]?key", "apikey", "ssh[\\s_]?key", "bearer", "access[\\s_]?token", "session[\\s_]?token", "secret[\\s_]?key",

    // Government & National Identifiers
    "aadhaar", "aadhar", "uidai", "\\buid\\b",
    "\\bpan\\b", "pannumber", "pancard", "permanent[\\s_]?account",
    "\\bssn\\b", "social[\\s_]?security",
    "passport", "voter[\\s_]?id", "\\bepic\\b",
    "govt[\\s_]?id", "govtid", "government[\\s_]?id", "national[\\s_]?id", "state[\\s_]?id",
    "driver[\\s_]?license", "drivers[\\s_]?license", "driving[\\s_]?license", "driv_?lic", "dl[\\s_]?num", "license[\\s_]?no",
    "gstin", "\\bgst\\b",

    // Financial & Payment Data
    "credit[\\s_]?card", "debit[\\s_]?card", "card[\\s_]?num", "card[\\s_]?type", "cc[\\s_]?num",
    "\\bcvv\\b", "\\bcvc\\b", "security[\\s_]?code", "card[\\s_]?sec", "csc",
    "card[\\s_]?exp", "expir", "expiry", "exp[\\s_]?date",
    "card[\\s_]?user", "cardholder", "name[\\s_]?on[\\s_]?card",
    "bank[\\s_]?account", "\\bbank\\b", "account[\\s_]?no", "account[\\s_]?number", "routing", "\\biban\\b", "\\bswift\\b",
    "\\bifsc\\b", "\\bupi\\b", "\\bvpa\\b",
    "\\bincome\\b", "\\bsalary\\b",

    // Personal & Demographics
    "first[\\s_]?name", "fname", "given[\\s_]?name",
    "middle[\\s_]?name", "middle[\\s_]?initial", "mname",
    "last[\\s_]?name", "lname", "surname", "family[\\s_]?name",
    "full[\\s_]?name", "\\bname\\b",
    "\\bdob\\b", "birth[\\s_]?date", "date[\\s_]?of[\\s_]?birth", "birthday",
    "\\bage\\b", "birth[\\s_]?place", "gender", "\\bsex\\b", "\\btitle\\b",

    // Contact & Location Data
    "address", "street", "addr", "addr1", "addr2", "residence",
    "\\bcity\\b", "\\bstate\\b", "province", "country",
    "zip", "postal", "pincode", "pin[\\s_]?code", "postcode", "zipcode",
    "phone", "mobile", "cell[\\s_]?phone", "telephone", "homephone", "workphone", "\\btel\\b", "\\bfax\\b",
    "email", "e-mail", "mail[\\s_]?addr",

    // Digital & Employment
    "ipv4", "ip[\\s_]?address",
    "username", "user[\\s_]?id", "login[\\s_]?id", "usrname",
    "web[\\s_]?site", "website", "\\burl\\b",
    "company", "organization", "employer",
    "position", "job[\\s_]?title", "occupation", "designation",

    // Miscellaneous
    "vehicle", "registration[\\s_]?no", "license[\\s_]?plate",
    "comment", "message", "feedback", "notes",
  ].join("|"),
  "i"
);

export function isRestrictedCategory(cat) {
  if (!cat) return false;
  return RESTRICTED_PII_CATEGORIES.has(cat);
}

export function isCredentialCategory(cat) {
  if (!cat) return false;
  return CREDENTIAL_CATEGORIES.has(cat);
}

export function isAlwaysRedactCategory(cat) {
  if (!cat) return false;
  return ALWAYS_REDACT_CATEGORIES.has(cat);
}

export function isAlwaysRedact(signals = {}) {
  if (!signals) return false;
  if (signals.alwaysRedact) return true;
  if (signals.isAutofilled || signals.autofilled) return true;
  const type = String(signals.type || "").toLowerCase();
  if (type === "password") return true;
  const autocomplete = String(signals.autocomplete || "").toLowerCase();
  if (/(password|one-time-code|webauthn)/i.test(autocomplete)) return true;
  const cat = signals.category || signals.piiCategory;
  if (cat && isAlwaysRedactCategory(cat)) return true;
  return false;
}

export function isSensitiveCategory(cat) {
  if (!cat) return false;
  return RESTRICTED_PII_CATEGORIES.has(cat) || PROFILE_PII_CATEGORIES.has(cat) || SENSITIVE_PATTERNS.test(cat);
}

export function isSensitiveText(text) {
  if (!text) return false;
  return SENSITIVE_PATTERNS.test(text);
}

export default {
  RESTRICTED_PII_CATEGORIES,
  CENSORED_CATEGORIES,
  ALWAYS_REDACT_CATEGORIES,
  CREDENTIAL_CATEGORIES,
  PROFILE_PII_CATEGORIES,
  SENSITIVE_PATTERNS,
  isRestrictedCategory,
  isCredentialCategory,
  isAlwaysRedactCategory,
  isAlwaysRedact,
  isSensitiveCategory,
  isSensitiveText,
};
