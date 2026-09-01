// Single source of truth for sensitive field categorization in the content script world.
// Attaches definitions to window.__PL.

(function () {
  const RESTRICTED_PII_CATEGORIES = new Set([
    "password",
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

  const CENSORED_CATEGORIES = RESTRICTED_PII_CATEGORIES;

  const PROFILE_PII_CATEGORIES = new Set([
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

  const SENSITIVE_PATTERNS = new RegExp(
    [
      // Auth & Credentials
      "password", "passcode", "passwd", "\\bpwd\\b",

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

  function isRestrictedCategory(cat) {
    if (!cat) return false;
    return RESTRICTED_PII_CATEGORIES.has(cat);
  }

  function isSensitiveCategory(cat) {
    if (!cat) return false;
    return RESTRICTED_PII_CATEGORIES.has(cat) || PROFILE_PII_CATEGORIES.has(cat) || SENSITIVE_PATTERNS.test(cat);
  }

  function isSensitiveText(text) {
    if (!text) return false;
    return SENSITIVE_PATTERNS.test(text);
  }

  window.__PL = window.__PL || {};
  window.__PL.RESTRICTED_PII_CATEGORIES = RESTRICTED_PII_CATEGORIES;
  window.__PL.CENSORED_CATEGORIES = CENSORED_CATEGORIES;
  window.__PL.PROFILE_PII_CATEGORIES = PROFILE_PII_CATEGORIES;
  window.__PL.SENSITIVE_PATTERNS = SENSITIVE_PATTERNS;
  window.__PL.isRestrictedCategory = isRestrictedCategory;
  window.__PL.isSensitiveCategory = isSensitiveCategory;
  window.__PL.isSensitiveText = isSensitiveText;
})();
