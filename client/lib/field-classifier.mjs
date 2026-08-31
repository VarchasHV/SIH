// DOM-free port of the field classifier in content.js.
// Source of truth for the *value* used by eval/ and tests/. content.js keeps an
// inline copy (content scripts can't import ESM); keep the two in sync.
// Operates on a plain "signals" object so it needs no browser.

export const MATCHERS = [
  { category: "password", type: /password/i, autocomplete: /^(new-password|current-password)$/i, nameId: /\b(password|passcode|passwd)\b/i, labelPlaceholder: /\b(password|passcode|passwd)\b/i },
  { category: "email", type: /email/i, autocomplete: /^email$/i, nameId: /\b(email|e-mail|mail_addr|mailaddr)\b/i, labelPlaceholder: /\b(email|e-mail|mail_addr|mailaddr)\b/i },
  { category: "username", autocomplete: /^(username|nickname)$/i, nameId: /\b(username|user_name|usrname|userid|user_id|login_id|loginid)\b/i, labelPlaceholder: /\b(username|user_name|usrname|userid|user_id|login_id|loginid)\b/i },
  { category: "phone number", type: /tel/i, autocomplete: /\b(tel|phone|mobile)\b/i, nameId: /\b(phone|telephone|mobile|cellphone|contact_no|contact_number|phone_no|phoneno|tel_no|homephone|home_phone|workphone|work_phone|fax)\b/i, labelPlaceholder: /\b(phone|telephone|mobile|cellphone|contact_no|contact_number|phone_no|phoneno|tel_no|home phone|work phone|fax)\b/i },
  { category: "credit/debit card number", autocomplete: /^cc-number$/i, nameId: /\b(cardnum|cardnumber|card_number|cc_number|cc-number|ccnum|creditcard|debitcard|credit_card|debit_card)\b/i, labelPlaceholder: /\b(card ?number|cardnum|creditcard|debitcard)\b/i },
  { category: "credit card type", autocomplete: /^cc-type$/i, nameId: /\b(cardtype|card_type|cc_type|cctype|cardbrand|card_brand)\b/i, labelPlaceholder: /\b(card type|card brand)\b/i },
  { category: "CVV/security code", autocomplete: /^cc-csc$/i, nameId: /\b(cvv|cvc|security_code|security-code|card_security_code|csc)\b/i, labelPlaceholder: /\b(cvv|cvc|security code|card security code|csc)\b/i },
  { category: "card expiry", autocomplete: /^(cc-exp|cc-exp-month|cc-exp-year)$/i, nameId: /\b(expdate|expiration|exp_date|expiry|cc-exp|cc_exp)\b/i, labelPlaceholder: /\b(expiry|expiration|exp\.? date)\b/i },
  { category: "card user name", autocomplete: /^cc-name$/i, nameId: /\b(carduser|card_user|cardusername|cardholder|card_holder|nameoncard|name_on_card)\b/i, labelPlaceholder: /\b(card user|cardholder|name on card)\b/i },
  { category: "card issuing bank", nameId: /\b(issuingbank|issuing_bank|card_bank)\b/i, labelPlaceholder: /\b(issuing bank|card bank)\b/i },
  { category: "card customer service phone", nameId: /\b(cardphone|card_phone|custservice|customer_service_phone)\b/i, labelPlaceholder: /\b(customer service phone|card phone)\b/i },
  { category: "first name", autocomplete: /^given-name$/i, nameId: /\b(firstname|first_name|fname|given_name|givenname)\b/i, labelPlaceholder: /\b(first name|given name)\b/i },
  { category: "middle initial", autocomplete: /^additional-name$/i, nameId: /\b(middle_name|middlename|middle_initial|middleinitial|mname|mid_init|minitial)\b/i, labelPlaceholder: /\b(middle name|middle initial|m\.i\.)\b/i },
  { category: "last name", autocomplete: /^family-name$/i, nameId: /\b(lastname|last_name|last-name|lname|family_name|surname)\b/i, labelPlaceholder: /\b(last name|family name|surname)\b/i },
  { category: "full name", autocomplete: /^name$/i, nameId: /\b(fullname|full_name)\b/i, labelPlaceholder: /\b(full name)\b/i },
  { category: "date of birth", autocomplete: /^(bday|bday-day|bday-month|bday-year)$/i, nameId: /\b(dob|birthdate|date_of_birth|birth_date|bday)\b/i, labelPlaceholder: /\b(date of birth|birth date|dob)\b/i },
  { category: "age", nameId: /\b(age|user_age|your_age)\b/i, labelPlaceholder: /\b(age)\b/i },
  { category: "birth place", nameId: /\b(birthplace|birth_place|place_of_birth|placeofbirth)\b/i, labelPlaceholder: /\b(birth place|place of birth|birthplace)\b/i },
  { category: "sex / gender", autocomplete: /^sex$/i, nameId: /\b(gender|sex|user_gender)\b/i, labelPlaceholder: /\b(gender|sex)\b/i },
  { category: "title", autocomplete: /^honorific-prefix$/i, nameId: /\b(title|salutation|honorific|prefix)\b/i, labelPlaceholder: /\b(title|salutation|honorific)\b/i },
  { category: "address", autocomplete: /\b(street-address|address-line|address-level)\b/i, nameId: /\b(address|street|addr|residence|addr1|addr2|address1|address2|street_address)\b/i, labelPlaceholder: /\b(address|street)\b/i },
  { category: "city", autocomplete: /^address-level2$/i, nameId: /\b(city|town|locality)\b/i, labelPlaceholder: /\b(city|town)\b/i },
  { category: "state", autocomplete: /^address-level1$/i, nameId: /\b(state|province|region)\b/i, labelPlaceholder: /\b(state|province|region)\b/i },
  { category: "country", autocomplete: /^country|country-name$/i, nameId: /\b(country|country_code|country_name|nation)\b/i, labelPlaceholder: /\b(country)\b/i },
  { category: "postal/ZIP code", autocomplete: /^postal-code$/i, nameId: /\b(zipcode|zip_code|zip|postalcode|postal_code|pincode|pin_code|postcode)\b/i, labelPlaceholder: /\b(zip|postal code|pin code|pincode|postcode)\b/i },
  { category: "company", autocomplete: /^organization$/i, nameId: /\b(company|company_name|companyname|organization|organisation|employer|workplace)\b/i, labelPlaceholder: /\b(company|organization|employer)\b/i },
  { category: "position", autocomplete: /^organization-title$/i, nameId: /\b(jobtitle|job_title|position|occupation|designation|profession)\b/i, labelPlaceholder: /\b(job title|position|occupation|designation)\b/i },
  { category: "web site", autocomplete: /^url$/i, nameId: /\b(website|web_site|homepage|webpage|user_url)\b/i, labelPlaceholder: /\b(website|web site|url|homepage)\b/i },
  { category: "income", nameId: /\b(income|salary|annual_income|annualincome|monthly_income)\b/i, labelPlaceholder: /\b(income|salary|annual income)\b/i },
  { category: "Aadhaar", nameId: /\b(aadhar|aadhaar|uidai|uid)\b/i, labelPlaceholder: /\b(aadhaar|aadhar|uidai)\b/i },
  { category: "PAN", nameId: /\b(pan|pannumber|pan_number|pancard|pan_card)\b/i, labelPlaceholder: /\bpan\b/i },
  { category: "SSN", autocomplete: /^ssn$/i, nameId: /\b(ssn|socialsecurity|social_security)\b/i, labelPlaceholder: /\b(ssn|social security)\b/i },
  { category: "passport number", nameId: /\b(passport|passportnum|passport_number|passportno)\b/i, labelPlaceholder: /\bpassport\b/i },
  { category: "government ID", nameId: /\b(govt_id|govtid|government_id|national_id|nationalid|state_id|stateid|drivers_license|driver_license|dl_number|dl_num|licence_number|license_no|epic_no|voter_id|voterid)\b/i, labelPlaceholder: /\b(government id|national id|driver'?s licen[cs]e|voter id|epic)\b/i },
  { category: "bank account information", nameId: /\b(bankaccount|bank_account|account_number|account_no|routing_number|routing_no|routing_num|aba_number|iban|swift|bic|ifsc)\b/i, labelPlaceholder: /\b(bank account|account number|routing number|iban|swift|ifsc)\b/i },
  { category: "IFSC", nameId: /\b(ifsc|ifsc_code|ifsccode)\b/i, labelPlaceholder: /\bifsc\b/i },
  { category: "UPI-VPA", nameId: /\b(upi|vpa|upi_id|upiid)\b/i, labelPlaceholder: /\b(upi|vpa)\b/i },
  { category: "GSTIN", nameId: /\b(gstin|gst|gst_number|gst_no)\b/i, labelPlaceholder: /\b(gstin|gst)\b/i },
  { category: "vehicle registration", nameId: /\b(vehicle_reg|vehiclereg|rc_number|rc_no|registration_no|number_plate|license_plate)\b/i, labelPlaceholder: /\b(vehicle registration|rc number|license plate|number plate)\b/i },
  { category: "custom messages and comments", nameId: /\b(comments|comment|message|messages|feedback|notes|remarks)\b/i, labelPlaceholder: /\b(comment|comments|message|feedback|notes)\b/i },
];

const NAME_EXCLUDE = /\b(domain|search|pet|product|file|host|category|display|class|group|event|stage|repo|project|brand|user|company|city|state|country|zip)\b/i;

// Loose substring keywords - obfuscated/truncated name attrs + spatial captions.
export const LOOSE_KEYWORDS = {
  password: ["password", "passwd", "passcode", "pwd"],
  email: ["email", "emailadr", "emailaddress", "mailaddr"],
  username: ["username", "userid", "loginid", "userlogin"],
  "phone number": ["phone", "phon", "mobile", "cellphone", "cellphon", "telephone", "homephon", "workphon", "faxphone"],
  "credit/debit card number": ["cardnumber", "ccnumber", "creditcard", "debitcard", "cardno"],
  "credit card type": ["cardtype", "cctype", "cardbrand"],
  "CVV/security code": ["cvv", "cvc", "cardverification", "securitycode"],
  "card expiry": ["expiry", "expiration", "ccexp", "cardexp"],
  "card user name": ["cardusername", "nameoncard", "cardholder"],
  "first name": ["firstname", "frstname", "givenname", "forename"],
  "middle initial": ["middlename", "middleinitial", "midinit"],
  "last name": ["lastname", "surname", "familyname"],
  "full name": ["fullname"],
  "date of birth": ["dateofbirth", "dob", "birthdate", "birthday"],
  age: ["age", "userage"],
  "birth place": ["birthplace", "placeofbirth"],
  "sex / gender": ["gender", "usergender"],
  title: ["salutation", "honorific"],
  address: ["address", "addressline", "streetaddress", "residence", "adraddress"],
  city: ["city", "town", "locality"],
  state: ["state", "province", "region"],
  country: ["country", "nation"],
  "postal/ZIP code": ["zipcode", "postalcode", "pincode", "postcode", "addrzip"],
  company: ["company", "organization", "organisation", "employer"],
  position: ["jobtitle", "occupation", "designation", "position"],
  "web site": ["website", "homepage", "webpage"],
  income: ["income", "salary", "annualincome"],
  Aadhaar: ["aadhaar", "aadhar", "uidai"],
  PAN: ["pannumber", "pancard", "permanentaccountnumber"],
  SSN: ["ssn", "socialsecurity", "persssn"],
  "passport number": ["passport", "passportno", "passportnumber"],
  "government ID": ["driverlicense", "driverslicense", "drivinglicense", "drivlic", "licensenumber", "voterid", "epic", "nationalid"],
  "bank account information": ["bankaccount", "accountnumber", "accountno", "ifsc", "iban", "routingnumber"],
  IFSC: ["ifsc", "ifsccode"],
  "UPI-VPA": ["upi", "vpa"],
  GSTIN: ["gstin", "gstnumber"],
  "vehicle registration": ["vehiclereg", "rcnumber", "licenseplate"],
  "custom messages and comments": ["comments", "feedback", "message"],
};

/**
 * @param {{tagName:string,type?:string,name?:string,id?:string,autocomplete?:string,placeholder?:string,ariaLabel?:string,labelText?:string,nearbyText?:string,normName?:string}} s
 * @returns {{category:string, confidence:number}|null}
 */
export function classifySignals(s) {
  const g = (k) => (s[k] || "").toLowerCase();
  const tag = (s.tagName || "").toLowerCase();
  const type = g("type");
  if (tag === "input" && ["button", "submit", "reset", "image", "file", "checkbox", "radio", "range", "color", "hidden"].includes(type)) return null;

  const normName = (s.normName || (g("name") + g("id"))).replace(/[^a-z]+/g, "");
  const capLetters = (g("labelText") + g("ariaLabel") + g("placeholder")).replace(/[^a-z]+/g, "");

  let best = null;
  let max = 0;
  for (const m of MATCHERS) {
    let c = 0;
    if (tag === "input" && m.type && m.type.test(type)) c = Math.max(c, 1.0);
    if (g("autocomplete") && m.autocomplete && m.autocomplete.test(g("autocomplete"))) c = Math.max(c, 0.95);
    if (m.nameId && (m.nameId.test(g("name")) || m.nameId.test(g("id")))) c = Math.max(c, 0.85);
    if (m.labelPlaceholder && (m.labelPlaceholder.test(g("placeholder")) || m.labelPlaceholder.test(g("ariaLabel")) || m.labelPlaceholder.test(g("labelText")))) c = Math.max(c, 0.75);
    if (m.labelPlaceholder && m.labelPlaceholder.test(g("nearbyText"))) c = Math.max(c, 0.45);
    const loose = LOOSE_KEYWORDS[m.category];
    if (loose && c < 0.85) {
      const nm = loose.find((kw) => normName.includes(kw));
      const cm = !nm && capLetters.length >= 3 && loose.find((kw) => capLetters.includes(kw));
      if (nm) c = Math.max(c, nm.length >= 9 ? 0.82 : 0.8);
      else if (cm) c = Math.max(c, cm.length >= 9 ? 0.82 : 0.72);
    }
    if (c > max) { max = c; best = { category: m.category, confidence: c }; }
  }
  if (max < 0.7) {
    const exact = /^(name|full_name|fullname)$/i;
    if ([g("name"), g("id"), g("placeholder"), g("ariaLabel"), g("labelText")].some((v) => exact.test(v)) &&
        !NAME_EXCLUDE.test([g("name"), g("id"), g("placeholder"), g("labelText")].join(" "))) {
      best = { category: "full name", confidence: 0.7 };
      max = 0.7;
    }
  }
  return max >= 0.5 ? best : null;
}

export default { MATCHERS, LOOSE_KEYWORDS, classifySignals };
