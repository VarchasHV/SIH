// Privacy Lens Content Script - Sensitive Field Detection

const matchers = [
  {
    category: 'password',
    type: /password/i,
    autocomplete: /^(new-password|current-password)$/i,
    nameId: /\b(password|passcode|passwd)\b/i,
    labelPlaceholder: /\b(password|passcode|passwd)\b/i,
  },
  {
    category: 'email',
    type: /email/i,
    autocomplete: /^email$/i,
    nameId: /\b(email|e-mail|mail_addr|mailaddr)\b/i,
    labelPlaceholder: /\b(email|e-mail|mail_addr|mailaddr)\b/i,
  },
  {
    category: 'username',
    autocomplete: /^(username|nickname)$/i,
    nameId: /\b(username|user_name|usrname|userid|user_id|login_id|loginid)\b/i,
    labelPlaceholder: /\b(username|user_name|usrname|userid|user_id|login_id|loginid)\b/i,
  },
  {
    category: 'phone number',
    type: /tel/i,
    autocomplete: /\b(tel|phone|mobile)\b/i,
    nameId: /\b(phone|telephone|mobile|cellphone|contact_no|contact_number|phone_no|phoneno|tel_no)\b/i,
    labelPlaceholder: /\b(phone|telephone|mobile|cellphone|contact_no|contact_number|phone_no|phoneno|tel_no)\b/i,
  },
  {
    category: 'credit/debit card number',
    autocomplete: /^cc-number$/i,
    nameId: /\b(cardnum|cardnumber|card_number|cc_number|ccnum|creditcard|debitcard|credit_card|debit_card)\b/i,
    labelPlaceholder: /\b(cardnum|cardnumber|card_number|cc_number|ccnum|creditcard|debitcard|credit_card|debit_card)\b/i,
  },
  {
    category: 'CVV/security code',
    autocomplete: /^cc-csc$/i,
    nameId: /\b(cvv|cvc|security_code|security-code|card_security_code|csc)\b/i,
    labelPlaceholder: /\b(cvv|cvc|security_code|security-code|card_security_code|csc)\b/i,
  },
  {
    category: 'card expiry',
    autocomplete: /^cc-exp|cc-exp-month|cc-exp-year$/i,
    nameId: /\b(expdate|expiration|exp_date|expiry|cc-exp|cc_exp)\b/i,
    labelPlaceholder: /\b(expdate|expiration|exp_date|expiry|cc-exp|cc_exp)\b/i,
  },
  {
    category: 'first name',
    autocomplete: /^given-name$/i,
    nameId: /\b(firstname|first_name|fname|given_name|givenname)\b/i,
    labelPlaceholder: /\b(firstname|first_name|fname|given_name|givenname)\b/i,
  },
  {
    category: 'last name',
    autocomplete: /^family-name$/i,
    nameId: /\b(lastname|last_name|lname|family_name|surname)\b/i,
    labelPlaceholder: /\b(lastname|last_name|lname|family_name|surname)\b/i,
  },
  {
    category: 'full name',
    autocomplete: /^name$/i,
    nameId: /\b(fullname|full_name)\b/i,
    labelPlaceholder: /\b(fullname|full_name)\b/i,
  },
  {
    category: 'date of birth',
    autocomplete: /^bday|bday-day|bday-month|bday-year$/i,
    nameId: /\b(dob|birthdate|date_of_birth|birth_date|bday)\b/i,
    labelPlaceholder: /\b(dob|birthdate|date_of_birth|birth_date|bday)\b/i,
  },
  {
    category: 'address',
    autocomplete: /\b(street-address|address-line|address-level)\b/i,
    nameId: /\b(address|street|addr|residence|addr1|addr2|address1|address2|street_address)\b/i,
    labelPlaceholder: /\b(address|street|addr|residence|addr1|addr2|address1|address2|street_address)\b/i,
  },
  {
    category: 'postal/ZIP code',
    autocomplete: /^postal-code$/i,
    nameId: /\b(zipcode|zip_code|zip|postalcode|postal_code|pincode|pin_code|postcode)\b/i,
    labelPlaceholder: /\b(zipcode|zip_code|zip|postalcode|postal_code|pincode|pin_code|postcode)\b/i,
  },
  {
    category: 'Aadhaar',
    nameId: /\b(aadhar|aadhaar|uidai)\b/i,
    labelPlaceholder: /\b(aadhar|aadhaar|uidai)\b/i,
  },
  {
    category: 'PAN',
    nameId: /\b(pan|pannumber|pan_number|pancard|pan_card)\b/i,
    labelPlaceholder: /\b(pan|pannumber|pan_number|pancard|pan_card)\b/i,
  },
  {
    category: 'SSN',
    autocomplete: /^ssn$/i,
    nameId: /\b(ssn|socialsecurity|social_security)\b/i,
    labelPlaceholder: /\b(ssn|socialsecurity|social_security)\b/i,
  },
  {
    category: 'passport number',
    nameId: /\b(passport|passportnum|passport_number|passportno)\b/i,
    labelPlaceholder: /\b(passport|passportnum|passport_number|passportno)\b/i,
  },
  {
    category: 'government ID',
    nameId: /\b(govt_id|govtid|government_id|national_id|nationalid|state_id|stateid|drivers_license|driver_license|dl_number|dl_num|licence_number|license_no)\b/i,
    labelPlaceholder: /\b(govt_id|govtid|government_id|national_id|nationalid|state_id|stateid|drivers_license|driver_license|dl_number|dl_num|licence_number|license_no)\b/i,
  },
  {
    category: 'bank account information',
    nameId: /\b(bankaccount|bank_account|account_number|account_no|routing_number|routing_no|routing_num|aba_number|iban|swift|bic|ifsc)\b/i,
    labelPlaceholder: /\b(bankaccount|bank_account|account_number|account_no|routing_number|routing_no|routing_num|aba_number|iban|swift|bic|ifsc)\b/i,
  }
];

// Loose substring keywords for fuzzy matching against letters-only name/id and
// spatial captions. Deliberately specific to limit false positives.
const LOOSE_KEYWORDS = {
  'password': ['password', 'passwd', 'passcode', 'pwd'],
  'email': ['email', 'emailadr', 'emailaddress', 'mailaddr'],
  'username': ['username', 'userid', 'loginid', 'userlogin'],
  'phone number': ['phone', 'phon', 'mobile', 'cellphone', 'cellphon', 'telephone', 'homephon', 'workphon', 'faxphone'],
  'credit/debit card number': ['cardnumber', 'ccnumber', 'creditcard', 'debitcard', 'cardno'],
  'CVV/security code': ['cvv', 'cvc', 'cardverification', 'securitycode'],
  'card expiry': ['expiry', 'expiration', 'ccexp', 'cardexp'],
  'first name': ['firstname', 'frstname', 'givenname', 'forename'],
  'last name': ['lastname', 'surname', 'familyname'],
  'full name': ['fullname', 'cardholder', 'cardusername', 'ccuname', 'nameoncard'],
  'date of birth': ['dateofbirth', 'dob', 'birthdate', 'birthday'],
  'address': ['address', 'addressline', 'streetaddress', 'residence', 'adraddress'],
  'postal/ZIP code': ['zipcode', 'postalcode', 'pincode', 'postcode', 'addrzip'],
  'Aadhaar': ['aadhaar', 'aadhar', 'uidai'],
  'PAN': ['pannumber', 'pancard', 'permanentaccountnumber'],
  'SSN': ['ssn', 'socialsecurity', 'persssn'],
  'passport number': ['passport', 'passportno', 'passportnumber'],
  'government ID': ['driverlicense', 'driverslicense', 'drivinglicense', 'drivlic', 'licensenumber', 'voterid', 'epic', 'nationalid'],
  'bank account information': ['bankaccount', 'accountnumber', 'accountno', 'ifsc', 'iban', 'routingnumber'],
};

// Letters-only text of an element, if it reads like a field caption.
function captionText(node) {
  if (!node) return '';
  const t = (node.textContent || '').replace(/\s+/g, ' ').trim();
  return t && t.length <= 60 && /[a-z]/i.test(t) ? t : '';
}

// Nearest caption when there is no <label>: table cell to the left, grid column
// sibling, or a preceding block within an ancestor.
function spatialLabel(el) {
  const cell = el.closest('td, th');
  if (cell) {
    const c = captionText(cell.previousElementSibling);
    if (c) return c;
  }
  let cur = el;
  for (let depth = 0; depth < 4 && cur; depth++, cur = cur.parentElement) {
    const sib = cur.previousElementSibling;
    if (sib && !sib.querySelector('input, select, textarea') && captionText(sib)) return captionText(sib);
  }
  const group = el.closest('[class*="form-group"], [class*="field"], [class*="row"], [class*="col"], dd');
  if (group) {
    const label = group.querySelector('label, legend');
    if (captionText(label)) return captionText(label);
    if (captionText(group.previousElementSibling)) return captionText(group.previousElementSibling);
  }
  return '';
}

function getElementSignals(el) {
  const tagName = el.tagName.toLowerCase();
  const type = el.getAttribute('type') || '';
  const name = el.getAttribute('name') || '';
  const id = el.getAttribute('id') || '';
  const autocomplete = el.getAttribute('autocomplete') || '';
  const placeholder = el.getAttribute('placeholder') || '';
  const ariaLabel = el.getAttribute('aria-label') || '';

  // Find associated label text
  let labelText = '';
  if (id) {
    try {
      const labelEl = document.querySelector(`label[for="${CSS.escape(id)}"]`);
      if (labelEl) {
        labelText = labelEl.textContent || '';
      }
    } catch (e) {
      // CSS.escape fallback / safe catch
    }
  }
  if (!labelText) {
    const closestLabel = el.closest('label');
    if (closestLabel) {
      labelText = closestLabel.textContent || '';
    }
  }

  // aria-labelledby
  const labelledBy = el.getAttribute('aria-labelledby');
  if (!labelText && labelledBy) {
    const labels = labelledBy.split(/\s+/).map(lId => {
      const lEl = document.getElementById(lId);
      return lEl ? (lEl.textContent || '') : '';
    }).filter(Boolean);
    if (labels.length > 0) {
      labelText = labels.join(' ');
    }
  }

  // Spatial fallback: captions in a sibling grid/table cell rather than a <label>.
  if (!labelText || labelText.length > 80) {
    labelText = labelText || spatialLabel(el);
  }

  // Preceding/nearby text content in the parent
  let nearbyText = '';
  const parent = el.parentElement;
  if (parent) {
    nearbyText = parent.textContent || '';
  }

  return {
    tagName,
    type: type.toLowerCase(),
    name: name.toLowerCase(),
    id: id.toLowerCase(),
    autocomplete: autocomplete.toLowerCase(),
    placeholder: placeholder.toLowerCase(),
    ariaLabel: ariaLabel.toLowerCase(),
    labelText: labelText.toLowerCase(),
    nearbyText: nearbyText.toLowerCase(),
    normName: (name + ' ' + id).toLowerCase().replace(/[^a-z]+/g, '')
  };
}

function classifyElement(el) {
  const s = getElementSignals(el);

  // Ignore non-editable and non-input buttons, submit, reset, checkboxes, radios, etc.
  if (s.tagName === 'input') {
    const ignoredTypes = ['button', 'submit', 'reset', 'image', 'file', 'checkbox', 'radio', 'range', 'color', 'hidden'];
    if (ignoredTypes.includes(s.type)) {
      return null;
    }
  } else if (s.tagName !== 'textarea' && s.tagName !== 'select') {
    // If it's a generic element, make sure it is actually contenteditable
    if (!el.isContentEditable && el.getAttribute('contenteditable') === null) {
      return null;
    }
  }

  let bestMatch = null;
  let maxConfidence = 0;

  for (const m of matchers) {
    let confidence = 0;

    // Check Type (Only for inputs)
    if (s.tagName === 'input' && m.type && m.type.test(s.type)) {
      confidence = Math.max(confidence, 1.0);
    }

    // Check Autocomplete
    if (s.autocomplete && m.autocomplete && m.autocomplete.test(s.autocomplete)) {
      confidence = Math.max(confidence, 0.95);
    }

    // Check Name / ID
    if (m.nameId) {
      if (m.nameId.test(s.name) || m.nameId.test(s.id)) {
        confidence = Math.max(confidence, 0.85);
      }
    }

    // Check Labels, Placeholders, Aria Labels
    if (m.labelPlaceholder) {
      if (m.labelPlaceholder.test(s.placeholder) || m.labelPlaceholder.test(s.ariaLabel) || m.labelPlaceholder.test(s.labelText)) {
        confidence = Math.max(confidence, 0.75);
      }
    }

    // Check nearby text (fallback)
    if (m.labelPlaceholder && m.labelPlaceholder.test(s.nearbyText)) {
      confidence = Math.max(confidence, 0.45);
    }

    // Fuzzy pass: obfuscated/truncated name attrs + spatial captions.
    const loose = LOOSE_KEYWORDS[m.category];
    if (loose && confidence < 0.85) {
      const nm = loose.find(kw => s.normName.includes(kw));
      const capLetters = (s.labelText + s.ariaLabel + s.placeholder).replace(/[^a-z]+/gi, '').toLowerCase();
      const cm = !nm && capLetters.length >= 3 && loose.find(kw => capLetters.includes(kw));
      if (nm) confidence = Math.max(confidence, nm.length >= 9 ? 0.82 : 0.8);
      else if (cm) confidence = Math.max(confidence, cm.length >= 9 ? 0.82 : 0.72);
    }

    if (confidence > maxConfidence) {
      maxConfidence = confidence;
      bestMatch = { category: m.category, confidence };
    }
  }

  // Custom fallback checks for "name" (when exactly name/fullname/fullname)
  if (maxConfidence < 0.7) {
    const isExactlyName = /^(name|full_name|fullname)$/i;
    const nameMatches = isExactlyName.test(s.name) || isExactlyName.test(s.id) || isExactlyName.test(s.placeholder) || isExactlyName.test(s.ariaLabel) || isExactlyName.test(s.labelText);
    if (nameMatches) {
      // Ensure it is not matching common non-sensitive name fields (like domain name, search name, pet name, etc.)
      const isExcluded = /\b(domain|search|pet|product|file|host|category|display|class|group|event|stage|repo|project)\b/i.test(s.name || s.id || s.placeholder || s.labelText);
      if (!isExcluded) {
        bestMatch = { category: 'full name', confidence: 0.70 };
        maxConfidence = 0.70;
      }
    }
  }

  // Set minimum confidence threshold
  if (maxConfidence >= 0.5) {
    return bestMatch;
  }
  return null;
}

function getSensitiveDOMBoxes() {
  const candidates = document.querySelectorAll('input, textarea, select, [contenteditable]');
  const dpr = window.devicePixelRatio || 1;
  const boxes = [];
  const uniqueElements = new Set();

  candidates.forEach(el => {
    if (uniqueElements.has(el)) return;
    uniqueElements.add(el);

    const classification = classifyElement(el);
    if (!classification) return;

    const rect = el.getBoundingClientRect();
    if (rect.width <= 0 || rect.height <= 0) return;

    boxes.push({
      category: classification.category,
      confidence: classification.confidence,
      element: el.tagName.toLowerCase(),
      name: el.getAttribute('name') || '',
      id: el.getAttribute('id') || '',
      x: Math.round(rect.left * dpr),
      y: Math.round(rect.top * dpr),
      w: Math.round(rect.width * dpr),
      h: Math.round(rect.height * dpr)
    });
  });

  return boxes;
}

// Debounce helper
function debounce(fn, delay) {
  let timer = null;
  return function (...args) {
    clearTimeout(timer);
    timer = setTimeout(() => fn.apply(this, args), delay);
  };
}

// Equality checker for cached findings
function findingsEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (
      a[i].category !== b[i].category ||
      a[i].confidence !== b[i].confidence ||
      a[i].element !== b[i].element ||
      a[i].name !== b[i].name ||
      a[i].id !== b[i].id ||
      a[i].x !== b[i].x ||
      a[i].y !== b[i].y ||
      a[i].w !== b[i].w ||
      a[i].h !== b[i].h
    ) {
      return false;
    }
  }
  return true;
}

// Check if mutation record is relevant to our scanning candidates or attributes
function isMutationRelevant(mutations) {
  for (const record of mutations) {
    if (record.type === 'attributes') {
      return true; // filtered by attributeFilter
    }
    if (record.type === 'childList') {
      for (const node of record.addedNodes) {
        if (node.nodeType === Node.ELEMENT_NODE) {
          if (node.matches('input, textarea, select, [contenteditable]') || node.querySelector('input, textarea, select, [contenteditable]')) {
            return true;
          }
        }
      }
      for (const node of record.removedNodes) {
        if (node.nodeType === Node.ELEMENT_NODE) {
          if (node.matches('input, textarea, select, [contenteditable]') || node.querySelector('input, textarea, select, [contenteditable]')) {
            return true;
          }
        }
      }
    }
  }
  return false;
}

if (!window.hasInjectedPrivacyAgent) {
  window.hasInjectedPrivacyAgent = true;

  let cachedBoxes = getSensitiveDOMBoxes();

  // Create MutationObserver
  const observer = new MutationObserver(mutations => {
    if (isMutationRelevant(mutations)) {
      debouncedScan();
    }
  });

  observer.observe(document.documentElement, {
    childList: true,
    subtree: true,
    attributes: true,
    attributeFilter: ['type', 'name', 'id', 'autocomplete', 'placeholder', 'aria-label', 'aria-labelledby', 'contenteditable']
  });

  const debouncedScan = debounce(() => {
    const newBoxes = getSensitiveDOMBoxes();
    if (!findingsEqual(cachedBoxes, newBoxes)) {
      cachedBoxes = newBoxes;
      try {
        chrome.runtime.sendMessage({ action: 'FIELDS_UPDATED', boxes: cachedBoxes }, () => {
          // Accessing lastError prevents uncaught exception when popup is closed
          if (chrome.runtime.lastError) {
            // No-op
          }
        });
      } catch (e) {
        // No-op
      }
    }
  }, 200);

  // Listen to scroll & resize
  window.addEventListener('scroll', debouncedScan, { passive: true });
  window.addEventListener('resize', debouncedScan, { passive: true });

  // Chrome messaging listener
  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'GET_PII_BOXES') {
      cachedBoxes = getSensitiveDOMBoxes();
      sendResponse({ boxes: cachedBoxes });
    }
    return true;
  });
}
