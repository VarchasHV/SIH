// Privacy Lens Content Script - Sensitive Field Detection & Scope Isolation

(function () {
  if (window.__plContentScriptLoaded) return;
  window.__plContentScriptLoaded = true;

  const matchers = [
    { category: 'password', type: /password/i, autocomplete: /^(new-password|current-password)$/i, nameId: /\b(password|passcode|passwd|secret_key|secret)\b/i, labelPlaceholder: /\b(password|passcode|passwd|secret)\b/i },
    { category: 'credential', autocomplete: /^(current-password|new-password|webauthn|credential)$/i, nameId: /\b(credential|credentials|secret|api_key|apikey|auth_token|token|ssh_key|session_token|access_token|security_key)\b/i, labelPlaceholder: /\b(credential|credentials|secret|api key|auth token|token|ssh key|session token|access token|security key)\b/i },
    { category: 'otp', autocomplete: /^one-time-code$/i, nameId: /\b(otp|2fa|mfa|totp|auth_code|verification_code|one_time_code|sms_code)\b/i, labelPlaceholder: /\b(otp|2fa|mfa|totp|verification code|one time code|security code|auth code|authenticator)\b/i },
    { category: 'email', type: /email/i, autocomplete: /^email$/i, nameId: /\b(email|e-mail|mail_addr|mailaddr)\b/i, labelPlaceholder: /\b(email|e-mail|mail_addr|mailaddr)\b/i },
    { category: 'username', autocomplete: /^(username|nickname)$/i, nameId: /\b(username|user_name|usrname|userid|user_id|login_id|loginid)\b/i, labelPlaceholder: /\b(username|user_name|usrname|userid|user_id|login_id|loginid)\b/i },
    { category: 'phone number', type: /tel/i, autocomplete: /\b(tel|phone|mobile)\b/i, nameId: /\b(phone|telephone|mobile|cellphone|contact_no|contact_number|phone_no|phoneno|tel_no|homephone|home_phone|workphone|work_phone|fax)\b/i, labelPlaceholder: /\b(phone|telephone|mobile|cellphone|contact_no|contact_number|phone_no|phoneno|tel_no|home phone|work phone|fax)\b/i },
    { category: 'credit/debit card number', autocomplete: /^cc-number$/i, nameId: /\b(cardnum|cardnumber|card_number|cc_number|cc-number|ccnum|creditcard|debitcard|credit_card|debit_card)\b/i, labelPlaceholder: /\b(card ?number|cardnum|creditcard|debitcard)\b/i },
    { category: 'credit card type', autocomplete: /^cc-type$/i, nameId: /\b(cardtype|card_type|cc_type|cctype|cardbrand|card_brand)\b/i, labelPlaceholder: /\b(card type|card brand)\b/i },
    { category: 'CVV/security code', autocomplete: /^cc-csc$/i, nameId: /\b(cvv|cvc|security_code|security-code|card_security_code|csc)\b/i, labelPlaceholder: /\b(cvv|cvc|security code|card security code|csc)\b/i },
    { category: 'card expiry', autocomplete: /^(cc-exp|cc-exp-month|cc-exp-year)$/i, nameId: /\b(expdate|expiration|exp_date|expiry|cc-exp|cc_exp)\b/i, labelPlaceholder: /\b(expiry|expiration|exp\.? date)\b/i },
    { category: 'card user name', autocomplete: /^cc-name$/i, nameId: /\b(carduser|card_user|cardusername|cardholder|card_holder|nameoncard|name_on_card)\b/i, labelPlaceholder: /\b(card user|cardholder|name on card)\b/i },
    { category: 'card issuing bank', nameId: /\b(issuingbank|issuing_bank|card_bank)\b/i, labelPlaceholder: /\b(issuing bank|card bank)\b/i },
    { category: 'card customer service phone', nameId: /\b(cardphone|card_phone|custservice|customer_service_phone)\b/i, labelPlaceholder: /\b(customer service phone|card phone)\b/i },
    { category: 'first name', autocomplete: /^given-name$/i, nameId: /\b(firstname|first_name|fname|given_name|givenname)\b/i, labelPlaceholder: /\b(first name|given name)\b/i },
    { category: 'middle initial', autocomplete: /^additional-name$/i, nameId: /\b(middle_name|middlename|middle_initial|middleinitial|mname|mid_init|minitial)\b/i, labelPlaceholder: /\b(middle name|middle initial|m\.i\.)\b/i },
    { category: 'last name', autocomplete: /^family-name$/i, nameId: /\b(lastname|last_name|last-name|lname|family_name|surname)\b/i, labelPlaceholder: /\b(last name|family name|surname)\b/i },
    { category: 'full name', autocomplete: /^name$/i, nameId: /\b(fullname|full_name)\b/i, labelPlaceholder: /\b(full name)\b/i },
    { category: 'date of birth', autocomplete: /^(bday|bday-day|bday-month|bday-year)$/i, nameId: /\b(dob|birthdate|date_of_birth|birth_date|bday)\b/i, labelPlaceholder: /\b(date of birth|birth date|dob)\b/i },
    { category: 'age', nameId: /\b(age|user_age|your_age)\b/i, labelPlaceholder: /\b(age)\b/i },
    { category: 'birth place', nameId: /\b(birthplace|birth_place|place_of_birth|placeofbirth)\b/i, labelPlaceholder: /\b(birth place|place of birth|birthplace)\b/i },
    { category: 'sex / gender', autocomplete: /^sex$/i, nameId: /\b(gender|sex|user_gender)\b/i, labelPlaceholder: /\b(gender|sex)\b/i },
    { category: 'title', autocomplete: /^honorific-prefix$/i, nameId: /\b(title|salutation|honorific|prefix)\b/i, labelPlaceholder: /\b(title|salutation|honorific)\b/i },
    { category: 'address', autocomplete: /\b(street-address|address-line|address-level)\b/i, nameId: /\b(address|street|addr|residence|addr1|addr2|address1|address2|street_address)\b/i, labelPlaceholder: /\b(address|street)\b/i },
    { category: 'city', autocomplete: /^address-level2$/i, nameId: /\b(city|town|locality)\b/i, labelPlaceholder: /\b(city|town)\b/i },
    { category: 'state', autocomplete: /^address-level1$/i, nameId: /\b(state|province|region)\b/i, labelPlaceholder: /\b(state|province|region)\b/i },
    { category: 'country', autocomplete: /^country|country-name$/i, nameId: /\b(country|country_code|country_name|nation)\b/i, labelPlaceholder: /\b(country)\b/i },
    { category: 'postal/ZIP code', autocomplete: /^postal-code$/i, nameId: /\b(zipcode|zip_code|zip|postalcode|postal_code|pincode|pin_code|postcode)\b/i, labelPlaceholder: /\b(zip|postal code|pin code|pincode|postcode)\b/i },
    { category: 'company', autocomplete: /^organization$/i, nameId: /\b(company|company_name|companyname|organization|organisation|employer|workplace)\b/i, labelPlaceholder: /\b(company|organization|employer)\b/i },
    { category: 'position', autocomplete: /^organization-title$/i, nameId: /\b(jobtitle|job_title|position|occupation|designation|profession)\b/i, labelPlaceholder: /\b(job title|position|occupation|designation)\b/i },
    { category: 'web site', autocomplete: /^url$/i, nameId: /\b(website|web_site|homepage|webpage|user_url)\b/i, labelPlaceholder: /\b(website|web site|url|homepage)\b/i },
    { category: 'income', nameId: /\b(income|salary|annual_income|annualincome|monthly_income)\b/i, labelPlaceholder: /\b(income|salary|annual income)\b/i },
    { category: 'Aadhaar', nameId: /\b(aadhar|aadhaar|uidai|uid)\b/i, labelPlaceholder: /\b(aadhaar|aadhar|uidai)\b/i },
    { category: 'PAN', nameId: /\b(pan|pannumber|pan_number|pancard|pan_card)\b/i, labelPlaceholder: /\bpan\b/i },
    { category: 'SSN', autocomplete: /^ssn$/i, nameId: /\b(ssn|socialsecurity|social_security)\b/i, labelPlaceholder: /\b(ssn|social security)\b/i },
    { category: 'passport number', nameId: /\b(passport|passportnum|passport_number|passportno)\b/i, labelPlaceholder: /\bpassport\b/i },
    { category: 'government ID', nameId: /\b(govt_id|govtid|government_id|national_id|nationalid|state_id|stateid|drivers_license|driver_license|dl_number|dl_num|licence_number|license_no|epic_no|voter_id|voterid)\b/i, labelPlaceholder: /\b(government id|national id|driver'?s licen[cs]e|voter id|epic)\b/i },
    { category: 'bank account information', nameId: /\b(bankaccount|bank_account|account_number|account_no|routing_number|routing_no|routing_num|aba_number|iban|swift|bic|ifsc)\b/i, labelPlaceholder: /\b(bank account|account number|routing number|iban|swift|ifsc)\b/i },
    { category: 'IFSC', nameId: /\b(ifsc|ifsc_code|ifsccode)\b/i, labelPlaceholder: /\bifsc\b/i },
    { category: 'UPI-VPA', nameId: /\b(upi|vpa|upi_id|upiid)\b/i, labelPlaceholder: /\b(upi|vpa)\b/i },
    { category: 'GSTIN', nameId: /\b(gstin|gst|gst_number|gst_no)\b/i, labelPlaceholder: /\b(gstin|gst)\b/i },
    { category: 'vehicle registration', nameId: /\b(vehicle_reg|vehiclereg|rc_number|rc_no|registration_no|number_plate|license_plate)\b/i, labelPlaceholder: /\b(vehicle registration|rc number|license plate|number plate)\b/i },
    { category: 'custom messages and comments', nameId: /\b(comments|comment|message|messages|feedback|notes|remarks)\b/i, labelPlaceholder: /\b(comment|comments|message|feedback|notes)\b/i },
  ];

  const LOOSE_KEYWORDS = {
    'password': ['password', 'passwd', 'passcode', 'pwd', 'secret'],
    'credential': ['credential', 'credentials', 'apikey', 'authtoken', 'secretkey', 'sshkey', 'sessiontoken', 'bearertoken'],
    'otp': ['otp', '2fa', 'mfa', 'totp', 'authcode', 'verificationcode', 'onetimecode'],
    'email': ['email', 'emailadr', 'emailaddress', 'mailaddr'],
    'username': ['username', 'userid', 'loginid', 'userlogin'],
    'phone number': ['phone', 'phon', 'mobile', 'cellphone', 'cellphon', 'telephone', 'homephon', 'workphon', 'faxphone'],
    'credit/debit card number': ['cardnumber', 'ccnumber', 'creditcard', 'debitcard', 'cardno'],
    'credit card type': ['cardtype', 'cctype', 'cardbrand'],
    'CVV/security code': ['cvv', 'cvc', 'cardverification', 'securitycode'],
    'card expiry': ['expiry', 'expiration', 'ccexp', 'cardexp'],
    'card user name': ['cardusername', 'nameoncard', 'cardholder'],
    'first name': ['firstname', 'frstname', 'givenname', 'forename'],
    'middle initial': ['middlename', 'middleinitial', 'midinit'],
    'last name': ['lastname', 'surname', 'familyname'],
    'full name': ['fullname'],
    'date of birth': ['dateofbirth', 'dob', 'birthdate', 'birthday'],
    'age': ['age', 'userage'],
    'birth place': ['birthplace', 'placeofbirth'],
    'sex / gender': ['gender', 'usergender'],
    'title': ['salutation', 'honorific'],
    'address': ['address', 'addressline', 'streetaddress', 'residence', 'adraddress'],
    'city': ['city', 'town', 'locality'],
    'state': ['state', 'province', 'region'],
    'country': ['country', 'nation'],
    'postal/ZIP code': ['zipcode', 'postalcode', 'pincode', 'postcode', 'addrzip'],
    'company': ['company', 'organization', 'organisation', 'employer'],
    'position': ['jobtitle', 'occupation', 'designation', 'position'],
    'web site': ['website', 'homepage', 'webpage'],
    'income': ['income', 'salary', 'annualincome'],
    'Aadhaar': ['aadhaar', 'aadhar', 'uidai'],
    'PAN': ['pannumber', 'pancard', 'permanentaccountnumber'],
    'SSN': ['ssn', 'socialsecurity', 'persssn'],
    'passport number': ['passport', 'passportno', 'passportnumber'],
    'government ID': ['driverlicense', 'driverslicense', 'drivinglicense', 'drivlic', 'licensenumber', 'voterid', 'epic', 'nationalid'],
    'bank account information': ['bankaccount', 'accountnumber', 'accountno', 'ifsc', 'iban', 'routingnumber'],
    'IFSC': ['ifsc', 'ifsccode'],
    'UPI-VPA': ['upi', 'vpa'],
    'GSTIN': ['gstin', 'gstnumber'],
    'vehicle registration': ['vehiclereg', 'rcnumber', 'licenseplate'],
    'custom messages and comments': ['comments', 'feedback', 'message'],
  };

  // Detect autofilled states from browser or password managers (1Password, Bitwarden, LastPass, Dashlane, Chrome)
  function isAutofilled(el) {
    if (!el) return false;
    try {
      if (el.matches(':-webkit-autofill, :autofill, [data-com-onepassword-filled], [data-bitwarden-filled], [data-lastpass-filled], [data-dashlane-filled], [data-pl-autofill], [autofilled]')) {
        return true;
      }
    } catch (e) {
      // CSS pseudo-class matches fallback
    }
    // Check custom attribute markers
    if (el.hasAttribute && (
      el.hasAttribute('data-com-onepassword-filled') ||
      el.hasAttribute('data-bitwarden-filled') ||
      el.hasAttribute('data-lastpass-filled') ||
      el.hasAttribute('data-pl-autofill')
    )) {
      return true;
    }
    return false;
  }

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
        // CSS.escape fallback
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
      normName: (name + ' ' + id).toLowerCase().replace(/[^a-z]+/g, ''),
      isAutofilled: isAutofilled(el)
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

    // ── 1. Deterministic Always-Redact for Autofilled & Credential Fields ──
    const isAutofill = !!s.isAutofilled;
    const isPwd = s.tagName === 'input' && s.type === 'password';
    const isCredentialAuto = s.autocomplete && /^(current-password|new-password|one-time-code|webauthn|credential)$/i.test(s.autocomplete);

    if (isAutofill || isPwd || isCredentialAuto) {
      let cat = 'password';
      if (s.autocomplete === 'one-time-code' || /\b(otp|2fa|mfa|totp)\b/i.test(s.normName + ' ' + s.labelText + ' ' + s.placeholder)) {
        cat = 'otp';
      } else if (/\b(credential|token|key|secret)\b/i.test(s.normName + ' ' + s.labelText + ' ' + s.placeholder)) {
        cat = 'credential';
      }
      return { category: cat, confidence: 1.0, alwaysRedact: true, isAutofilled: isAutofill };
    }

    // ── 2. Standard heuristic classification ──
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

    // Custom fallback checks for "name" (when exactly name/fullname)
    if (maxConfidence < 0.7) {
      const isExactlyName = /^(name|full_name|fullname)$/i;
      const nameMatches = isExactlyName.test(s.name) || isExactlyName.test(s.id) || isExactlyName.test(s.placeholder) || isExactlyName.test(s.ariaLabel) || isExactlyName.test(s.labelText);
      if (nameMatches) {
        const isExcluded = /\b(domain|search|pet|product|file|host|category|display|class|group|event|stage|repo|project)\b/i.test(s.name || s.id || s.placeholder || s.labelText);
        if (!isExcluded) {
          bestMatch = { category: 'full name', confidence: 0.70 };
          maxConfidence = 0.70;
        }
      }
    }

    // Set minimum confidence threshold
    if (maxConfidence >= 0.5 && bestMatch) {
      const isCred = ['password', 'credential', 'otp', 'credit/debit card number', 'CVV/security code', 'SSN', 'Aadhaar', 'PAN'].includes(bestMatch.category);
      return {
        ...bestMatch,
        alwaysRedact: isCred,
      };
    }
    return null;
  }

  // Viewport-isolated sensitive DOM bounding box extraction
  function getSensitiveDOMBoxes() {
    const candidates = document.querySelectorAll('input, textarea, select, [contenteditable]');
    const dpr = window.devicePixelRatio || 1;
    const boxes = [];
    const uniqueElements = new Set();

    const vpW = window.innerWidth;
    const vpH = window.innerHeight;

    candidates.forEach(el => {
      if (uniqueElements.has(el)) return;
      uniqueElements.add(el);

      const classification = classifyElement(el);
      if (!classification) return;

      const rect = el.getBoundingClientRect();
      if (rect.width <= 0 || rect.height <= 0) return;

      // Strict active viewport scope isolation: skip elements entirely outside the visible viewport
      if (rect.bottom <= 0 || rect.right <= 0 || rect.top >= vpH || rect.left >= vpW) {
        return;
      }

      // Clamp bounding box to active viewport boundaries
      const clampLeft = Math.max(0, Math.min(vpW, rect.left));
      const clampTop = Math.max(0, Math.min(vpH, rect.top));
      const clampRight = Math.max(0, Math.min(vpW, rect.right));
      const clampBottom = Math.max(0, Math.min(vpH, rect.bottom));
      const clampW = clampRight - clampLeft;
      const clampH = clampBottom - clampTop;

      if (clampW <= 0 || clampH <= 0) return;

      boxes.push({
        category: classification.category,
        confidence: classification.confidence,
        alwaysRedact: !!(classification.alwaysRedact || classification.isAutofilled),
        element: el.tagName.toLowerCase(),
        name: el.getAttribute('name') || '',
        id: el.getAttribute('id') || '',
        x: Math.round(clampLeft * dpr),
        y: Math.round(clampTop * dpr),
        w: Math.round(clampW * dpr),
        h: Math.round(clampH * dpr)
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
        a[i].alwaysRedact !== b[i].alwaysRedact ||
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
        return true;
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
      attributeFilter: ['type', 'name', 'id', 'autocomplete', 'placeholder', 'aria-label', 'aria-labelledby', 'contenteditable', 'class', 'data-com-onepassword-filled', 'data-bitwarden-filled', 'data-lastpass-filled']
    });

    const debouncedScan = debounce(() => {
      const newBoxes = getSensitiveDOMBoxes();
      if (!findingsEqual(cachedBoxes, newBoxes)) {
        cachedBoxes = newBoxes;
        try {
          chrome.runtime.sendMessage({ action: 'FIELDS_UPDATED', boxes: cachedBoxes }, () => {
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

  window.classifyElement = classifyElement;
  window.getElementSignals = getElementSignals;
  window.getSensitiveDOMBoxes = getSensitiveDOMBoxes;
  window.isAutofilled = isAutofilled;
})();
