/**
 * Client-side Data Loss Prevention (DLP) - DOM Traversal & Form Sanitizer
 * Part of Privacy Lens Secure Form-Filling Agent.
 *
 * Traverses active document DOM, associates labels with inputs via ID/proximity,
 * strips personal user data, injects semantic tokens, quarantines media,
 * and compiles a minimal, structural payload for LLM inference.
 */

import {
  classifyFieldHeuristics,
  sanitizeParagraphText,
  isSensitiveMedia,
} from "./dlp-heuristics.mjs";

// ═══════════════════════════════════════════════════════════════════════════
// 1. DOM HELPER FUNCTIONS & LABEL RESOLVER
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Finds the human-readable label associated with a form control.
 * Order of precedence:
 *  1. Explicit <label for="inputId">
 *  2. Enclosing parent <label>
 *  3. aria-labelledby target elements
 *  4. aria-label or title attributes
 *  5. DOM Proximity (preceding sibling, parent table header/cell, preceding text)
 *
 * @param {Element} element
 * @param {Document} doc
 * @returns {string}
 */
export function resolveFieldLabel(element, doc = typeof document !== "undefined" ? document : null) {
  if (!element) return "";

  // 1. Explicit <label for="id">
  const id = element.getAttribute("id");
  if (id && doc) {
    const escaped = typeof CSS !== "undefined" && CSS.escape ? CSS.escape(id) : id.replace(/["\\]/g, "\\$&");
    const explicit = doc.querySelector(`label[for="${escaped}"]`);
    if (explicit && explicit.textContent.trim()) {
      return explicit.textContent.trim();
    }
  }

  // 2. Enclosing <label>
  const enclosingLabel = element.closest ? element.closest("label") : null;
  if (enclosingLabel) {
    // Clone and remove the input itself to get just the text
    const clone = enclosingLabel.cloneNode(true);
    const nestedInput = clone.querySelector ? clone.querySelector("input, select, textarea") : null;
    if (nestedInput) nestedInput.remove();
    const text = clone.textContent.trim();
    if (text) return text;
  }

  // 3. aria-labelledby
  const labelledBy = element.getAttribute("aria-labelledby");
  if (labelledBy && doc) {
    const ref = doc.getElementById ? doc.getElementById(labelledBy) : null;
    if (ref && ref.textContent.trim()) {
      return ref.textContent.trim();
    }
  }

  // 4. aria-label / title / placeholder
  const ariaLabel = element.getAttribute("aria-label");
  if (ariaLabel) return ariaLabel.trim();

  const placeholder = element.getAttribute("placeholder");
  if (placeholder) return placeholder.trim();

  const title = element.getAttribute("title");
  if (title) return title.trim();

  // 5. DOM Proximity Heuristics
  let prev = element.previousElementSibling;
  while (prev) {
    if (["LABEL", "SPAN", "P", "DIV", "B", "STRONG"].includes(prev.tagName)) {
      const text = prev.textContent.trim();
      if (text && text.length <= 80) return text;
    }
    prev = prev.previousElementSibling;
  }

  const td = element.closest ? element.closest("td") : null;
  if (td && td.previousElementSibling) {
    const text = td.previousElementSibling.textContent.trim();
    if (text && text.length <= 80) return text;
  }

  return "";
}

/**
 * Gathers nearby text for media elements to detect sensitive context.
 *
 * @param {Element} element
 * @returns {string}
 */
export function getNearbyContextText(element) {
  if (!element) return "";
  const parent = element.parentElement;
  if (!parent) return "";
  return (parent.textContent || "").slice(0, 150).trim();
}

// ═══════════════════════════════════════════════════════════════════════════
// 2. DOM SANITIZER & SKELETON EXTRACTOR
// ═══════════════════════════════════════════════════════════════════════════

export class DLPSanitizer {
  /**
   * Sanitizes a single form element (input, select, textarea).
   *
   * @param {HTMLInputElement|HTMLSelectElement|HTMLTextAreaElement} el
   * @param {Document} doc
   * @returns {Object} Sanitized field schema
   */
  static sanitizeField(el, doc) {
    const tagName = el.tagName.toLowerCase();
    const type = (el.getAttribute("type") || (tagName === "textarea" ? "textarea" : tagName === "select" ? "select" : "text")).toLowerCase();
    const id = el.getAttribute("id") || "";
    const name = el.getAttribute("name") || "";
    const className = el.getAttribute("class") || "";
    const autocomplete = el.getAttribute("autocomplete") || "";
    const placeholder = el.getAttribute("placeholder") || "";
    const ariaLabel = el.getAttribute("aria-label") || "";
    const required = el.required || el.getAttribute("aria-required") === "true";
    const label = resolveFieldLabel(el, doc);

    const isAutofill = !!(
      (typeof isAutofilled === "function" && isAutofilled(el)) ||
      (el.hasAttribute && (
        el.hasAttribute("data-com-onepassword-filled") ||
        el.hasAttribute("data-bitwarden-filled") ||
        el.hasAttribute("data-lastpass-filled") ||
        el.hasAttribute("data-pl-autofill") ||
        el.hasAttribute("autofilled")
      ))
    );

    // Heuristics classification
    const classification = classifyFieldHeuristics({
      id,
      name,
      className,
      type,
      autocomplete,
      placeholder,
      ariaLabel,
      labelText: label,
      isAutofilled: isAutofill,
    });

    // Strip raw value: If sensitive, inject semantic token; otherwise preserve structural empty/state
    let sanitizedValue = "";
    if (classification.isSensitive) {
      sanitizedValue = classification.token;
    } else if (type === "checkbox" || type === "radio") {
      sanitizedValue = el.checked ? "checked" : "unchecked";
    }

    const isAlwaysRedact = !!(classification.alwaysRedact || isAutofill);

    const fieldData = {
      tag: tagName,
      type,
      id: id || undefined,
      name: isAlwaysRedact ? undefined : (name || undefined),
      label: isAlwaysRedact ? undefined : (label || undefined),
      required: required ? true : undefined,
      isSensitive: classification.isSensitive,
      alwaysRedact: isAlwaysRedact || undefined,
      category: classification.category || undefined,
      value: sanitizedValue,
    };

    // Extract options for <select>
    if (tagName === "select" && el.options) {
      fieldData.options = Array.from(el.options).slice(0, 30).map((opt) => ({
        value: opt.value,
        text: opt.textContent.trim(),
        selected: opt.selected || undefined,
      }));
    }

    return fieldData;
  }

  /**
   * Sanitizes an image element, stripping src data URIs or sensitive identity photos.
   *
   * @param {HTMLImageElement} img
   * @returns {Object} Sanitized image schema
   */
  static sanitizeImage(img) {
    const src = img.getAttribute("src") || "";
    const alt = img.getAttribute("alt") || "";
    const title = img.getAttribute("title") || "";
    const nearbyText = getNearbyContextText(img);

    const isSensitive = isSensitiveMedia({ src, alt, title, nearbyText });

    return {
      tag: "img",
      alt: isSensitive ? "[SENSITIVE_IMAGE_REDACTED]" : alt || undefined,
      src: isSensitive ? "[SENSITIVE_IMAGE_REDACTED]" : (src.startsWith("data:") ? "[DATA_URI_REDACTED]" : src),
      isSensitive,
    };
  }

  /**
   * Sanitizes a document or root element into a clean, structural JSON payload.
   *
   * @param {Document|Element} root
   * @returns {{ forms: Array, looseFields: Array, paragraphs: Array, images: Array }}
   */
  static extractSanitizedTree(root = typeof document !== "undefined" ? document : null) {
    if (!root) throw new Error("No DOM root provided for sanitization.");

    const doc = root.ownerDocument || root;
    const forms = [];
    const processedElements = new Set();

    // 1. Process explicit <form> structures
    const formNodes = root.querySelectorAll ? root.querySelectorAll("form") : [];
    formNodes.forEach((form, index) => {
      const formId = form.getAttribute("id") || `form-${index + 1}`;
      const formName = form.getAttribute("name") || undefined;
      const formAction = form.getAttribute("action") || undefined;

      const fields = [];
      const controls = form.querySelectorAll("input, select, textarea");
      controls.forEach((ctrl) => {
        processedElements.add(ctrl);
        fields.push(DLPSanitizer.sanitizeField(ctrl, doc));
      });

      forms.push({
        formId,
        name: formName,
        action: formAction,
        fields,
      });
    });

    // 2. Process loose fields (inputs outside <form>)
    const looseFields = [];
    const allControls = root.querySelectorAll ? root.querySelectorAll("input, select, textarea") : [];
    allControls.forEach((ctrl) => {
      if (!processedElements.has(ctrl)) {
        looseFields.push(DLPSanitizer.sanitizeField(ctrl, doc));
      }
    });

    // 3. Process <p> tags & text nodes containing sensitive patterns
    const paragraphs = [];
    const pNodes = root.querySelectorAll ? root.querySelectorAll("p") : [];
    pNodes.forEach((p) => {
      const rawText = p.textContent.trim();
      if (rawText) {
        const sanitized = sanitizeParagraphText(rawText);
        paragraphs.push(sanitized);
      }
    });

    // 4. Process <img> media tags
    const images = [];
    const imgNodes = root.querySelectorAll ? root.querySelectorAll("img") : [];
    imgNodes.forEach((img) => {
      images.push(DLPSanitizer.sanitizeImage(img));
    });

    return {
      forms,
      looseFields,
      paragraphs,
      images,
    };
  }

  /**
   * Serializes the sanitized DOM tree into a clean, minified HTML string
   * formatted specifically for high-efficiency LLM inference.
   *
   * @param {Document|Element} root
   * @returns {string} Minified HTML skeleton with semantic tokens
   */
  static toCleanHtml(root = typeof document !== "undefined" ? document : null) {
    const tree = DLPSanitizer.extractSanitizedTree(root);
    const htmlParts = [];

    // Helper to format attributes
    const formatAttrs = (f) => {
      const attrs = [`type="${f.type}"`];
      if (f.id) attrs.push(`id="${f.id}"`);
      if (f.name) attrs.push(`name="${f.name}"`);
      if (f.required) attrs.push("required");
      if (f.value) attrs.push(`value="${f.value}"`);
      return attrs.join(" ");
    };

    // Helper to render a field element
    const renderFieldHtml = (f) => {
      const labelPrefix = f.label ? `<label>${f.label}</label>` : "";
      if (f.tag === "textarea") {
        return `${labelPrefix}<textarea ${f.id ? `id="${f.id}"` : ""} ${f.name ? `name="${f.name}"` : ""}>${f.value || ""}</textarea>`;
      }
      if (f.tag === "select") {
        const opts = (f.options || []).map((o) => `<option value="${o.value}">${o.text}</option>`).join("");
        return `${labelPrefix}<select ${f.id ? `id="${f.id}"` : ""} ${f.name ? `name="${f.name}"` : ""}>${opts}</select>`;
      }
      return `${labelPrefix}<input ${formatAttrs(f)}/>`;
    };

    // Render forms
    for (const form of tree.forms) {
      const fieldsHtml = form.fields.map(renderFieldHtml).join("");
      htmlParts.push(`<form id="${form.formId}">${fieldsHtml}</form>`);
    }

    // Render loose fields
    if (tree.looseFields.length > 0) {
      const looseHtml = tree.looseFields.map(renderFieldHtml).join("");
      htmlParts.push(`<div class="loose-fields">${looseHtml}</div>`);
    }

    // Render redacted text paragraphs if any
    for (const p of tree.paragraphs) {
      if (p.includes("[TOKEN_") || p.includes("[TEXT_REDACTED]")) {
        htmlParts.push(`<p>${p}</p>`);
      }
    }

    // Render redacted media if any
    for (const img of tree.images) {
      if (img.isSensitive) {
        htmlParts.push(`<img alt="[SENSITIVE_IMAGE_REDACTED]" src="[SENSITIVE_IMAGE_REDACTED]"/>`);
      }
    }

    return htmlParts.join("");
  }

  /**
   * Serializes the sanitized structure into a compact JSON schema for the LLM.
   *
   * @param {Document|Element} root
   * @returns {string} JSON string
   */
  static toJsonPayload(root = typeof document !== "undefined" ? document : null) {
    const tree = DLPSanitizer.extractSanitizedTree(root);
    return JSON.stringify(tree, null, 2);
  }
}

export default DLPSanitizer;
