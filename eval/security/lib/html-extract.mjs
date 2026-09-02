// Minimal HTML surface extractor for the security lab benchmark.
//
// NOT a DOM. Regex-based, good enough for the controlled test pages in
// security-lab/ (which this repo authors). It pulls exactly the surfaces the
// real content script inspects: visible-ish text, injectable attributes, HTML
// comments, <meta content>, form actions, links, and input semantics.
//
// A real browser render is NOT MEASURED here — CSS visibility, computed styles,
// and JS-built DOM are out of scope. Lab pages that need "hidden text" carry a
// data-visibility="hidden" marker so the scorer can still reason about them.

const stripTags = (s) => s.replace(/<[^>]+>/g, " ").replace(/&nbsp;/g, " ").replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/\s+/g, " ").trim();

export function extractHtmlSurfaces(html) {
  const src = String(html || "");

  // strip <script>/<style> bodies before text extraction
  const noScript = src.replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, " ").replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, " ");

  // comments
  const comments = [...src.matchAll(/<!--([\s\S]*?)-->/g)].map((m) => m[1].trim()).filter(Boolean);

  // meta content
  const metas = [...src.matchAll(/<meta\b[^>]*>/gi)].map((m) => {
    const tag = m[0];
    const name = (tag.match(/\b(?:name|property)\s*=\s*["']([^"']+)["']/i) || [])[1] || null;
    const content = (tag.match(/\bcontent\s*=\s*["']([^"']*)["']/i) || [])[1] || "";
    return { name, content };
  }).filter((x) => x.content);

  // injectable attributes on any element
  const attrs = [];
  for (const attr of ["alt", "aria-label", "title", "placeholder", "data-instruction", "data-prompt", "data-ai", "data-agent"]) {
    for (const m of src.matchAll(new RegExp(`\\b${attr}\\s*=\\s*["']([^"']+)["']`, "gi"))) {
      attrs.push({ attr, value: m[1] });
    }
  }

  // elements marked hidden for the scorer (lab convention)
  const hiddenBlocks = [...src.matchAll(/<[^>]*\bdata-visibility\s*=\s*["']hidden["'][^>]*>([\s\S]*?)<\/[a-z]+>/gi)].map((m) => stripTags(m[1])).filter(Boolean);
  // ...also inline-styled hidden spans
  for (const m of src.matchAll(/<([a-z]+)\b[^>]*style\s*=\s*["'][^"']*(?:opacity\s*:\s*0|font-size\s*:\s*0(?:px)?|left\s*:\s*-\d{3,}|display\s*:\s*none|visibility\s*:\s*hidden)[^"']*["'][^>]*>([\s\S]*?)<\/\1>/gi)) {
    const t = stripTags(m[2]);
    if (t) hiddenBlocks.push(t);
  }

  // forms
  const forms = [...src.matchAll(/<form\b[^>]*>/gi)].map((m) => ({
    action: (m[0].match(/\baction\s*=\s*["']([^"']*)["']/i) || [])[1] || null,
    method: (m[0].match(/\bmethod\s*=\s*["']([^"']*)["']/i) || [])[1] || "get",
  }));

  // inputs
  const inputs = [...src.matchAll(/<input\b[^>]*>/gi)].map((m) => ({
    type: (m[0].match(/\btype\s*=\s*["']([^"']*)["']/i) || [])[1] || "text",
    name: (m[0].match(/\bname\s*=\s*["']([^"']*)["']/i) || [])[1] || "",
    autocomplete: (m[0].match(/\bautocomplete\s*=\s*["']([^"']*)["']/i) || [])[1] || "",
    placeholder: (m[0].match(/\bplaceholder\s*=\s*["']([^"']*)["']/i) || [])[1] || "",
  }));

  // links
  const links = [...src.matchAll(/<a\b[^>]*\bhref\s*=\s*["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi)].map((m) => ({ href: m[1], text: stripTags(m[2]) }));

  // page-declared "true" location (lab convention — no real navigation here)
  const declaredUrl = (src.match(/<link\b[^>]*\brel\s*=\s*["']canonical["'][^>]*\bhref\s*=\s*["']([^"']+)["']/i) || [])[1]
    || (metas.find((m) => m.name === "lab:url") || {}).content || null;

  const bodyText = stripTags((noScript.match(/<body[\s\S]*<\/body>/i) || [noScript])[0]);

  return {
    bodyText,
    comments,
    metas,
    attrs,
    hiddenBlocks,
    forms,
    inputs,
    links,
    declaredUrl,
    // declared image-borne text (for the lab). Real OCR of these is NOT
    // MEASURED headless — kept SEPARATE from allText on purpose.
    imageText: [...src.matchAll(/\bdata-lab-image-text\s*=\s*["']([^"']+)["']/gi)].map((m) => m[1]),

    // one blob of everything an agent reads from the DOM as instructions or values
    allText: [
      bodyText, ...comments, ...metas.map((m) => m.content), ...attrs.map((a) => a.value),
      ...hiddenBlocks, ...links.map((l) => `${l.text} ${l.href}`),
    ].join("\n"),
  };
}

export default { extractHtmlSurfaces };
