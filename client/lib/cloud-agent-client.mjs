// Client-side direct cloud VLM agent adapter.
// Supports Google Gemini, OpenAI, and custom OpenAI-compatible endpoints using
// the user's locally stored API key without touching the local FastAPI server.

export class CloudAuthError extends Error {
  constructor(message = "Cloud API key unauthorized or rejected (HTTP 401/403)") {
    super(message);
    this.name = "CloudAuthError";
    this.isAuthError = true;
    this.isCloud = true;
  }
}

export class CloudRequestError extends Error {
  constructor(message, status = null) {
    super(message);
    this.name = "CloudRequestError";
    this.status = status;
    this.isCloud = true;
  }
}

// Canonical CONNOR system directive matching server/prompts/system.md
export const SYSTEM_PROMPT = `# **CONNOR SYSTEM DIRECTIVE: TOKENIZED FORM FILLING & REDACTION COMPLIANCE**

You are the reasoning half of a privacy-preserving browser agent. A lightweight client runs on the user's machine, reads their screen, redacts sensitive visual areas with solid black boxes, and generates an accessibility skeleton containing **zero real personal data**.

## What you receive each step
- \`taskGoal\` — what the user wants done.
- \`screenshot\` — the page, **with sensitive PII blacked out with solid black boxes**.
- \`skeleton\` — the interactable elements. Each node has a stable \`id\`, \`label\`, \`state\` (\`empty\` / \`filled\` / \`readonly\` / \`disabled\`), \`isCensored\` (boolean), \`hasFill\` (boolean), \`fillToken\` (e.g. \`local:ssn\`, \`local:first name\`), and \`piiCategory\`.
- \`visionDetections\` — PII regions the client found and redacted.
- \`history\` — your previous actions and their results.

## What you return
A JSON object: \`{ "rationale": "...", "actions": [ ... ], "done": bool }\`.

Each action is one of:
| action | fields | meaning |
|---|---|---|
| \`type\`   | \`targetId\`, \`piiCategory\` **or** \`fillToken\` **or** \`literalValue\` | put a value in a field |
| \`select\` | \`targetId\`, \`literalValue\` | choose a dropdown option |
| \`click\`  | \`targetId\` | click a button / link / checkbox |
| \`scroll\` | \`targetId\` (optional) | bring an element into view |
| \`submit\` | \`targetId\` (a submit button) | submit the form |
| \`wait\`   | \`ms\` (optional) | pause |
| \`done\`   | — | task finished |

## Rules
1. **Filling Censored & Tokenized Fields (\`isCensored: true\`, \`hasFill: true\`):**
   - You MAY target fields where \`isCensored: true\` IF \`hasFill: true\` or a \`fillToken\` (e.g., \`local:ssn\`, \`local:aadhaar\`) is available.
   - Emit \`type\` with \`fillToken\` = \`node.fillToken\` (or \`piiCategory\` = \`node.piiCategory\`).
   - The client extension will resolve the token locally from the user's secure vault and type the real value on device.
   - **NEVER invent, guess, or put raw secret data or dummy numbers into \`literalValue\`.**
2. **Filling Plain Profile Fields:**
   - Emit \`type\` with \`piiCategory\` = that field's \`piiCategory\` (or \`fillToken\`).
3. **Using \`literalValue\`:**
   - Use \`literalValue\` ONLY for non-personal selections (e.g. "I agree" checkboxes, selecting country "India" from dropdowns).
4. **Fields You Cannot Fill — skip them, never retry:**
   - \`isCensored: true, hasFill: false\` — no local secret available.
   - \`hasFill: false\` and no \`fillToken\` on a plain text field — no profile value available.
   - \`state\` is \`readonly\`, \`disabled\`, \`filled\`, or the node has \`skip: true\` — already handled or retired by the client.
   - If you already emitted a \`type\`/\`select\` for a field in a previous step and \`history\` shows it did not become \`filled\`, the client has no data for it. **Do not target it again.**
5. **Form Submission:**
   - Only \`submit\` if \`taskGoal\` explicitly asks to submit. If it says "stop before submitting" / "do not submit", finish with \`done\` instead once fields are filled.
6. Return 1–4 actions per step. **Emit \`done: true\` as soon as every field you are able to fill has been filled** — do not invent extra work, do not re-touch filled fields, do not wait. An empty \`actions\` list with \`done: true\` is the correct response when nothing actionable remains.

Respond with **only** the JSON object, no prose around it.`;

const RESTRICTED_PII_RE =
  /\b(password|passwd|passcode|aadhaar|aadhar|uidai|\bpan\b|\bssn\b|credit[_\s]?card|debit[_\s]?card|\bcvv\b|\bcvc\b|bank[_\s]?account|account[_\s]?no|routing|ifsc|upi|passport|govt[_\s]?id|national[_\s]?id|voter[_\s]?id|\bepic\b|driver[_\s]?license)\b/i;

function cleanActions(actions) {
  if (!Array.isArray(actions)) return [];
  return actions.filter((act) => {
    if (!act || typeof act !== "object") return false;
    const val = act.literalValue || "";
    return !RESTRICTED_PII_RE.test(val);
  });
}

function splitDataUrl(dataUrl) {
  if (!dataUrl) return null;
  const m = String(dataUrl).match(/^data:([^;]+);base64,(.*)$/s);
  return m ? { mimeType: m[1], base64Data: m[2] } : null;
}

function formatContextJson(payload) {
  return JSON.stringify({
    taskGoal: payload.taskGoal || "",
    step: payload.step || 1,
    skeleton: payload.skeleton || { nodes: [] },
    visionDetections: payload.visionDetections || [],
    history: payload.history || [],
  });
}

function extractJson(text) {
  if (!text || typeof text !== "string") return {};
  const cleaned = text.trim().replace(/^```(?:json)?\s*|\s*```$/gi, "").trim();
  try {
    return JSON.parse(cleaned);
  } catch {
    const firstBrace = cleaned.indexOf("{");
    const lastBrace = cleaned.lastIndexOf("}");
    if (firstBrace !== -1 && lastBrace > firstBrace) {
      return JSON.parse(cleaned.slice(firstBrace, lastBrace + 1));
    }
    throw new Error("Model response did not contain valid JSON");
  }
}

/**
 * Fetch with timeout, authentication check, and 429/5xx retry backoff.
 * Never leaks the API key in error messages.
 */
async function fetchWithRetry(url, init, timeoutMs = 45000, maxTries = 3) {
  let lastErr = null;
  for (let attempt = 1; attempt <= maxTries; attempt++) {
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), timeoutMs);
    try {
      const res = await fetch(url, { ...init, signal: ctl.signal });
      clearTimeout(timer);

      if (res.status === 401 || res.status === 403) {
        throw new CloudAuthError(`Authentication failed (${res.status}): check your API key.`);
      }

      if (!res.ok) {
        let errSnippet = "";
        try {
          const bodyText = await res.text();
          errSnippet = bodyText.slice(0, 160).replace(/key=[^&"'\s]+/gi, "key=[REDACTED]");
        } catch {
          // ignore
        }

        const isRetryable = res.status === 429 || (res.status >= 500 && res.status <= 599);
        if (isRetryable && attempt < maxTries) {
          const backoffMs = attempt * 1200;
          await new Promise((r) => setTimeout(r, backoffMs));
          continue;
        }

        throw new CloudRequestError(`HTTP ${res.status}${errSnippet ? `: ${errSnippet}` : ""}`, res.status);
      }

      return await res.json();
    } catch (err) {
      clearTimeout(timer);
      if (err instanceof CloudAuthError) {
        throw err;
      }
      if (err.name === "AbortError") {
        const timeoutErr = new CloudRequestError(`Cloud AI request timed out after ${timeoutMs}ms`);
        timeoutErr.isTimeout = true;
        throw timeoutErr;
      }
      lastErr = err;
      if (attempt < maxTries && !err.isAuthError) {
        await new Promise((r) => setTimeout(r, attempt * 1000));
      }
    }
  }
  throw lastErr || new CloudRequestError("Cloud request failed");
}

/**
 * @param {object} settings  - { aiProvider, aiModel, aiApiKey, aiCustomEndpoint }
 * @param {object} payload   - { taskGoal, step, skeleton, visionDetections, screenshot, history }
 * @param {object} opts      - { timeoutMs?: number }
 */
export async function requestCloudStep(settings, payload, opts = {}) {
  const { timeoutMs = 45000 } = opts;
  const provider = settings.aiProvider || "gemini";
  const apiKey = (settings.aiApiKey || "").trim();

  if (!apiKey) {
    throw new CloudAuthError("No API key configured for cloud agent call.");
  }

  const started = performance.now();

  let parsedResponse = null;

  if (provider === "gemini") {
    const model = (settings.aiModel || "").trim() || "gemini-2.0-flash";
    const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent`;

    const parts = [{ text: formatContextJson(payload) }];
    const img = splitDataUrl(payload.screenshot);
    if (img) {
      parts.push({ inlineData: { mimeType: img.mimeType, data: img.base64Data } });
    }

    const body = {
      systemInstruction: { parts: [{ text: SYSTEM_PROMPT }] },
      contents: [{ role: "user", parts }],
      generationConfig: {
        temperature: 0,
        maxOutputTokens: 4096,
        responseMimeType: "application/json",
      },
    };

    const data = await fetchWithRetry(
      endpoint,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-goog-api-key": apiKey,
        },
        body: JSON.stringify(body),
      },
      timeoutMs
    );

    if (data.error) {
      throw new CloudRequestError(`Gemini error: ${data.error.message || data.error.code || "unknown"}`);
    }

    const candidate = data.candidates?.[0];
    if (!candidate) {
      throw new CloudRequestError("Gemini returned no response candidates");
    }

    const textParts = candidate.content?.parts?.filter((p) => !p.thought) || [];
    const rawText = textParts.map((p) => p.text || "").join("");
    if (!rawText) {
      throw new CloudRequestError(`Gemini returned empty content (finishReason: ${candidate.finishReason || "?"})`);
    }

    parsedResponse = extractJson(rawText);
  } else if (provider === "openai" || provider === "custom") {
    const isCustom = provider === "custom";
    let endpoint = isCustom ? (settings.aiCustomEndpoint || "").trim().replace(/\/+$/, "") : "https://api.openai.com/v1";

    if (isCustom && !endpoint) {
      throw new CloudRequestError("Custom AI endpoint URL is required when using custom provider.");
    }

    if (!endpoint.endsWith("/chat/completions")) {
      endpoint = `${endpoint}/chat/completions`;
    }

    const defaultModel = isCustom ? "default" : "gpt-4o-mini";
    const model = (settings.aiModel || "").trim() || defaultModel;

    const content = [{ type: "text", text: formatContextJson(payload) }];
    if (payload.screenshot && payload.screenshot.startsWith("data:image")) {
      content.push({ type: "image_url", image_url: { url: payload.screenshot } });
    }

    const body = {
      model,
      messages: [
        { role: "system", content: SYSTEM_PROMPT },
        { role: "user", content },
      ],
      temperature: 0,
      response_format: { type: "json_object" },
    };

    const data = await fetchWithRetry(
      endpoint,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          Authorization: `Bearer ${apiKey}`,
        },
        body: JSON.stringify(body),
      },
      timeoutMs
    );

    if (data.error) {
      throw new CloudRequestError(`API error: ${data.error.message || data.error.code || "unknown"}`);
    }

    const choice = data.choices?.[0];
    const rawText = choice?.message?.content || "";
    if (!rawText) {
      throw new CloudRequestError("Provider returned empty message content");
    }

    parsedResponse = extractJson(rawText);
  } else {
    throw new CloudRequestError(`Unknown AI provider: "${provider}"`);
  }

  const roundTripMs = performance.now() - started;

  return {
    actions: cleanActions(parsedResponse?.actions),
    rationale: parsedResponse?.rationale || "",
    done: !!parsedResponse?.done,
    serverLatencyMs: Math.round(roundTripMs),
    roundTripMs: Math.round(roundTripMs),
  };
}

function escapeRegex(s) {
  return String(s || "").replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function sanitizeErrorMessage(msg, apiKey) {
  let clean = String(msg || "Request failed");
  if (apiKey) {
    clean = clean.replace(new RegExp(escapeRegex(apiKey), "gi"), "[REDACTED]");
  }
  return clean.replace(/key=[^&"'\s]+/gi, "key=[REDACTED]");
}

/**
 * Lightweight connection test that makes a minimal prompt request
 * without sending screenshots or user payloads.
 * @param {object} settings - { aiProvider, aiModel, aiApiKey, aiCustomEndpoint }
 * @returns {Promise<{ ok: boolean, message: string }>}
 */
export async function testConnection(settings = {}) {
  const provider = settings.aiProvider || "gemini";
  const apiKey = (settings.aiApiKey || "").trim();

  if (!apiKey) {
    return { ok: false, message: "No API key entered" };
  }

  const timeoutMs = 15000;
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeoutMs);

  try {
    if (provider === "gemini") {
      const model = (settings.aiModel || "").trim() || "gemini-2.0-flash";
      const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent`;

      const body = {
        contents: [{ role: "user", parts: [{ text: "ping" }] }],
        generationConfig: {
          maxOutputTokens: 10,
          temperature: 0,
        },
      };

      const res = await fetch(endpoint, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-goog-api-key": apiKey,
        },
        body: JSON.stringify(body),
        signal: ctl.signal,
      });

      if (res.status === 401 || res.status === 403) {
        return { ok: false, message: "API key invalid or unauthorized (401/403)" };
      }

      let data = {};
      try {
        data = await res.json();
      } catch {
        // ignore parse error if response is not json
      }

      if (!res.ok || data?.error) {
        const errDesc = data?.error?.message || `HTTP ${res.status}`;
        return { ok: false, message: sanitizeErrorMessage(errDesc, apiKey) };
      }

      return { ok: true, message: "✓ Connected" };
    } else if (provider === "openai" || provider === "custom") {
      const isCustom = provider === "custom";
      let endpoint = isCustom
        ? (settings.aiCustomEndpoint || "").trim().replace(/\/+$/, "")
        : "https://api.openai.com/v1";

      if (isCustom && !endpoint) {
        return { ok: false, message: "Custom endpoint URL is required" };
      }

      if (!endpoint.endsWith("/chat/completions")) {
        endpoint = `${endpoint}/chat/completions`;
      }

      const defaultModel = isCustom ? "default" : "gpt-4o-mini";
      const model = (settings.aiModel || "").trim() || defaultModel;

      const body = {
        model,
        messages: [{ role: "user", content: "ping" }],
        max_tokens: 5,
        temperature: 0,
      };

      const res = await fetch(endpoint, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          Authorization: `Bearer ${apiKey}`,
        },
        body: JSON.stringify(body),
        signal: ctl.signal,
      });

      if (res.status === 401 || res.status === 403) {
        return { ok: false, message: "API key invalid or unauthorized (401/403)" };
      }

      let data = {};
      try {
        data = await res.json();
      } catch {
        // ignore parse error if response is not json
      }

      if (!res.ok || data?.error) {
        const errDesc = data?.error?.message || `HTTP ${res.status}`;
        return { ok: false, message: sanitizeErrorMessage(errDesc, apiKey) };
      }

      return { ok: true, message: "✓ Connected" };
    } else {
      return { ok: false, message: `Unknown provider: ${provider}` };
    }
  } catch (err) {
    if (err.name === "AbortError") {
      return { ok: false, message: "Connection timed out (15s)" };
    }
    return { ok: false, message: sanitizeErrorMessage(err.message || "Network error", apiKey) };
  } finally {
    clearTimeout(timer);
  }
}

export default { requestCloudStep, testConnection, CloudAuthError, CloudRequestError, SYSTEM_PROMPT };
