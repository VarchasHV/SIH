import test from "node:test";
import assert from "node:assert/strict";
import { requestCloudStep, CloudAuthError, CloudRequestError, SYSTEM_PROMPT } from "../client/lib/cloud-agent-client.mjs";

test("requestCloudStep throws CloudAuthError when apiKey is missing", async () => {
  await assert.rejects(
    async () => {
      await requestCloudStep({ aiProvider: "gemini", aiApiKey: "" }, { taskGoal: "test" });
    },
    (err) => err instanceof CloudAuthError && err.isAuthError
  );
});

test("requestCloudStep formats Gemini request and parses response", async () => {
  const originalFetch = globalThis.fetch;
  let interceptedUrl = null;
  let interceptedHeaders = null;
  let interceptedBody = null;

  globalThis.fetch = async (url, init) => {
    interceptedUrl = url;
    interceptedHeaders = init.headers;
    interceptedBody = JSON.parse(init.body);

    return {
      ok: true,
      status: 200,
      json: async () => ({
        candidates: [
          {
            content: {
              parts: [
                {
                  text: JSON.stringify({
                    rationale: "Filling standard contact fields",
                    actions: [
                      { action: "type", targetId: "name-input", piiCategory: "name" },
                      { action: "type", targetId: "bad-input", literalValue: "my ssn 123-45-6789" }, // should be filtered out
                      { action: "done" },
                    ],
                    done: false,
                  }),
                },
              ],
            },
          },
        ],
      }),
    };
  };

  try {
    const payload = {
      taskGoal: "Fill application",
      step: 1,
      skeleton: { nodes: [{ id: "name-input" }] },
      visionDetections: [],
      screenshot: "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=",
      history: [],
    };

    const res = await requestCloudStep(
      { aiProvider: "gemini", aiModel: "gemini-2.0-flash", aiApiKey: "SECRET_KEY_123" },
      payload
    );

    assert.ok(interceptedUrl.includes("generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent"));
    assert.equal(interceptedHeaders["x-goog-api-key"], "SECRET_KEY_123");
    assert.equal(interceptedBody.systemInstruction.parts[0].text, SYSTEM_PROMPT);
    assert.equal(interceptedBody.contents[0].parts[1].inlineData.mimeType, "image/png");

    assert.equal(res.rationale, "Filling standard contact fields");
    assert.equal(res.done, false);
    // Verified safety filter removed the action with literal restricted PII
    assert.equal(res.actions.length, 2);
    assert.equal(res.actions[0].targetId, "name-input");
    assert.equal(res.actions[1].action, "done");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("requestCloudStep formats OpenAI request with Bearer token", async () => {
  const originalFetch = globalThis.fetch;
  let interceptedUrl = null;
  let interceptedHeaders = null;
  let interceptedBody = null;

  globalThis.fetch = async (url, init) => {
    interceptedUrl = url;
    interceptedHeaders = init.headers;
    interceptedBody = JSON.parse(init.body);

    return {
      ok: true,
      status: 200,
      json: async () => ({
        choices: [
          {
            message: {
              content: JSON.stringify({
                rationale: "All complete",
                actions: [{ action: "done" }],
                done: true,
              }),
            },
          },
        ],
      }),
    };
  };

  try {
    const payload = {
      taskGoal: "Done test",
      step: 2,
      skeleton: { nodes: [] },
      visionDetections: [],
      screenshot: "data:image/png;base64,abc",
      history: [],
    };

    const res = await requestCloudStep(
      { aiProvider: "openai", aiModel: "gpt-4o-mini", aiApiKey: "sk-openai-key" },
      payload
    );

    assert.equal(interceptedUrl, "https://api.openai.com/v1/chat/completions");
    assert.equal(interceptedHeaders["Authorization"], "Bearer sk-openai-key");
    assert.equal(interceptedBody.model, "gpt-4o-mini");
    assert.equal(interceptedBody.messages[0].role, "system");
    assert.equal(interceptedBody.messages[1].content[1].type, "image_url");

    assert.equal(res.done, true);
    assert.equal(res.actions.length, 1);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("requestCloudStep throws CloudAuthError on 401/403 and does not leak API key", async () => {
  const originalFetch = globalThis.fetch;
  const SECRET = "secret-super-private-key-99999";

  globalThis.fetch = async () => ({
    ok: false,
    status: 401,
    text: async () => `Unauthorized invalid key=${SECRET}`,
  });

  try {
    await assert.rejects(
      async () => {
        await requestCloudStep(
          { aiProvider: "gemini", aiApiKey: SECRET },
          { taskGoal: "test" }
        );
      },
      (err) => {
        assert.ok(err instanceof CloudAuthError);
        assert.ok(err.isAuthError);
        assert.ok(!err.message.includes(SECRET), "Error message must never leak the API key");
        return true;
      }
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("testConnection returns success for valid Gemini and OpenAI responses", async () => {
  const originalFetch = globalThis.fetch;

  // Gemini test
  globalThis.fetch = async (url) => {
    assert.ok(url.includes("models/gemini-2.0-flash:generateContent"));
    return {
      ok: true,
      status: 200,
      json: async () => ({ candidates: [{ content: { parts: [{ text: "OK" }] } }] }),
    };
  };

  try {
    const { testConnection } = await import("../client/lib/cloud-agent-client.mjs");
    const geminiRes = await testConnection({ aiProvider: "gemini", aiApiKey: "fake-key" });
    assert.equal(geminiRes.ok, true);
    assert.equal(geminiRes.message, "✓ Connected");

    // OpenAI test
    globalThis.fetch = async (url) => {
      assert.ok(url.includes("api.openai.com/v1/chat/completions"));
      return {
        ok: true,
        status: 200,
        json: async () => ({ choices: [{ message: { content: "OK" } }] }),
      };
    };

    const openaiRes = await testConnection({ aiProvider: "openai", aiApiKey: "fake-openai-key" });
    assert.equal(openaiRes.ok, true);
    assert.equal(openaiRes.message, "✓ Connected");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("testConnection handles auth failure and redacts secret key from errors", async () => {
  const originalFetch = globalThis.fetch;
  const SECRET = "very-confidential-api-key-12345";

  globalThis.fetch = async () => ({
    ok: false,
    status: 401,
    json: async () => ({ error: { message: `Bad request with key=${SECRET}` } }),
  });

  try {
    const { testConnection } = await import("../client/lib/cloud-agent-client.mjs");
    const res = await testConnection({ aiProvider: "gemini", aiApiKey: SECRET });
    assert.equal(res.ok, false);
    assert.ok(res.message.includes("401/403"));
    assert.ok(!res.message.includes(SECRET), "Secret key must not leak in test message");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

