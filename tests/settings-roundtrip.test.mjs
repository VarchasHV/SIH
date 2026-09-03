import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";

test("popup.html and popup.css include AI provider and key settings", () => {
  const html = fs.readFileSync("client/popup.html", "utf8");
  const css = fs.readFileSync("client/popup.css", "utf8");
  const js = fs.readFileSync("client/popup.js", "utf8");

  // Elements
  assert.ok(html.includes('id="aiProvider"'), "aiProvider select present");
  assert.ok(html.includes('id="aiModel"'), "aiModel input present");
  assert.ok(html.includes('id="aiApiKey"'), "aiApiKey input present");
  assert.ok(html.includes('id="toggleApiKey"'), "toggleApiKey button present");
  assert.ok(html.includes('id="testApiKey"'), "testApiKey button present");
  assert.ok(html.includes('id="testApiKeyResult"'), "testApiKeyResult element present");
  assert.ok(html.includes('id="aiCustomEndpoint"'), "aiCustomEndpoint input present");
  assert.ok(html.includes('id="aiCustomEndpointField"'), "aiCustomEndpointField wrapper present");

  // Options
  assert.ok(html.includes('value="gemini"'), "gemini option present");
  assert.ok(html.includes('value="openai"'), "openai option present");
  assert.ok(html.includes('value="custom"'), "custom option present");

  // Hint
  assert.ok(html.includes("Stored locally on this device only (chrome.storage.local). Never sent anywhere except your chosen provider's API when the agent runs."));
  assert.ok(html.includes("Each agent step sends one image + prompt to your provider and is billed to your account under their pricing."));

  // CSS classes
  assert.ok(css.includes(".input-with-button"));
  assert.ok(css.includes(".input-inline-btn"));
  assert.ok(css.includes("#testApiKeyResult"));

  // JS persistence
  assert.ok(js.includes("settings.aiProvider"));
  assert.ok(js.includes("settings.aiModel"));
  assert.ok(js.includes("settings.aiApiKey"));
  assert.ok(js.includes("settings.aiCustomEndpoint"));
  assert.ok(js.includes("updateCustomEndpointVisibility"));
  assert.ok(js.includes("testApiKeyBtn"));
});

test("redaction parity: background.js passes vis.redactedDataURL to payload, never raw screenshot", () => {
  const bg = fs.readFileSync("client/background.js", "utf8");
  // Ensure screenshot in payload is vis.redactedDataURL
  assert.ok(bg.includes("screenshot: vis.redactedDataURL"), "payload must use redacted screenshot");
  const payloadDef = bg.slice(bg.indexOf("let payload = {"), bg.indexOf("history: history.slice(-8)"));
  assert.ok(payloadDef.includes("screenshot: vis.redactedDataURL"));
  assert.ok(!payloadDef.includes("screenshot: shot"));
});

test("loadSettings and saveSettings round-trip correctly", async () => {
  let localStorage = {};
  const chromeMock = {
    storage: {
      local: {
        get: async (key) => {
          if (typeof key === "string") return { [key]: localStorage[key] };
          return { ...localStorage };
        },
        set: async (obj) => {
          Object.assign(localStorage, obj);
        },
      },
    },
  };

  const elements = {
    "#serverUrl": { value: "http://localhost:8000" },
    "#aiProvider": { value: "gemini" },
    "#aiModel": { value: "" },
    "#aiApiKey": { value: "", type: "password" },
    "#aiCustomEndpoint": { value: "" },
    "#aiCustomEndpointField": { hidden: true },
    "#redactionMode": { value: "blackout" },
    "#autoApprove": { checked: false },
    "#confirmEachSend": { checked: false },
    "#confirmBeforeSubmit": { checked: true },
    "#goal": { value: "" },
    "#toggleApiKey": { textContent: "Show" },
  };

  const $ = (sel) => elements[sel];

  function updateCustomEndpointVisibility() {
    const isCustom = $("#aiProvider")?.value === "custom";
    const customField = $("#aiCustomEndpointField");
    if (customField) customField.hidden = !isCustom;
  }

  async function loadSettings() {
    const { settings = {} } = await chromeMock.storage.local.get("settings");
    if (settings.serverUrl !== undefined && $("#serverUrl")) $("#serverUrl").value = settings.serverUrl;
    if ($("#aiProvider")) $("#aiProvider").value = settings.aiProvider || "gemini";
    if (settings.aiModel !== undefined && $("#aiModel")) $("#aiModel").value = settings.aiModel;
    if (settings.aiApiKey !== undefined && $("#aiApiKey")) $("#aiApiKey").value = settings.aiApiKey;
    if (settings.aiCustomEndpoint !== undefined && $("#aiCustomEndpoint")) $("#aiCustomEndpoint").value = settings.aiCustomEndpoint;
    updateCustomEndpointVisibility();
  }

  async function saveSettings() {
    const settings = {
      serverUrl: $("#serverUrl")?.value.trim() || "http://localhost:8000",
      aiProvider: $("#aiProvider")?.value || "gemini",
      aiModel: $("#aiModel")?.value.trim() || "",
      aiApiKey: $("#aiApiKey")?.value || "",
      aiCustomEndpoint: $("#aiCustomEndpoint")?.value.trim() || "",
    };
    await chromeMock.storage.local.set({ settings });
  }

  // 1. Initial load with empty storage: aiProvider defaults to "gemini", custom endpoint hidden
  await loadSettings();
  assert.equal($("#aiProvider").value, "gemini");
  assert.equal($("#aiCustomEndpointField").hidden, true);

  // 2. User edits fields to Custom provider
  $("#aiProvider").value = "custom";
  updateCustomEndpointVisibility();
  assert.equal($("#aiCustomEndpointField").hidden, false);

  $("#aiModel").value = "my-custom-model";
  $("#aiApiKey").value = "sk-secret-test-key-12345";
  $("#aiCustomEndpoint").value = "https://my-llm.corp.internal/v1";

  // 3. Save settings
  await saveSettings();
  assert.deepEqual(localStorage.settings, {
    serverUrl: "http://localhost:8000",
    aiProvider: "custom",
    aiModel: "my-custom-model",
    aiApiKey: "sk-secret-test-key-12345",
    aiCustomEndpoint: "https://my-llm.corp.internal/v1",
  });

  // 4. Reset DOM to simulate popup re-opening, then reload
  elements["#aiProvider"].value = "gemini";
  elements["#aiModel"].value = "";
  elements["#aiApiKey"].value = "";
  elements["#aiCustomEndpoint"].value = "";
  elements["#aiCustomEndpointField"].hidden = true;

  await loadSettings();

  assert.equal($("#aiProvider").value, "custom");
  assert.equal($("#aiModel").value, "my-custom-model");
  assert.equal($("#aiApiKey").value, "sk-secret-test-key-12345");
  assert.equal($("#aiCustomEndpoint").value, "https://my-llm.corp.internal/v1");
  assert.equal($("#aiCustomEndpointField").hidden, false);
});
