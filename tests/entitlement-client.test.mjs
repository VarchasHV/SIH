// The extension must treat the server's 401/402/403 responses as authoritative
// and never invent its own allow/deny decision — these tests pin that
// contract at the fetch-wrapper level (agent-client.requestStep and
// auth-client.authFetch), independent of the full background.js loop.
import test from "node:test";
import assert from "node:assert/strict";
import { requestStep } from "../client/lib/agent-client.mjs";

function mockFetchOnce(status, body, { headerCheck } = {}) {
  const calls = [];
  globalThis.fetch = async (url, init) => {
    calls.push({ url, init });
    if (headerCheck) headerCheck(init.headers || {});
    return {
      ok: status >= 200 && status < 300,
      status,
      json: async () => body,
    };
  };
  return calls;
}

test("requestStep surfaces a 402 usage-limit response as isUpgradeRequired, not a generic error", async () => {
  mockFetchOnce(402, {
    detail: { error: "usage_limit_reached", operation: "agent_step", plan: "EXPLORER", used: 15, limit: 15, period: "day", message: "limit reached" },
  });
  await assert.rejects(
    () => requestStep("http://localhost:8000", { taskGoal: "x", skeleton: { viewport: {}, nodes: [] } }),
    (err) => {
      assert.equal(err.isUpgradeRequired, true);
      assert.equal(err.detail.error, "usage_limit_reached");
      assert.equal(err.detail.limit, 15);
      return true;
    }
  );
});

test("requestStep surfaces a 403 upgrade_required feature-gate response as isUpgradeRequired", async () => {
  mockFetchOnce(403, { detail: { error: "upgrade_required", feature: "SECURITY_ANALYSIS", plan: "EXPLORER" } });
  await assert.rejects(
    () => requestStep("http://localhost:8000", { taskGoal: "x", skeleton: { viewport: {}, nodes: [] } }),
    (err) => {
      assert.equal(err.isUpgradeRequired, true);
      assert.equal(err.detail.feature, "SECURITY_ANALYSIS");
      return true;
    }
  );
});

test("requestStep surfaces a 401 as isAuthRequired", async () => {
  mockFetchOnce(401, { detail: "Missing bearer token." });
  await assert.rejects(
    () => requestStep("http://localhost:8000", { taskGoal: "x", skeleton: { viewport: {}, nodes: [] } }),
    (err) => {
      assert.equal(err.isAuthRequired, true);
      return true;
    }
  );
});

test("requestStep attaches the access token as a Bearer header when provided", async () => {
  let seenAuth = null;
  mockFetchOnce(200, { actions: [], done: true }, {
    headerCheck: (headers) => { seenAuth = headers.authorization; },
  });
  await requestStep("http://localhost:8000", { taskGoal: "x", skeleton: { viewport: {}, nodes: [] } }, { accessToken: "tok_abc" });
  assert.equal(seenAuth, "Bearer tok_abc");
});

test("requestStep sends no Authorization header when no token is supplied (server will reject with 401)", async () => {
  let seenAuth = "unset";
  mockFetchOnce(200, { actions: [], done: true }, {
    headerCheck: (headers) => { seenAuth = headers.authorization; },
  });
  await requestStep("http://localhost:8000", { taskGoal: "x", skeleton: { viewport: {}, nodes: [] } });
  assert.equal(seenAuth, undefined);
});
