// Authentication client: signup/login/refresh/logout against the local
// CONNOR server, and a token store in chrome.storage.local.
//
// IMPORTANT: nothing in this module is an authority on entitlement. A token
// stored here is only a bearer credential — every privileged call still gets
// its allow/deny decision from the server (see entitlement-client.mjs and
// the 401/402/403 handling in agent-client.mjs / background.js). If this
// storage is cleared, edited, or forged, the worst a user can do is log
// themselves out or send a request that gets rejected — they cannot grant
// themselves a plan they don't have server-side.

const STORAGE_KEY = "connor_auth";

async function readAuth() {
  const { [STORAGE_KEY]: auth } = await chrome.storage.local.get(STORAGE_KEY);
  return auth || null;
}

async function writeAuth(auth) {
  await chrome.storage.local.set({ [STORAGE_KEY]: auth });
}

export async function clearAuth() {
  await chrome.storage.local.remove(STORAGE_KEY);
}

async function postJson(serverUrl, path, body) {
  const res = await fetch(`${serverUrl.replace(/\/$/, "")}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body || {}),
  });
  let data = {};
  try { data = await res.json(); } catch { /* empty body, e.g. 204 */ }
  if (!res.ok) {
    const err = new Error(typeof data.detail === "string" ? data.detail : (data.detail?.message || `HTTP ${res.status}`));
    err.status = res.status;
    err.detail = data.detail;
    throw err;
  }
  return data;
}

function toStored(tokenResponse) {
  return {
    accessToken: tokenResponse.access_token,
    refreshToken: tokenResponse.refresh_token,
    expiresAt: Date.now() + Math.max(0, (tokenResponse.expires_in || 0) - 30) * 1000, // 30s safety margin
  };
}

export async function signup(serverUrl, email, password) {
  const data = await postJson(serverUrl, "/auth/signup", { email, password });
  await writeAuth(toStored(data));
  return { ok: true };
}

export async function login(serverUrl, email, password) {
  const data = await postJson(serverUrl, "/auth/login", { email, password });
  await writeAuth(toStored(data));
  return { ok: true };
}

export async function logout(serverUrl) {
  const auth = await readAuth();
  if (auth?.refreshToken) {
    try { await postJson(serverUrl, "/auth/logout", { refresh_token: auth.refreshToken }); } catch { /* best effort */ }
  }
  await clearAuth();
}

export async function isLoggedIn() {
  const auth = await readAuth();
  return !!auth?.refreshToken;
}

let _refreshInFlight = null;

async function refresh(serverUrl) {
  const auth = await readAuth();
  if (!auth?.refreshToken) throw Object.assign(new Error("Not logged in."), { isAuthRequired: true });
  if (!_refreshInFlight) {
    _refreshInFlight = postJson(serverUrl, "/auth/refresh", { refresh_token: auth.refreshToken })
      .then(async (data) => { await writeAuth(toStored(data)); return data; })
      .catch(async (err) => { await clearAuth(); throw Object.assign(err, { isAuthRequired: true }); })
      .finally(() => { _refreshInFlight = null; });
  }
  return _refreshInFlight;
}

/** Returns a currently-valid access token, refreshing if it's expired/near-expiry. */
export async function getAccessToken(serverUrl) {
  const auth = await readAuth();
  if (!auth?.accessToken) throw Object.assign(new Error("Not logged in."), { isAuthRequired: true });
  if (Date.now() >= auth.expiresAt) {
    const refreshed = await refresh(serverUrl);
    return refreshed.access_token;
  }
  return auth.accessToken;
}

/**
 * Fetch wrapper that attaches a bearer token and retries once after a
 * refresh if the server says the token is invalid/expired.
 */
export async function authFetch(serverUrl, path, init = {}) {
  const base = serverUrl.replace(/\/$/, "");
  let token = await getAccessToken(serverUrl);
  let res = await fetch(`${base}${path}`, {
    ...init,
    headers: { ...(init.headers || {}), Authorization: `Bearer ${token}` },
  });
  if (res.status === 401) {
    token = (await refresh(serverUrl)).access_token;
    res = await fetch(`${base}${path}`, {
      ...init,
      headers: { ...(init.headers || {}), Authorization: `Bearer ${token}` },
    });
  }
  return res;
}

export default { signup, login, logout, isLoggedIn, getAccessToken, authFetch, clearAuth };
