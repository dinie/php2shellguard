importScripts("config.js");
// Deploy-time default comes from api-config.json (see config.js).
const defaultApiBasePromise = loadDefaultApiBase();

const tabStatus = new Map();

const BADGES = {
  vulnerable: { text: "VULN", color: "#dc2626" },
  patched: { text: "OK", color: "#16a34a" },
  unknown: { text: "?", color: "#d97706" },
  not_php: { text: "", color: "#64748b" },
  offline: { text: "OFF", color: "#f59e0b" },
};

async function getApiBase() {
  const fallback = await defaultApiBasePromise;
  const { apiBase } = await chrome.storage.sync.get({ apiBase: fallback });
  return (apiBase || fallback).replace(/\/+$/, "");
}

function extractHeaders(responseHeaders) {
  const payload = { server: null, x_powered_by: null, cookie_names: [] };
  for (const header of responseHeaders || []) {
    const name = header.name.toLowerCase();
    if (name === "server") {
      payload.server = header.value || null;
    } else if (name === "x-powered-by") {
      payload.x_powered_by = header.value || null;
    } else if (name === "set-cookie") {
      const cookieName = (header.value || "").split("=")[0].trim();
      if (cookieName) payload.cookie_names.push(cookieName);
    }
  }
  return payload;
}

function safeHost(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return null;
  }
}

async function setBadge(tabId, status) {
  const badge = BADGES[status] || BADGES.unknown;
  await chrome.action.setBadgeText({ tabId, text: badge.text });
  if (badge.text) {
    await chrome.action.setBadgeBackgroundColor({ tabId, color: badge.color });
  }
}

async function analyseTab(tabId, url, headers) {
  let result;
  try {
    const apiBase = await getApiBase();
    const response = await fetch(`${apiBase}/api/v1/check`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, ...headers }),
    });
    if (!response.ok) throw new Error(`backend responded ${response.status}`);
    result = await response.json();
  } catch (error) {
    result = {
      status: "offline",
      host: safeHost(url),
      reason: `Backend unreachable: ${error.message}`,
    };
  }
  tabStatus.set(tabId, result);
  await setBadge(tabId, result.status);
}

chrome.webRequest.onCompleted.addListener(
  (details) => {
    if (details.tabId < 0) return;
    if (!/^https?:/.test(details.url)) return;
    analyseTab(
      details.tabId,
      details.url,
      extractHeaders(details.responseHeaders)
    );
  },
  { urls: ["http://*/*", "https://*/*"], types: ["main_frame"] },
  ["responseHeaders"]
);

chrome.tabs.onRemoved.addListener((tabId) => tabStatus.delete(tabId));

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message && message.type === "getTabStatus") {
    sendResponse(
      tabStatus.get(message.tabId) || {
        status: "pending",
        reason: "No response headers observed for this tab yet.",
      }
    );
  }
  return false;
});
