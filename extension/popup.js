// Deploy-time default comes from api-config.json (see config.js, loaded via popup.html).
const defaultApiBasePromise = loadDefaultApiBase();

const LABELS = {
  vulnerable: "Vulnerable",
  patched: "Patched",
  unknown: "Undetermined",
  not_php: "No PHP evidence",
  offline: "Backend offline",
  pending: "Checking…",
};

async function getApiBase() {
  const fallback = await defaultApiBasePromise;
  const { apiBase } = await chrome.storage.sync.get({ apiBase: fallback });
  return (apiBase || fallback).replace(/\/+$/, "");
}

async function activeTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

function getTabStatus(tabId) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({ type: "getTabStatus", tabId }, resolve);
  });
}

function render(status, apiBase) {
  const verdict = document.getElementById("verdict");
  const label = LABELS[status.status] || status.status;
  verdict.textContent = label;
  verdict.className = `verdict verdict-${status.status}`;
  document.getElementById("status-card").className = `card card-${status.status}`;

  const host = status.host || "";
  document.getElementById("host").textContent = host;
  document.getElementById("reason").textContent = status.reason || "";

  const details = document.getElementById("details");
  if (status.php_version) {
    details.hidden = false;
    document.getElementById("php-version").textContent = status.php_version;
    document.getElementById("patched-version").textContent =
      status.patched_version || "—";
  }

  if (Array.isArray(status.cves) && status.status === "vulnerable") {
    document.getElementById("cve-card").hidden = false;
    const list = document.getElementById("cve-list");
    list.replaceChildren(
      ...status.cves.map((cve) => {
        const li = document.createElement("li");
        li.textContent = `${cve.id} · CVSS ${cve.cvss} — ${cve.title}`;
        return li;
      })
    );
  }

  if (host && ["vulnerable", "patched", "unknown"].includes(status.status)) {
    const reportLink = document.getElementById("report-link");
    reportLink.href = `${apiBase}/hosts/${encodeURIComponent(host)}`;
    reportLink.hidden = false;
  }
}

async function init() {
  const apiBase = await getApiBase();
  document.getElementById("dashboard-link").href = `${apiBase}/`;
  const input = document.getElementById("api-base");
  input.value = apiBase;
  input.placeholder = await defaultApiBasePromise;

  const tab = await activeTab();
  if (!tab || tab.id === undefined) {
    render({ status: "pending", reason: "No active tab." }, apiBase);
    return;
  }
  const status = await getTabStatus(tab.id);
  render(status || { status: "pending" }, apiBase);
}

document.getElementById("save-settings").addEventListener("click", async () => {
  const value = document.getElementById("api-base").value.trim();
  await chrome.storage.sync.set({
    apiBase: value || (await defaultApiBasePromise),
  });
  const saved = document.getElementById("settings-saved");
  saved.hidden = false;
  setTimeout(() => (saved.hidden = true), 1500);
});

init();
