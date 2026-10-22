/* Shared API base resolution.
 *
 * Loaded by background.js via importScripts() and by popup.html via <script>.
 * Priority (first match wins):
 *   1. chrome.storage.sync "apiBase" — per-user override (Backend settings)
 *   2. api-config.json bundled with the extension — deploy-time default
 *   3. FALLBACK_API_BASE — last-resort default if the config file is missing
 */

const FALLBACK_API_BASE = "http://localhost:8000";

async function loadDefaultApiBase() {
  try {
    const response = await fetch(chrome.runtime.getURL("api-config.json"));
    const config = await response.json();
    if (config && typeof config.apiBase === "string" && config.apiBase.trim()) {
      return config.apiBase.trim().replace(/\/+$/, "");
    }
  } catch (error) {
    console.warn("api-config.json unavailable, using built-in default:", error);
  }
  return FALLBACK_API_BASE;
}
