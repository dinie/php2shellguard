# PHP2Shell Guard — Firefox build

Firefox equivalent of the Chrome extension in `../extension`. Everything
except `manifest.json` is an exact copy — `background.js`, `config.js`,
`popup.*`, `api-config.json`, and `icons/` mirror the Chrome sources, so
**update both directories whenever you touch shared code** (or script the
sync later if it grows painful).

## Differences from the Chrome build

- Firefox MV3 uses an event page (`background.scripts`) instead of a service
  worker; `background.js` detects this and silently skips `importScripts`
  (config.js is already loaded by the manifest).
- `browser_specific_settings.gecko` carries an ID so `storage.sync`
  (Backend settings) works, plus the data-collection category AMO requires
  (`websiteActivity` — observed URLs go to your configured backend).
- Code keeps the `chrome.*` namespace throughout: Firefox 127+ implements it
  with promises, so no source changes were needed.

## Install

Temporary (development):

1. Open `about:debugging#/runtime/this-firefox`.
2. **Load Temporary Add-on…** → select `manifest.json` from this directory.

Persistent install either means signing (`web-ext sign`, needs AMO API keys)
or `about:config` → `xpinstall.signatures.required = false` (Nightly/ESR only).

## Configuration

Same as Chrome:

- Deploy-time backend default — edit `api-config.json`.
- Per-user override — popup → *Backend settings*.
