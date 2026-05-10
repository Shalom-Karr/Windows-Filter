# skfilter browser extension

Companion extension for the skfilter local firewall dashboard. When you navigate to a site that isn't on your allowlist, this extension redirects the tab to the dashboard's "Request access" page.

The firewall itself does the actual blocking — the extension is only there for UX (so you see a friendly page instead of a connection-refused error).

## Install (Chrome / Edge — Developer Mode)

1. Open `chrome://extensions` (or `edge://extensions`).
2. Toggle **Developer mode** in the top-right.
3. Click **Load unpacked** and select this `extension` folder.
4. Pin the extension if you'd like the icon visible in the toolbar.

## Install (Firefox)

1. Open `about:debugging#/runtime/this-firefox`.
2. Click **Load Temporary Add-on**, pick `manifest.json`.
3. Note: Firefox unloads temporary add-ons on browser restart. For permanent install, see [extension force-install via policies] in the main project README.

## How it works

On every navigation:
1. The background script extracts the destination hostname.
2. It hits `https://127.0.0.1:8765/api/check?domain=<host>` on the local dashboard.
3. If the dashboard says `allowed: false`, the tab is redirected to `https://127.0.0.1:8765/blocked?url=<original>`.

If the dashboard is unreachable, the extension does nothing — your local firewall is still the real enforcement.

The first time you hit the dashboard you'll see a self-signed cert warning. Click through once per browser; the extension caches its own connection.
