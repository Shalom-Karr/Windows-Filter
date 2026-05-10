// skfilter background service worker.
// On every top-level navigation, ask the local dashboard whether the
// destination host is on the allowlist. If not, redirect the tab to the
// dashboard's /blocked page. The Windows firewall does the real enforcement;
// this exists purely so the user sees a friendly page instead of a timeout.

const DASHBOARD = 'https://127.0.0.1:8765';
const CACHE_TTL_MS = 30 * 1000;
const cache = new Map(); // hostname -> { allowed: bool, expires: number }

const SKIP_HOSTS = new Set(['127.0.0.1', 'localhost', '[::1]', '::1']);

function shouldSkip(url) {
  if (!url) return true;
  if (!/^https?:/i.test(url)) return true;
  let parsed;
  try { parsed = new URL(url); } catch { return true; }
  const host = parsed.hostname;
  if (!host) return true;
  if (SKIP_HOSTS.has(host)) return true;
  return false;
}

async function checkHost(host) {
  const now = Date.now();
  const hit = cache.get(host);
  if (hit && hit.expires > now) return hit.allowed;

  const checkUrl = `${DASHBOARD}/api/check?domain=${encodeURIComponent(host)}`;
  const res = await fetch(checkUrl, { credentials: 'omit', cache: 'no-store' });
  if (!res.ok) throw new Error(`check returned ${res.status}`);
  const body = await res.json();
  const allowed = body && body.allowed === true;
  cache.set(host, { allowed, expires: now + CACHE_TTL_MS });
  return allowed;
}

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return;
  if (shouldSkip(details.url)) return;

  let host;
  try { host = new URL(details.url).hostname; } catch { return; }

  try {
    const allowed = await checkHost(host);
    if (allowed) return;
    const target = `${DASHBOARD}/blocked?url=${encodeURIComponent(details.url)}`;
    chrome.tabs.update(details.tabId, { url: target });
  } catch (err) {
    // Dashboard unreachable — fail open for UX. Firewall is the real enforcement.
    console.warn('[skfilter] check failed for', host, err);
  }
}, { url: [{ schemes: ['http', 'https'] }] });
