# skfilter — netsh-backed allowlist firewall with redirect-on-block UX

## Context

Self-imposed website filter for **this Windows machine**. After scoping conversations:

- **Use case**: "only allow websites I built myself" → default-deny outbound + an IP allowlist of the user's own sites. The whole HTTPS / DoH / SNI / MITM rabbit hole is sidestepped because we're not doing domain filtering of third-party traffic.
- **Filter mechanism**: Windows Defender Firewall driven by `netsh advfirewall`. No kernel driver, no WinDivert, no MITM.
- **Single Go binary** running as a Windows service (`LocalSystem`) so it can call `netsh` without admin prompts.
- **Local HTTP dashboard** at `http://localhost:8764` (loopback-only, plain HTTP — never leaves the machine), password-gated, and **ONLY** lets the user add or remove allowed sites (no default-deny toggle exposed — that's set once at install and stays set).
- **Redirect-on-block UX**: when the user navigates to a blocked site, they should land on `http://localhost:8764/blocked?url=<original>` with a one-click "Request access" button that, after password confirmation, adds the site to the allowlist.
- **IP source**: enter a domain, the service resolves it at request time and re-resolves on a schedule, keeping the netsh rule in sync.
- **Audit log**: yes — every login attempt, rule add/remove, IP-refresh is appended to `audit_log` and viewable on the dashboard.

### How redirect-on-block actually works (because netsh alone can't redirect)

Windows Firewall drops packets — the browser sees a connection timeout, not a redirect. To produce the friendly "you blocked this — click to allow" page, **we ship a small browser extension** alongside the service. The extension is the only realistic way to redirect a blocked HTTPS load without installing a custom root CA and MITMing the user's TLS.

```
Browser navigates to https://example.com
   │
   ▼
Extension's onBeforeRequest fires, asks the local service: "is example.com allowed?"
   │
   ├── YES → return; browser proceeds normally; firewall allows the IP because it's in the netsh rule
   │
   └── NO  → redirect the tab to http://localhost:8764/blocked?url=https://example.com
                                         │
                                         ▼
                            Dashboard "Blocked" page:
                                "You navigated to https://example.com.
                                 This site is not on your allowlist.
                                 [ Add to allowlist ]   (requires password)"
                                         │
                                         ▼
                              On confirm → /api/rules POST → service resolves
                              IPs → netsh add rule → audit log → "Allowed, retry"
```

Result: zero MITM, no CA install, no DoH issue, no SNI inspection. The extension handles UX; the firewall is the real enforcement.

## Architecture

```
                   ┌─────────────────────────────────────┐
                   │  Windows Defender Firewall          │
                   │  default-policy: BLOCK outbound     │
                   │  + skfilter_<rule-id> allow rules   │
                   └────────────────▲────────────────────┘
                                    │  netsh advfirewall ...
                                    │
Browser ──HTTP──> localhost:8764 ────┤  (Go service, LocalSystem)
       (extension                    │  ├── chi router + bcrypt + sessions
        redirects on                 │  ├── SQLite (modernc.org/sqlite)
        blocked sites)               │  ├── DNS resolver goroutine (15-min tick)
                                     │  └── netsh wrapper
                                     │
Browser extension ──HTTP──> localhost:8764/api/check?domain=…   (rate-limited, unauth, read-only)
```

Three components, all in one repo:

| Component | Lives in | Runs as |
| --- | --- | --- |
| **Service** | `cmd/skfilter/` + `internal/...` | Windows service, `LocalSystem` |
| **Dashboard** | `internal/webui/dist/` (Go-embedded) | served by the service |
| **Browser extension** | `extension/` | installed manually into Chrome / Edge / Firefox |

## Project layout

Final path: **`C:\Users\nates\Downloads\Claude\Filter\`**.

```
Filter/
├── Plan.md                          ← this document
├── README.md
├── go.mod
├── main.go                          ← entry, dispatches -dev / -install / -uninstall / service-mode
├── cmd/
│   ├── service.go                   ← golang.org/x/sys/windows/svc plumbing
│   ├── install.go                   ← register service, set sc failure recovery, prompt to install extension
│   └── dev.go                       ← foreground mode for development
├── internal/
│   ├── config/                      ← %PROGRAMDATA%\skfilter\ paths
│   ├── db/
│   │   ├── schema.sql               ← settings / rules / audit_log
│   │   ├── store.go
│   │   └── migrations.go
│   ├── auth/
│   │   ├── password.go              ← bcrypt + first-run setup
│   │   └── sessions.go              ← gorilla/sessions
│   ├── firewall/
│   │   ├── netsh.go                 ← exec.Command wrappers, output parsing, INJECTION-SAFE input validation
│   │   ├── policy.go                ← read/set default-outbound policy (set once at install)
│   │   └── rules.go                 ← Add / Delete / List rules with "skfilter_" prefix
│   ├── resolver/
│   │   └── refresh.go               ← 15-min ticker; net.LookupIP per rule; diff → rewrite
│   ├── httpapi/
│   │   ├── router.go                ← chi + middleware (auth, audit, JSON, rate-limit on /api/check)
│   │   ├── handlers_rules.go        ← GET / POST / DELETE /api/rules
│   │   ├── handlers_blocked.go      ← GET /blocked?url=… (renders the request-access page)
│   │   ├── handlers_check.go        ← GET /api/check?domain=… (extension uses this; rate-limited)
│   │   ├── handlers_audit.go        ← GET /api/audit
│   │   └── handlers_login.go        ← POST /login, POST /setup
│   └── webui/
│       ├── embed.go                 ← go:embed dist/*
│       └── dist/
│           ├── index.html           ← rules list + add/remove UI
│           ├── blocked.html         ← redirect target — "Request access" flow
│           ├── login.html
│           ├── setup.html           ← first-run password creation
│           ├── audit.html
│           ├── app.js               ← vanilla JS, no framework
│           └── styles.css           ← dark-slate (#0f172a / #1e293b), match Luach admin aesthetic
└── extension/
    ├── manifest.json                ← MV3, declares localhost:8764 as host_permissions
    ├── background.js                ← onBeforeRequest → fetch /api/check → redirect on block
    ├── icons/
    └── README.md                    ← "drag this folder into chrome://extensions, Developer Mode = on"
```

## Scope of the dashboard (locked in)

The dashboard surface is **deliberately minimal**:

1. `/setup` — first-run password creation (one-time, then hidden behind auth).
2. `/login` — password prompt.
3. `/` — the rules list. Each row = domain + current resolved IPs + last refresh + ✕ remove. One textbox + "Add" at the top.
4. `/blocked?url=...` — the redirect target. Shows the blocked domain, "Add to allowlist" button. If user is logged in already the button is one-click; if not, prompts for password inline.
5. `/audit` — read-only log of every action.

**Not** in the dashboard: default-policy toggle, port/protocol controls, inbound rules, profile selection. Those would expand the attack surface for "I'll just turn it off in a weak moment." Default-deny outbound is set once at install and is never exposed in the dashboard JSON.

## Implementation phases

Build and test each phase end-to-end before the next.

### Phase 1 — Dev-mode service + first-run password
- `go.mod`, `main.go` dispatching `-dev` flag.
- Serve plain HTTP on `127.0.0.1:8764` (loopback-only — connection never leaves the machine, no cert ceremony).
- SQLite store + schema migrations.
- `/setup` flow when `password_hash IS NULL`, then `/login`, then `/` with an empty rules table.
- **Verify**: `go run . -dev`, browser to `http://localhost:8764`, set password, log in, see "no rules yet."

### Phase 2 — netsh wrapper + manual rule add via dashboard
- `internal/firewall/netsh.go` — argv-style `exec.Command("netsh", "advfirewall", ...)` (never string-built; passes each token separately to avoid injection).
- Naming convention: `skfilter_<rule-id>` for every rule we own.
- `AddAllowRule(name, ips []string)`, `DeleteRule(name)`, `ListSkfilterRules()`, `SetDefaultOutboundBlock()`.
- `/api/rules` POST resolves the domain via `net.LookupIP`, stores the row, runs `AddAllowRule`.
- **Verify**: with default-deny manually set in a test PowerShell, add example.com from the UI, confirm `netsh advfirewall firewall show rule name="skfilter_<id>"` shows the rule and `curl https://example.com` succeeds.

### Phase 3 — Resolver goroutine
- `internal/resolver/refresh.go` — `time.NewTicker(15 * time.Minute)`. For each enabled rule: re-resolve, diff `ips_csv`, on change delete+re-add the netsh rule, append `audit_log` entry "ips_refreshed."
- Manual "Refresh now" button per row.
- **Verify**: edit `rules.ips_csv` to a wrong value in SQLite directly, click Refresh, confirm the netsh rule contents update.

### Phase 4 — Windows service install/uninstall
- `golang.org/x/sys/windows/svc` and `.../svc/mgr`.
- `skfilter.exe -install`:
   1. Installs as auto-start `LocalSystem` service.
   2. Sets `sc failure skfilter reset= 0 actions= restart/5000` (auto-restart with 5s delay).
   3. Runs `netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound` (this is the only place default-deny is touched — never exposed in dashboard).
   4. Adds an `skfilter_self_loopback` rule allowing outbound to `127.0.0.1` so the dashboard reaches the service.
- `skfilter.exe -uninstall` — prompts for the dashboard password, then removes service, restores default firewall policy.
- **Verify**: install, reboot, confirm dashboard reaches without manual start; uninstall, confirm clean removal.

### Phase 5 — Redirect-on-block: browser extension + /blocked page
- `extension/manifest.json` — Manifest V3, `host_permissions: ["<all_urls>"]`, `permissions: ["webNavigation","declarativeNetRequest"]`.
- `extension/background.js` — listens to `chrome.webNavigation.onBeforeNavigate` (main frame only). For each, `fetch("http://localhost:8764/api/check?domain="+host)`. If `{ allowed: false }`, calls `chrome.tabs.update(tabId, { url: "http://localhost:8764/blocked?url="+encodeURIComponent(originalUrl) })`.
- Service exposes `/api/check?domain=...` — UN-authenticated but rate-limited (10 req/s/IP, loopback-only). Returns `{ allowed: bool, rule_id: int }`. Strict input validation (must be a valid hostname).
- `/blocked` template — shows the requested URL, "Add to allowlist" button. Posts to `/api/rules` if user has an active session, else shows inline password prompt.
- **Verify**: load extension into Chrome (Developer Mode → Load unpacked → `extension/`). Try to visit `https://reddit.com` (assuming not allowed) → tab redirects to `http://localhost:8764/blocked?url=https%3A%2F%2Freddit.com%2F`. Click "Add to allowlist," enter password, retry → reddit loads.

### Phase 6 — Audit log + light bypass-resistance
- `audit_log(id, ts, actor_session_id, action, payload_json)` written from middleware on every state-changing API call and every `/login` (success/fail).
- `/audit` page renders the table read-only.
- `sc failure` recovery is already in Phase 4.
- A small "are you sure?" delay (10-second countdown) on the Remove-rule button — friction without lockout.

## Critical files (will be created)

| Path | Role |
| --- | --- |
| `Filter/main.go` | Entry, flag dispatch (`-dev` / `-install` / `-uninstall` / service mode) |
| `Filter/internal/firewall/netsh.go` | The only thing that talks to `netsh`. Argv-safe. Owns the `skfilter_*` namespace. |
| `Filter/internal/resolver/refresh.go` | Domain → IPs sync goroutine |
| `Filter/internal/httpapi/router.go` | chi + middleware (auth, audit, rate-limit) |
| `Filter/internal/httpapi/handlers_blocked.go` | The `/blocked?url=...` redirect target |
| `Filter/internal/httpapi/handlers_check.go` | The extension's `/api/check?domain=...` endpoint |
| `Filter/internal/db/schema.sql` | settings / rules / audit_log DDL |
| `Filter/extension/manifest.json` + `background.js` | Browser-side redirect mechanism |

## Libraries (no need to reinvent)

- `golang.org/x/sys/windows/svc` + `svc/mgr` — Windows service support.
- `github.com/go-chi/chi/v5` — router.
- `golang.org/x/crypto/bcrypt` — password hashing.
- `github.com/gorilla/sessions` — cookie sessions.
- `modernc.org/sqlite` — pure-Go SQLite, no CGO.
- `net.LookupIP` — stdlib resolver.
- `golang.org/x/time/rate` — rate-limit `/api/check`.

## Hardening options (Phase 7, opt-in)

The base plan is "medium bypass resistance" — anything an Administrator can do, an Administrator can undo. Each subphase below adds friction; ship the recommended set for free, others are opt-in.

### Admin running `netsh advfirewall reset` or stopping the service

1. **Service-process watchdog (Phase 7a — easy, ~30 lines)**
   The service itself, every 30 seconds, asserts that the default-outbound policy is still `block`. If it's not, it reapplies `blockinbound,blockoutbound` and writes an `audit_log` entry tagged `policy_drift_recovered`.

2. **Scheduled-task watchdog (Phase 7b — moderate, ~80 lines)**
   `skfilter.exe -install` registers a Task Scheduler entry `skfilter_watchdog` running as `SYSTEM`, trigger = every 1 minute. If `skfilter` service isn't running, `Start-Service skfilter`. Stopping the service via `services.msc` brings it back within 60s.

3. **Service ACL lockdown (Phase 7c — moderate, surgical)**
   At install, run `sc sdset skfilter <SDDL>` to remove `RP` (start), `WP` (stop), and `DC` (delete) from the `BA` (Built-in Administrators) ACE while leaving them on `SY` (LocalSystem). Even an Admin account can't stop or remove the service from `services.msc` without elevating to SYSTEM (via `psexec -s`).

4. **Block edits to Defender Firewall via Group Policy (Phase 7d — invasive, Pro/Enterprise only)**
   Local Group Policy → Computer Configuration → Administrative Templates → Network → Network Connections → Windows Defender Firewall → set the firewall to managed. Once `HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\…` keys are set, `netsh advfirewall reset` no longer reverts default policy.

5. **Standard-user account (the real fix)**
   Demote your daily account to Standard, keep a separate Administrator account whose password isn't autofilled. Now bypassing requires typing an admin password.

**Recommendation**: ship 7a + 7b + 7c + 7h (below) for free. 7d is opt-in. Standard-user advice goes in README.

### Phase 7h — Declarative reconciler ("only the dashboard can change anything")

The single most effective answer to "stop firewall edits that don't go through the UI" is a **state reconciler**: the service treats SQLite as the source of truth and continuously rewrites the firewall to match. Any out-of-band change — `netsh advfirewall firewall add rule …`, `netsh advfirewall reset`, deleting a rule from `wf.msc` — is wiped within the reconciler interval.

**Tick interval — corrected (2026-05-10)**: original plan said "10s, drop to 2s once netsh parsing is fast." Reality check: `netsh advfirewall firewall show rule name=all` runs in 200–500 ms each call, plus parse. A 2s tick would mean we're spending ~25 % of one CPU continuously, with most of that wasted. **Realistic floor with netsh shelling is 5 s.** Sub-second drift correction would require switching from `netsh` shell-out to the **Windows Filtering Platform COM API** (`HNetCfg.FwPolicy2` via `golang.org/x/sys/windows/com`), which is a separate, larger project — out of scope for v1.

Compromise: **default to 5 s**, expose as a config knob in the dashboard (10 s for casual use, 5 s for "actively trying to bypass" scenarios). Anything below 5 s on netsh is a non-starter without a different firewall API.

Implementation:

- New goroutine in `internal/firewall/reconciler.go`, ticks every **5 seconds** (configurable).
- Each tick:
  1. `desiredRules = db.SelectEnabledRules()` → set of `{name, ips}` we want present.
  2. `actualRules = netsh.ListSkfilterRules()` → set of `skfilter_*` rules currently in Windows Firewall.
  3. `desiredDefaultOutbound = "block"`; `actualDefaultOutbound = netsh.GetDefaultOutbound()`.
  4. Diff and apply:
     - Any `skfilter_*` rule present in actual but not desired → `DeleteRule`.
     - Any rule present in desired but not actual → `AddAllowRule`.
     - Any rule with IP-list drift → `DeleteRule` + `AddAllowRule`.
     - Default-policy mismatch → `SetDefaultOutboundBlock`.
     - Any non-`skfilter_*` allow rule that was newly added since last tick → `DeleteRule` (catches manual `netsh ... add rule name="my_bypass" action=allow ...`).
  5. Every drift event → `audit_log` entry with the original observed state (so out-of-band attempts are visible after the fact).
- The reconciler runs alongside the existing resolver goroutine. They never both write the same rule because the resolver flips a single `desired_ips` column in SQLite and lets the reconciler do the netsh work.

Net behavior:
- A user opens `wf.msc` and disables an `skfilter_*` rule → it comes back within 10s.
- A user runs `netsh advfirewall firewall add rule name="paypal_bypass" action=allow remoteip=any` → it gets deleted within 10s.
- A user runs `netsh advfirewall reset` → default-policy is restored and every `skfilter_*` rule is re-added within 10s.
- A user runs `Set-NetFirewallProfile -DefaultOutboundAction Allow` → reverted within 10s.

The only ways to *durably* change state are:
1. Through the dashboard (which writes to SQLite and lets the reconciler apply it). ✓ Intended.
2. Stop the service first. Phase 7b watchdog brings it back within 60s, Phase 7c ACL lockdown makes stopping require SYSTEM elevation.

**Caveats**:
- 5-second window: a determined user has ~5s of "freedom" between out-of-band change and reconciler revert. Sub-second would need WFP COM, see above.
- An Administrator can edit SQLite directly to add a "bypass" rule. Mitigation: SQLite file ACL'd to `LocalSystem` only (Phase 7c sibling).
- WFP filtering bypasses (loading a kernel driver or hooking `netsh.exe` to no-op) defeat us. Out of scope.

### Browser hardening — force-install + lock the browser to the extension

**Requirement**: the Go installer auto-installs the extension AND configures Chrome / Edge so the browser cannot be effectively used *without* the extension active.

**⚠ Correction (2026-05-10)**: Chrome / Edge stopped honoring `file://` update URLs in `ExtensionInstallForcelist` several years ago for security reasons. The original plan's `file:///C:/ProgramData/skfilter/extension/update.xml` approach **does not work**. Real options:

| Option | What it costs | Trade-offs |
| --- | --- | --- |
| **(a) Publish to Chrome Web Store + Edge Add-ons** | $5 one-time Chrome developer account; free Edge account; ~1 week review on first submit | Public listing (anyone can find it). Updates push automatically. The simplest force-install story. |
| **(b) Self-host signed `.crx` + `update.xml` over HTTPS** | A public HTTPS endpoint we control (Cloudflare Pages free tier, GitHub Pages, or any static host); generate a stable RSA key for `.crx` signing | Stays "private" but the URL is reachable from any browser, not really a secret. Updates require pushing a new `.crx`. |
| **(c) Skip force-install — manual unpacked load** | Nothing | The user drags `extension/` into `chrome://extensions` Developer Mode once per browser. Survives until the user manually removes it. No policy lock. |

**Decision pending user input**: which path to take. Options (a) and (b) both let us write `ExtensionInstallForcelist` with the public update URL, which then *does* enable the rest of the lockdown matrix below. Option (c) means the lockdown matrix becomes "if the extension happens to be loaded, lock down everything else" — still useful, less complete.

**Update (2026-05-10)**: the GitHub repo is now auto-deploying to **https://skfilter.pages.dev/** via Cloudflare Pages. That's the public HTTPS endpoint option (b) needs. Concrete next steps for force-install on this path:

1. Generate a stable RSA-2048 keypair (committed only as the public key inside `manifest.json` derivation; private key kept in a GitHub Actions secret).
2. Add a GitHub Action that, on each push to `main`, packs `extension/` into a signed `.crx` and writes `update.xml` pointing at it.
3. Pages serves both files at `https://skfilter.pages.dev/skfilter.crx` and `https://skfilter.pages.dev/update.xml`.
4. Installer writes `ExtensionInstallForcelist\1 = "<ext-id>;https://skfilter.pages.dev/update.xml"` for Chrome and Edge.

This is a self-contained ~half-day of work. The extension ID is deterministic from the public key, so we can hardcode it in the installer once we generate the key. **Not yet implemented** — file under "next pickup."

The original plan called this "Phase 7e — moderate ~150 lines." Reality: ~50 lines of registry writes (trivial) + however much work option (a) or (b) entails, which is mostly account / hosting setup, not code.

How "the browser is unusable without the extension" is achieved (all via HKLM registry policies the installer writes — these all work regardless of which (a)/(b)/(c) path was chosen, and don't depend on file:// URLs):

| What we set | Registry path | Effect |
| --- | --- | --- |
| Force-install our extension (only on options a/b) | `HKLM\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist\1` = `<ext-id>;https://updates.example.com/skfilter.xml` (and the matching `\Microsoft\Edge\…` key) | Extension always installed, can't be removed or disabled by user. Requires HTTPS update URL — file:// not honored. |
| Restrict installable extensions to ours only | `…\Chrome\ExtensionInstallAllowlist\1` = `<ext-id>` and `…\ExtensionInstallBlocklist\1` = `*` | User can't install ANY other extension. Combined with forcelist, the only extension that can ever load is ours |
| Block disabling extensions via the UI | `…\Chrome\ExtensionSettings` JSON value with our ID set to `installation_mode = "force_installed"` and `update_url = file:///…` | Disable button greyed out; toggle ignored |
| Disable Incognito (which would skip extensions) | `…\Chrome\IncognitoModeAvailability` = `1` | "New Incognito Window" greyed out |
| Disable Guest mode | `…\Chrome\BrowserGuestModeEnabled` = `0` | No incognito-like guest profiles |
| Disable developer mode (so user can't load a side extension that conflicts) | `…\Chrome\DeveloperToolsAvailability` = `2` | F12 / DevTools blocked entirely. Aggressive but matches the lockdown intent |
| Disable user profiles other than the policy-managed default | `…\Chrome\BrowserAddPersonEnabled` = `0` | Can't create a fresh profile that escapes policies |
| Disable extension-load-from-disk shortcuts | `…\Chrome\ExtensionDeveloperModeSettings` = `Blocked` | Can't side-load a different extension |
| Pin Chrome's policy refresh to be aggressive | `…\Chrome\ChromeFrameRendererSettings`: not needed; policies refresh on each tab open. We rely on default. |

The same matrix is written for Edge under `HKLM\SOFTWARE\Policies\Microsoft\Edge\…`. Firefox gets a `policies.json` in `C:\Program Files\Mozilla Firefox\distribution\` setting `Extensions.Install` (force-install) and `Extensions.Locked` (block disable).

Combined effect:

- The user cannot uninstall the extension via UI.
- The user cannot install any other extension that might interfere.
- The user cannot open Incognito mode (which skips extensions).
- The user cannot create a new profile that bypasses the policy.
- The user cannot enable Developer Mode to side-load a no-op extension that fakes the API check.

The installer runs an extra reconciliation step: every tick, the Phase 7h reconciler also asserts that the registry policy keys are present and untouched. If a key is deleted, the reconciler restores it with the correct value within 10 s and writes an `audit_log` entry.

**Belt-and-suspenders for "what if the user installs a browser we didn't lock down" (e.g., Brave, Vivaldi, Opera, Tor Browser, Arc)**:

- The firewall is still default-deny outbound. A new browser hitting an allowlisted domain works (because the firewall is per-IP, not per-process). But the browser itself can't reach anything not on the allowlist, just like Chrome would without the extension. The extension is purely UX — the firewall is the enforcement.
- If we want to *ban* unknown browsers entirely, the installer can also write an AppLocker policy banning execution of any browser EXE not in `{chrome.exe, msedge.exe, firefox.exe}`. This is **Phase 7p** below, opt-in.

#### Phase 7p — AppLocker browser allowlist (opt-in)

- Configure AppLocker via local Group Policy / `Set-AppLockerPolicy` to allow Publisher rule for Google Chrome (Google LLC), Microsoft Edge (Microsoft Corporation), and optionally Mozilla Firefox.
- Deny rule for everything matching publisher = `*` and category = browser, or path-match for known alt-browser EXEs.
- Same registry-ACL lockdown as elsewhere.
- This is heavy: AppLocker requires Pro/Enterprise editions; Home users can use WDAC (newer, sometimes overlapping). Document the trade-off in README.

#### Phase 7q — Hosts file watch (covered by 7m)

Already in 7m above — file ACL'd to SYSTEM-only and watched by reconciler.

### Cover non-browser apps with hosts-file blocking (Phase 7g — optional)

For curl / non-browser HTTPS clients, append `0.0.0.0 example.com` to `C:\Windows\System32\drivers\etc\hosts` for blocked domains. Belt-and-suspenders with the firewall — improves error messages for non-browser apps. Skip unless needed.

## Honest assessment: bypass paths without the password

No user-mode software running on a machine the user has Administrator rights to can be fully unbypassable. The goal is enough friction that an in-the-moment urge can't satisfy itself in under a few minutes of deliberate, knowledgeable effort.

| # | Bypass path | Required level | Friction | Mitigated by |
| --- | --- | --- | --- | --- |
| 1 | Out-of-band `netsh advfirewall firewall add rule …` | Admin | < 5 s, low knowledge | **Phase 7h** reconciler — reverts within 10 s |
| 2 | `netsh advfirewall reset` | Admin | < 5 s, low knowledge | **Phase 7h** reconciler reverts; **7d** Group Policy makes the reset itself a no-op |
| 3 | Stop service via `sc stop skfilter` / `services.msc` | Admin | < 30 s | **Phase 7b** watchdog restarts within 60 s; **Phase 7c** ACL requires SYSTEM elevation |
| 4 | Stop both service AND scheduled-task watchdog | Admin → SYSTEM via `psexec -s` | ~2 min, requires `psexec` | Acknowledged limit. Both have ACLs requiring SYSTEM (Phase 7c). |
| 5 | Edit SQLite directly | Admin → SYSTEM | ~1 min from SYSTEM shell | **Phase 7c** file ACL only (Phase 7i dropped — see below). Accept that SYSTEM defeats the password gate. |
| 6 | Delete `skfilter.db` to reset first-run, set new password | Admin → SYSTEM | ~1 min | **Phase 7c** file ACL. Same diminishing-returns reasoning. |
| 7 | Replace `skfilter.exe` with a no-op binary, start the service | Admin → SYSTEM | ~5 min, requires preparation | **Phase 7j signature self-check** |
| 8 | Stop the underlying `MpsSvc` (Windows Defender Firewall service) | Admin | < 30 s | Reconciler watches `MpsSvc` and `Start-Service`s it |
| 9 | Boot into Safe Mode, delete `%PROGRAMDATA%\skfilter\` | Local Admin | ~3 min | **Phase 7k SafeBoot registration** |
| 10 | Boot a Linux USB / Windows PE, mount the disk, delete service files | Physical access | ~10 min, prepared USB | BitLocker (out of scope for v1) |
| 11 | Connect via mobile hotspot / VPN / different network | None | < 1 min | Firewall is IP-layer; **network change doesn't bypass it**. ✓ |
| 12 | Roll back system time to defeat a "change delay" | Admin | < 30 s | Use monotonic time-since-boot, never wall-clock arithmetic |
| 13 | Disable the browser extension manually | Local user | < 30 s | **Phase 7e** force-install policy greys out the disable button; firewall is the real enforcement regardless |
| 14 | Use a different browser without the extension | Local user | < 1 min | Firewall still blocks. UX = connection error. ✓ |
| 15 | Run a non-browser program that reaches out (curl, native app) | Local user | varies | Firewall still blocks. ✓ |

### Additional hardening phases

#### Phase 7i — Encrypted SQLite — DROPPED (re-evaluated 2026-05-10)

Original idea: derive a 32-byte key from the password via Argon2id, encrypt the SQLite DB at rest. Reasons it's NOT worth shipping:

1. **Pure-Go path is bad.** `modernc.org/sqlite` doesn't support SQLCipher. The "row-level encryption of sensitive cells" workaround is significantly more code (encrypt-on-write, decrypt-on-read for every column) and breaks SQLite query semantics — you can't `WHERE password_hash = ?` if the column is ciphertext, you have to decrypt every row in code. ~300 lines of glue, fragile.

2. **CGO path defeats the rest of the stack.** Switching to CGO + SQLCipher loses the "single static EXE, no DLLs" property that makes deployment trivial.

3. **Threat model has diminishing returns.** The bypass it would close (#5: SYSTEM-elevation user reads `password_hash` from DB) is gated by Phase 7c (SQLite file ACL'd to `LocalSystem` only). If an attacker has SYSTEM, they can also patch the binary, replace the whole DB, hook `netsh.exe`, or just run `netsh advfirewall reset`. Encryption-at-rest doesn't move the line meaningfully.

**Decision**: rely on Phase 7c (file ACL) and accept that a SYSTEM shell defeats the password gate. The friction model still holds — getting to SYSTEM is the deliberate, knowing step we wanted in the first place.

Bypass row #5 / #6 (above) is therefore mitigated only by Phase 7c, not Phase 7i. Update the table accordingly when re-reading.

#### Phase 7j — Binary signature self-check

Closes #7.

- At install, compute SHA-256 of `skfilter.exe`, store in a sidecar `%PROGRAMDATA%\skfilter\binary.fp` with SYSTEM-only permissions.
- On service start, re-hash the running EXE and compare. Mismatch → refuse to start, write to Event Log.

#### Phase 7k — Safe Mode persistence

Closes #9 (partially).

- During `-install`, set:
  ```
  HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\skfilter   = "Service"
  HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\skfilter   = "Service"
  ```
- `MpsSvc` doesn't run in Minimal Safe Mode by default, so Minimal isn't fully covered. For Minimal, the real fix is "demote to Standard user."

### Phases 7l – 7o (additional bypasses found in audit)

| # | Bypass path | Mitigation |
| --- | --- | --- |
| 16 | **Hyper-V / WSL2 / Windows Sandbox VM escape** — these have their own network stacks via vEthernet, can route around host Defender Firewall | **Phase 7l**: at install, disable optional features `Microsoft-Hyper-V`, `VirtualMachinePlatform`, `Microsoft-Windows-Subsystem-Linux`, `Containers-DisposableClientVM` via `dism.exe /online /disable-feature`. Block re-enable by setting `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OptionalFeatures` registry ACLs. Acceptable trade-off: no WSL or VMs on this machine. |
| 17 | **Edit `C:\Windows\System32\drivers\etc\hosts`** to point a blocked domain at an allowlisted IP — bypasses the firewall (which only sees IP, not hostname) | **Phase 7m**: file ACL the hosts file to SYSTEM-only. Reconciler watches for changes (mtime check every 10s) and reverts to a known-good baseline if modified. |
| 18 | **Stop the Base Filtering Engine** (`sc stop BFE`) — disables Defender Firewall entirely | **Phase 7n**: same pattern as #8 — reconciler checks `MpsSvc` AND `BFE` are running every tick, restarts whichever is stopped. ACL lockdown both services. |
| 19 | **Rules only cover IPv4** — connections over IPv6 sneak past | **Phase 7o**: `AddAllowRule` always emits TWO rules: `skfilter_<id>_v4` (with the resolved A records) and `skfilter_<id>_v6` (with the resolved AAAA records). Default-deny applied to all profiles + all address families. Resolver tracks both. |

### What remains permanently open

Even with all of 7a–7k:

- **Boot from external media** (#10) — BitLocker is the only counter, separate decision.
- **Elevate to SYSTEM via `psexec -s` and remove everything** — `psexec` needs to be on disk and run as Admin first.
- **Replace SQLite + binary + fingerprint + reg keys atomically** — full nuclear option, ~10 min, requires preparation.

**The friction model**: the goal isn't to keep a determined Administrator out forever — that's impossible for any user-mode tool — it's to make the bypass slow, deliberate, and require sober preparation rather than an impulsive 30-second action. Phases 7a–7k take the average bypass from "30 seconds, no knowledge" → "~10 minutes, specific preparation + technical knowledge + SYSTEM elevation." That's the right ceiling for a personal self-discipline tool.

For users who want stricter: demote your daily account to Standard, set a long admin password you don't autofill, and put the BitLocker recovery key somewhere inconvenient. Those three steps do more than all of Phases 7a–7k combined.

## Risks / remaining notes

1. **Self-signed cert warnings** on the dashboard. Once-per-browser "Advanced → Proceed." Acceptable for a `127.0.0.1` app; could later auto-install the cert into Windows Trusted Root via `certutil -addstore Root` during install.
2. **Recovery if password is lost.** With Phase 7i (encrypted DB), the only recovery is full reinstall. From an Administrator shell: `skfilter.exe -nuke` removes the service, deletes `%PROGRAMDATA%\skfilter\`, then reinstall fresh. `-nuke` doesn't require the password but does require Admin + the `-nuke` flag is intentionally inconvenient.
3. **DNS still works for blocked sites** under this architecture. The extension catches them before TCP. If a non-browser app tries to reach a blocked site it'll get a clean firewall deny (connection refused / timeout). Fine for the "only my sites" use case.

## Verification (end-to-end, after Phase 5)

1. `go build -o skfilter.exe`.
2. Admin PowerShell → `.\skfilter.exe -install` → reboot.
3. Browser → `http://localhost:8764` → set password → log in → empty rules list.
4. Drag `extension/` into `chrome://extensions` (Developer Mode on).
5. Try `https://example.com` → tab redirects to `http://localhost:8764/blocked?url=...`.
6. Click "Add to allowlist" → confirm password if needed → wait for the row's IPs to populate.
7. Retry `https://example.com` → loads normally.
8. `/audit` page should show: login success, rule_added, ips_refreshed.
9. Remove the rule from `/` → click confirm after the 10-second delay → retry the URL → redirect appears again.
10. `netsh advfirewall firewall show rule name=all | findstr skfilter_` should reflect the live state at each step.
