# skfilter

A Windows-only allowlist firewall driven by `netsh advfirewall`, paired with a password-gated local HTTP dashboard at `http://localhost:8764` (loopback only — never reachable off the machine). Default-deny outbound; only domains you've explicitly added can be reached. A companion browser extension redirects blocked navigations to the dashboard's "Request access" page.

See [`Plan.md`](./Plan.md) for the full architecture, scope, bypass-resistance audit, and roadmap.

---

## Prerequisites

- **Windows 10 or 11** (Home / Pro / Enterprise — service install works on all)
- **Go 1.22+** ([download](https://go.dev/dl/)) — only needed to build, not to run
- **Admin PowerShell** for service install / uninstall and for setting default-deny on the firewall
- **Chrome, Edge, or Firefox** for the dashboard + extension

The runtime binary has zero CGO; once built, `skfilter.exe` is a single static EXE.

---

## Build

From the project root:

```powershell
cd C:\Users\nates\Downloads\Claude\Filter
go mod tidy
go build -o skfilter.exe
```

`go mod tidy` populates `go.sum` on first build. After that, `go build` is enough.

If the build complains about a missing dep, run `go mod tidy` again — the four parallel build agents may have left a small mismatch that surfaces only when the toolchain runs end-to-end.

---

## Test path 1 — Dev mode (no service install, no firewall changes)

This is the fastest way to confirm the dashboard, DB, auth, and HTTP API work end-to-end. **No `netsh` calls happen until you actually add a rule** — and even then they only succeed if you're running the EXE as Administrator.

```powershell
# In a regular PowerShell (NOT admin):
.\skfilter.exe -dev
```

What should happen:

1. Console prints `serving on http://localhost:8764`.
2. Open `http://localhost:8764/` in your browser. No cert warnings — the dashboard runs over plain HTTP on the loopback interface.
3. You land on `/setup`. Set a password (≥ 8 chars).
4. You're redirected to `/`. Empty rules list, "Add domain…" textbox at the top.

That's the dashboard fully functional. Data lives in `%PROGRAMDATA%\skfilter\skfilter.db` (or your `%TEMP%\skfilter\` if running as a non-admin without that path).

To clean state for a fresh test:

```powershell
Stop-Process -Name skfilter -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force "$env:PROGRAMDATA\skfilter" -ErrorAction SilentlyContinue
```

---

## Test path 2 — Adding a rule (requires Administrator)

`netsh advfirewall` requires admin. Open an **Admin PowerShell**, then:

```powershell
# Set default-deny manually for this test (the installer normally does this for you):
netsh advfirewall set allprofiles firewallpolicy blockinboundalways,blockoutbound

# Run skfilter in dev mode AS ADMIN:
.\skfilter.exe -dev
```

In the dashboard:

1. Type `example.com` in the Add box, hit Enter.
2. Within ~1 second the row appears with resolved IPs.
3. Verify on the command line:
   ```powershell
   netsh advfirewall firewall show rule name=skfilter_1_v4
   ```
   Should print the rule with `RemoteIP` matching `example.com`'s A records.
4. From a separate terminal: `curl https://example.com` → succeeds.
5. Try `curl https://google.com` → connection times out (default-deny is in effect).
6. Click ✕ on the example.com row → wait the 10-second confirm countdown → click again. Rule disappears within seconds. `curl https://example.com` now times out.

When done testing, restore the default firewall policy:

```powershell
netsh advfirewall set allprofiles firewallpolicy notconfigured,allowoutbound
```

---

## Test path 3 — Reconciler (Phase 7h)

While `skfilter -dev` is running with rules in place, in another Admin shell:

```powershell
# Try to add a bypass rule — the reconciler should delete it within 10s:
netsh advfirewall firewall add rule name="my_bypass" dir=out action=allow remoteip=any

# Wait 15s, then check — should be gone:
netsh advfirewall firewall show rule name="my_bypass"
```

Output: `No rules match the specified criteria.` — confirmed reconciler deleted it.

Now try defeating the policy:

```powershell
netsh advfirewall set allprofiles firewallpolicy notconfigured,allowoutbound
# Wait 15s
netsh advfirewall show allprofiles state | findstr "Outbound"
```

Output: `Outbound connections that do not match a rule are blocked` — reconciler restored default-deny. Check `http://localhost:8764/audit` — there should be `policy_drift_recovered` and any `rogue_rule_deleted` entries.

---

## Test path 4 — Browser extension + redirect-on-block

1. Make sure `skfilter -dev` is running and you've logged into the dashboard.
2. Chrome / Edge: open `chrome://extensions`, enable **Developer mode** (top-right toggle), click **Load unpacked**, pick the `extension/` folder.
3. Confirm the extension shows up with `Service worker` link active.
4. Try to visit `https://reddit.com` (or any site not on the allowlist).
5. Expected: tab redirects to `http://localhost:8764/blocked?url=https%3A%2F%2Freddit.com%2F`.
6. The "Request access" page shows the blocked domain. If you're logged in, click **Add to allowlist** — the rule's added, audit log gets an entry, and you can navigate to reddit.com.

If the extension doesn't redirect, check the service worker console:
- `chrome://extensions` → click the extension's "service worker" link → DevTools console
- A `[skfilter] check failed` log = service unreachable. Make sure `skfilter -dev` is running.
- A `[skfilter] allowed` log on every navigation = working as intended.

---

## Test path 5 — Full service install (do this on a VM first if possible)

This actually flips the default-deny outbound on your machine. **Have an Admin shell handy in case anything goes sideways.**

```powershell
# In Admin PowerShell:
.\skfilter.exe -install
```

What should happen:
1. The `skfilter` service is registered with auto-start.
2. `netsh advfirewall set allprofiles firewallpolicy blockinboundalways,blockoutbound` runs.
3. The `skfilter_self_loopback` allow rule is added (lets the dashboard reach the local service).
4. Service starts.
5. Console prints "open http://localhost:8764 to set your password."

Verify the service is healthy:

```powershell
Get-Service skfilter
sc.exe qc skfilter
```

Reboot the machine. After login, browser → `http://localhost:8764` should load without manually starting anything.

To remove cleanly:

```powershell
.\skfilter.exe -uninstall
# Prompts for the dashboard password.
```

That stops the service, restores `notconfigured,allowoutbound` (default Windows firewall), removes our rules. Audit log + DB are preserved at `%PROGRAMDATA%\skfilter\` for review — delete it manually if you want a clean slate.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `go build` errors about missing packages | `go.sum` not yet populated | `go mod tidy` then rebuild |
| Browser refuses to connect | Service not running, or another app already on port 8764 | `Get-Process -Name skfilter` and `netstat -ano | findstr :8764` |
| `netsh: rule cannot be added` when adding a rule | Not running as Administrator | Re-run `skfilter.exe -dev` in an Admin shell |
| Browser extension never redirects | Service worker can't reach localhost:8764 | Confirm dashboard loads in a normal browser tab; check the service worker console |
| `skfilter -install` fails with "service exists" | Previous install left behind | `sc.exe delete skfilter`, then re-run install |
| Locked out — forgot password | DB has bcrypt-hashed password | `Stop-Service skfilter; Remove-Item -Recurse -Force $env:PROGRAMDATA\skfilter; Start-Service skfilter` → setup screen reappears |
| Whole machine has no network after install | Default-deny is doing its job | Add the rules you actually need via dashboard, OR run `.\skfilter.exe -uninstall` from an Admin shell to fully revert |

---

## Where things live

| Path | Contents |
| --- | --- |
| `%PROGRAMDATA%\skfilter\skfilter.db` | SQLite — settings, rules, audit_log |
| `%PROGRAMDATA%\skfilter\tls\cert.pem` & `key.pem` | Self-signed cert used by the dashboard |
| Windows Service `skfilter` | Auto-start, runs as `LocalSystem` |
| `netsh advfirewall` rules named `skfilter_*` | Owned by us — reconciler keeps them in sync with the DB |

---

## What's NOT yet implemented

These are future work tracked in `Plan.md`:

- **Phase 7a** service-process watchdog (poll firewall state every 30 s and self-repair) — currently the Phase 7h reconciler covers most of this in its 10 s tick, so 7a is mostly redundant. Still worth confirming.
- **Phase 7b** scheduled-task watchdog
- **Phase 7c** service ACL lockdown
- **Phase 7e** force-install browser extension via Chrome / Edge / Firefox policies + lock the browser to ONLY the policy-installed extension (Incognito off, DevTools off, only-allowlisted extensions). The "browser cannot be used without the extension" requirement. **Caveat:** Chrome stopped honoring `file://` update URLs years ago. Force-install requires either (a) publishing the extension to the Chrome Web Store, (b) self-hosting an HTTPS update XML + signed `.crx`, or (c) skipping force-install and accepting manual unpacked-extension load. Decision pending.
- **Phase 7i** encrypted SQLite — **dropped**. Pure-Go path is fragile, CGO path defeats the static-EXE property, and the bypass it would close (SYSTEM-elevation user reads `password_hash`) is already past the friction threshold we wanted. Phase 7c (file ACL) is the answer instead.
- **Phase 7j** binary signature self-check
- **Phase 7k** Safe Mode persistence
- **Phase 7l–7o** Hyper-V/WSL2 disable, hosts-file ACL, BFE service watch, IPv6 coverage
- **Phase 7p** AppLocker browser allowlist

Roughly: the **base flow works** (dashboard, rules CRUD, firewall enforcement, reconciler, extension redirect), but **bypass-resistance hardening is not yet wired in**. Treat the current build as a functional MVP, not a deployed self-discipline tool.

---

## Browser-extension deploy pipeline

The extension ships in two ways:

1. **Manual unpacked load** — drag `extension/` into `chrome://extensions` (Developer Mode).
2. **Force-install via policy** — the installer writes `ExtensionInstallForcelist` keys
   pointing at `https://skfilter.pages.dev/update.xml`. Chrome / Edge then fetch and
   install the signed `.crx` on next launch and the user can't disable it.

Path 2 requires a signed `.crx` and a matching `update.xml` hosted over real HTTPS
(Chrome dropped `file://` support years ago). That hosting is **Cloudflare Pages**,
auto-deploying from this repo's `main` branch with `web/` as the build output dir.

### How it builds

```
push to main (touching extension/ or tools/pack-crx/)
        │
        ▼
.github/workflows/extension-release.yml
        │  - decode EXTENSION_SIGNING_KEY secret → temp .pem
        │  - go run ./tools/pack-crx -key=… -src=./extension -out=./web
        │  - commit web/skfilter.crx + web/update.xml back to main (if changed)
        ▼
Cloudflare Pages auto-redeploys from the new commit
        │
        ▼
https://skfilter.pages.dev/skfilter.crx
https://skfilter.pages.dev/update.xml
```

### One-time setup

1. Generate the keypair on a trusted machine:
   ```powershell
   openssl genrsa -out skfilter-extension.pem 2048
   ```
2. Paste the entire PEM (including BEGIN/END lines) into the repo's GitHub Secrets
   as **`EXTENSION_SIGNING_KEY`**.
3. Derive the public key + extension ID and commit them:
   ```powershell
   go run ./tools/pack-crx -key=skfilter-extension.pem -id    # prints the ID
   go run ./tools/pack-crx -key=skfilter-extension.pem -src=./extension -out=./web
   ```
   - Put the printed base64 SPKI into `extension/manifest.json` as the `"key"` field.
   - Put the printed 32-char ID into `extension/extension-id.txt`.
4. In the Cloudflare Pages dashboard, set the project's **build output directory** to
   `web/`. No build command needed; this is a static deploy.

Until step 1–3 are done, the workflow logs a clear "set up the secret" message and
exits clean — the rest of CI is unaffected.

### Verifying a deploy worked

After a successful workflow run:

- `https://skfilter.pages.dev/update.xml` should serve the XML with the right
  `appid` (matches `extension-id.txt`) and current `version` (matches `manifest.json`).
- `https://skfilter.pages.dev/skfilter.crx` should download (~tens of kB) and start
  with the bytes `Cr24` `03 00 00 00`.
- Drag the `.crx` into `chrome://extensions` — Chrome should accept it and report
  the same extension ID that's in `extension-id.txt`.

### Files involved

| Path | Role |
| --- | --- |
| `.github/workflows/extension-release.yml` | The pipeline trigger + steps. |
| `tools/pack-crx/main.go` | Pure-Go CRX3 packer. Hand-rolled protobuf, stdlib only. |
| `tools/pack-crx/README.md` | Tool-level docs, including the keypair flow. |
| `extension/manifest.json` `"key"` field | Pins the deterministic extension ID. |
| `extension/extension-id.txt` | Read by the Go installer to write policy keys. |
| `web/index.html` | Public landing page on `skfilter.pages.dev`. |
| `web/skfilter.crx`, `web/update.xml` | Regenerated by the workflow; gitignored locally. |

---

## License

TBD.
