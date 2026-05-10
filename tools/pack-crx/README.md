# pack-crx

Pure-Go CRX3 packer + `update.xml` generator for the skfilter browser extension.

## What it does

Given an unpacked extension dir and a PEM-encoded RSA-2048 private key, produces:

- `<out>/skfilter.crx` — a CRX3-format signed extension package
- `<out>/update.xml` — a Chrome/Edge auto-update manifest pointing at the public CRX URL

Both files only get rewritten if their content actually changes, so re-running the tool on
an unchanged extension doesn't churn git.

## Usage

```
go run ./tools/pack-crx \
  -key=skfilter-extension.pem \
  -src=./extension \
  -out=./web \
  -url=https://skfilter.pages.dev/skfilter.crx
```

Flags:

| Flag | Default | Meaning |
| --- | --- | --- |
| `-key` | (required) | Path to PEM RSA private key (PKCS#1 or PKCS#8). |
| `-src` | `./extension` | Source dir; must contain `manifest.json` with a `version`. |
| `-out` | `./web` | Output dir; receives `skfilter.crx` + `update.xml`. |
| `-url` | `https://skfilter.pages.dev/skfilter.crx` | `codebase=` URL written into `update.xml`. |
| `-id`  | `false` | Print the deterministic extension ID for the key and exit. |

## One-time keypair setup

Chrome derives a stable extension ID from the public key. Once we pick a keypair, the ID
is fixed forever — that's what makes `ExtensionInstallForcelist` policy point at the
right extension on every machine.

### 1. Generate the private key (one machine, kept off the repo)

```powershell
openssl genrsa -out skfilter-extension.pem 2048
```

### 2. Derive the public key + extension ID

```powershell
go run ./tools/pack-crx -key=skfilter-extension.pem -id
```

That prints the 32-character extension ID. Then run a full pack to also see the public key:

```powershell
go run ./tools/pack-crx -key=skfilter-extension.pem -src=./extension -out=./web
```

The first line of stderr-style output includes:

```
pubkey (manifest "key" field): MIIBIjANBgkqh...
```

### 3. Commit the public bits to the repo

- Paste the `MIIBIj…` base64 string into `extension/manifest.json` as the `"key"` field.
  Chrome uses that to verify the extension ID at install time without needing the .crx
  on every dev machine.
- Write the extension ID into `extension/extension-id.txt` (one line, no trailing space).
  The Go installer reads this file to populate `ExtensionInstallForcelist` policy keys.

### 4. Stash the private key in GitHub Secrets

In the repo's GitHub Settings → Secrets → Actions, create `EXTENSION_SIGNING_KEY` and
paste the **entire** `skfilter-extension.pem` file content, including the
`-----BEGIN RSA PRIVATE KEY-----` / `-----END RSA PRIVATE KEY-----` lines.

The `extension-release.yml` workflow writes the secret to a temp file on each run and
passes it to this tool as `-key`. The secret never lands on disk in the repo.

**If the secret is missing**, the workflow logs a clear setup message and exits 0
without failing the rest of CI.

## Why hand-roll the CRX3 protobuf?

The CRX3 file format only uses three message types and two wire-format constructs
(varints + length-delimited bytes). Hand-rolling the marshaler keeps this tool
dependency-free; no `google.golang.org/protobuf` import, no `go.mod` churn for an
isolated tool. See `main.go` top-of-file comment for the format spec.

## Verifying a built `.crx`

After running the tool you can sanity-check the output:

```powershell
# Magic + version
Get-Content .\web\skfilter.crx -Encoding Byte -TotalCount 8

# Should print:  67 114 50 52  3 0 0 0     (= "Cr24" then uint32 LE = 3)
```

Or load it into Chrome: `chrome://extensions` → Developer Mode → drag the `.crx` onto
the page. Chrome will accept the install if the signature is valid.
