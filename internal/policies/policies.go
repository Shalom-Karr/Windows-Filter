// Package policies writes the HKLM registry keys that force-install the
// skfilter browser extension into Chrome / Edge and lock the browser down
// (Incognito off, DevTools off, no new profiles, only-our-extension allowed).
//
// All writes target HKLM and require admin. Idempotent — calling Write
// repeatedly is fine. Calling Remove undoes everything Write did.
package policies

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"
)

const (
	chromePolicyRoot = `SOFTWARE\Policies\Google\Chrome`
	edgePolicyRoot   = `SOFTWARE\Policies\Microsoft\Edge`

	updateXMLURL = "https://skfilter.pages.dev/update.xml"
)

// browsers is the list of policy roots we mirror the same lockdown matrix
// into. Chrome and Edge both speak the Chromium policy schema with identical
// key names, so we just enumerate the two roots.
var browsers = []struct {
	name string
	root string
}{
	{"Chrome", chromePolicyRoot},
	{"Edge", edgePolicyRoot},
}

// WriteBrowserPolicies sets every HKLM Chrome / Edge policy key needed to
// force-install our extension and lock the browser down. Idempotent — safe
// to call repeatedly. Best-effort: continues past per-key errors and returns
// the first error encountered (nil if everything succeeded).
func WriteBrowserPolicies() error {
	extID, idErr := readExtensionID()
	if idErr != nil {
		// Not fatal — we still want the lockdown keys (Incognito off, etc.)
		// to apply even before Agent A finishes the extension build.
		fmt.Fprintln(os.Stderr, "warning: skipping extension force-install keys:", idErr)
	}

	var firstErr error
	record := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}

	for _, b := range browsers {
		// Extension force-install / allowlist / blocklist — only if we have
		// an extension ID. Without one, ExtensionInstallBlocklist=* would
		// brick all extensions; better to skip these entirely.
		if extID != "" {
			record(writeStringSubkey(b.root+`\ExtensionInstallForcelist`, "1", extID+";"+updateXMLURL))
			record(writeStringSubkey(b.root+`\ExtensionInstallAllowlist`, "1", extID))
			record(writeStringSubkey(b.root+`\ExtensionInstallBlocklist`, "1", "*"))
		}

		// Lockdown matrix — always applied.
		record(writeDword(b.root, "IncognitoModeAvailability", 1))
		record(writeDword(b.root, "BrowserGuestModeEnabled", 0))
		record(writeDword(b.root, "DeveloperToolsAvailability", 2))
		record(writeDword(b.root, "BrowserAddPersonEnabled", 0))
	}

	return firstErr
}

// RemoveBrowserPolicies undoes WriteBrowserPolicies. Best-effort: ignores
// "not found" errors so it's safe to run on a partially-cleaned machine.
func RemoveBrowserPolicies() error {
	var firstErr error
	record := func(err error) {
		if err != nil && !errors.Is(err, registry.ErrNotExist) && firstErr == nil {
			firstErr = err
		}
	}

	for _, b := range browsers {
		// Delete the "1" value inside each list subkey, then the subkey
		// itself if empty. We don't blow away the whole policy root because
		// an admin may have other unrelated policies under it.
		record(deleteSubkeyValue(b.root+`\ExtensionInstallForcelist`, "1"))
		record(deleteSubkeyValue(b.root+`\ExtensionInstallAllowlist`, "1"))
		record(deleteSubkeyValue(b.root+`\ExtensionInstallBlocklist`, "1"))
		// Attempt to drop the empty list subkeys; ignore errors (they may
		// have other values an admin added, or simply not exist).
		_ = registry.DeleteKey(registry.LOCAL_MACHINE, b.root+`\ExtensionInstallForcelist`)
		_ = registry.DeleteKey(registry.LOCAL_MACHINE, b.root+`\ExtensionInstallAllowlist`)
		_ = registry.DeleteKey(registry.LOCAL_MACHINE, b.root+`\ExtensionInstallBlocklist`)

		record(deleteValue(b.root, "IncognitoModeAvailability"))
		record(deleteValue(b.root, "BrowserGuestModeEnabled"))
		record(deleteValue(b.root, "DeveloperToolsAvailability"))
		record(deleteValue(b.root, "BrowserAddPersonEnabled"))
	}
	return firstErr
}

// readExtensionID returns the deterministic extension ID written by the
// build pipeline (`extension/extension-id.txt` next to skfilter.exe).
// Returns "" and a non-nil error if the file is missing or empty — the
// caller is expected to log the error and skip the force-install keys.
func readExtensionID() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("resolve exe: %w", err)
	}
	idPath := filepath.Join(filepath.Dir(exe), "extension", "extension-id.txt")
	b, err := os.ReadFile(idPath)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", idPath, err)
	}
	id := strings.TrimSpace(string(b))
	if id == "" {
		return "", fmt.Errorf("%s is empty", idPath)
	}
	return id, nil
}

// writeDword creates (or opens) key and sets name = val (REG_DWORD).
func writeDword(key, name string, val uint32) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, key, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("open %s: %w", key, err)
	}
	defer k.Close()
	if err := k.SetDWordValue(name, val); err != nil {
		return fmt.Errorf("set %s\\%s: %w", key, name, err)
	}
	return nil
}

// writeStringSubkey creates (or opens) `key` and sets `name = val` (REG_SZ).
// `key` is the full subkey path under HKLM (e.g.
// `SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist`).
func writeStringSubkey(key, name, val string) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, key, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("open %s: %w", key, err)
	}
	defer k.Close()
	if err := k.SetStringValue(name, val); err != nil {
		return fmt.Errorf("set %s\\%s: %w", key, name, err)
	}
	return nil
}

// deleteValue removes a single named value from a key. Returns
// registry.ErrNotExist when the key or value doesn't exist.
func deleteValue(key, name string) error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, key, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.DeleteValue(name)
}

// deleteSubkeyValue deletes value `name` inside subkey `key`.
func deleteSubkeyValue(key, name string) error {
	return deleteValue(key, name)
}
