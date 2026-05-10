// Remote-management-tool preservation. If skfilter is going to flip a
// default-deny outbound policy on a box you're currently managing
// remotely, we need to make sure your management tool keeps working —
// otherwise you lock yourself out the instant the filter activates.
//
// This file scans for known remote-management software at install /
// -test time and adds outbound allow rules for each one. The rules are
// named `skfilter_preserve_<tool>` and are listed in the system-reserved
// set so the reconciler doesn't sweep them.
//
// Currently covers AnyDesk. New tools are trivial to add — just append
// to the preservedTools table.
package cmd

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// preservedTool describes one remote-management tool we want to keep
// alive across a default-deny flip. The first path that exists on disk
// wins.
type preservedTool struct {
	name     string   // human-readable, used in stdout messages
	ruleName string   // netsh rule name (must match skfilter_preserve_*)
	paths    []string // candidate install locations, checked in order
}

// preservedTools is the registry of tools we auto-preserve. Add new ones
// here. Reconciler whitelists every name starting with skfilter_preserve_.
var preservedTools = []preservedTool{
	{
		name:     "AnyDesk",
		ruleName: "skfilter_preserve_anydesk",
		paths: []string{
			`C:\Program Files (x86)\AnyDesk\AnyDesk.exe`,
			`C:\Program Files\AnyDesk\AnyDesk.exe`,
			filepath.Join(os.Getenv("LOCALAPPDATA"), `Programs`, `AnyDesk`, `AnyDesk.exe`),
			filepath.Join(os.Getenv("APPDATA"), `AnyDesk`, `AnyDesk.exe`),
			filepath.Join(os.Getenv("PROGRAMDATA"), `AnyDesk`, `AnyDesk.exe`),
		},
	},
	{
		name:     "TeamViewer",
		ruleName: "skfilter_preserve_teamviewer",
		paths: []string{
			`C:\Program Files (x86)\TeamViewer\TeamViewer_Service.exe`,
			`C:\Program Files\TeamViewer\TeamViewer_Service.exe`,
		},
	},
	{
		name:     "RustDesk",
		ruleName: "skfilter_preserve_rustdesk",
		paths: []string{
			`C:\Program Files\RustDesk\rustdesk.exe`,
			`C:\Program Files (x86)\RustDesk\rustdesk.exe`,
		},
	},
}

const rdpInboundRuleName = "skfilter_preserve_rdp"

// addPreserveRules adds firewall rules that keep remote-management
// sessions alive across a default-deny flip:
//   - One outbound rule per detected tool (AnyDesk, TeamViewer, RustDesk).
//   - One inbound rule for the current RDP listener port (so RDP sessions
//     can be reached even with blockinbound default).
// Failures are non-fatal — print a warning, keep going. Idempotent: existing
// rules with the same name are deleted first.
func addPreserveRules() {
	any := false
	for _, t := range preservedTools {
		path := firstExisting(t.paths)
		if path == "" {
			continue
		}
		_ = runNetsh("advfirewall", "firewall", "delete", "rule", "name="+t.ruleName)
		if err := runNetsh(
			"advfirewall", "firewall", "add", "rule",
			"name="+t.ruleName,
			"dir=out",
			"action=allow",
			"program="+path,
			"enable=yes",
			"profile=any",
		); err != nil {
			fmt.Fprintln(os.Stderr, "warning: preserve "+t.name+":", err)
			continue
		}
		fmt.Printf("Preserving %s outbound (%s)\n", t.name, path)
		any = true
	}

	// Inbound RDP — preserve the session you're using to run this.
	port := currentRDPPort()
	_ = runNetsh("advfirewall", "firewall", "delete", "rule", "name="+rdpInboundRuleName)
	if err := runNetsh(
		"advfirewall", "firewall", "add", "rule",
		"name="+rdpInboundRuleName,
		"dir=in",
		"action=allow",
		"protocol=TCP",
		"localport="+strconv.Itoa(port),
		"enable=yes",
		"profile=any",
	); err != nil {
		fmt.Fprintln(os.Stderr, "warning: preserve RDP inbound:", err)
	} else {
		fmt.Printf("Preserving RDP inbound on TCP port %d\n", port)
	}
	// Also force-enable the built-in Remote Desktop firewall group across
	// all profiles, in case Windows had it scoped to Domain/Private only.
	_ = runNetsh("advfirewall", "firewall", "set", "rule", `group="remote desktop"`, "new", "enable=Yes")

	if !any {
		fmt.Println("(No outbound remote-management tools detected. RDP inbound preserved.)")
	}
}

// removePreserveRules deletes every skfilter_preserve_* rule. Called from
// -test cleanup and from -uninstall. Errors swallowed — "no rules match"
// from netsh on a non-existent rule isn't a problem.
func removePreserveRules() {
	for _, t := range preservedTools {
		_ = runNetsh("advfirewall", "firewall", "delete", "rule", "name="+t.ruleName)
	}
	_ = runNetsh("advfirewall", "firewall", "delete", "rule", "name="+rdpInboundRuleName)
}

// currentRDPPort reads HKLM\SYSTEM\CurrentControlSet\Control\Terminal
// Server\WinStations\RDP-Tcp\PortNumber. Defaults to 3389 if the key is
// missing or unparseable. Soladrive's Windows image ships RDP on 23389
// (security-by-obscurity); we read the actual value so the allow rule
// matches the listener.
func currentRDPPort() int {
	const fallback = 3389
	cmd := exec.Command("reg", "query",
		`HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`,
		"/v", "PortNumber")
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Run(); err != nil {
		return fallback
	}
	for _, line := range strings.Split(buf.String(), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "PortNumber") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		// "PortNumber   REG_DWORD   0xd3d"
		v := fields[len(fields)-1]
		if strings.HasPrefix(v, "0x") || strings.HasPrefix(v, "0X") {
			if n, err := strconv.ParseInt(v[2:], 16, 32); err == nil {
				return int(n)
			}
		} else if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

func firstExisting(paths []string) string {
	for _, p := range paths {
		if p == "" {
			continue
		}
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}
