package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Shalom-Karr/skfilter/internal/auth"
	"github.com/Shalom-Karr/skfilter/internal/config"
	"github.com/Shalom-Karr/skfilter/internal/db"
	"github.com/Shalom-Karr/skfilter/internal/policies"

	"golang.org/x/sys/windows/svc/mgr"
	"golang.org/x/term"
)

const (
	serviceDisplay  = "Skfilter (allowlist firewall)"
	loopbackRule    = "skfilter_self_loopback"
	selfProgramRule = "skfilter_self_program"
)

// Install registers the service, sets failure recovery, applies default-deny
// outbound, and starts the service.
func Install() error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve exe path: %w", err)
	}
	exePath, err = filepath.Abs(exePath)
	if err != nil {
		return fmt.Errorf("absolute exe path: %w", err)
	}

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect SCM (run as Administrator?): %w", err)
	}
	defer m.Disconnect()

	// Refuse to clobber an existing installation; force the user to uninstall first.
	if existing, err := m.OpenService(serviceName); err == nil {
		_ = existing.Close()
		return fmt.Errorf("service %q already exists; run -uninstall first", serviceName)
	}

	cfg := mgr.Config{
		ServiceType:  windowsServiceWin32OwnProcess,
		StartType:    mgr.StartAutomatic,
		ErrorControl: mgr.ErrorNormal,
		BinaryPathName: exePath,
		DisplayName:    serviceDisplay,
		Description:    "Default-deny outbound firewall with a per-domain allowlist managed at http://localhost:8764.",
	}
	s, err := m.CreateService(serviceName, exePath, cfg)
	if err != nil {
		return fmt.Errorf("create service: %w", err)
	}
	defer s.Close()

	// Auto-restart with 5s delay; reset counter never (period 0 = never reset).
	if err := s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
	}, 0); err != nil {
		// Non-fatal — the service still works without recovery.
		fmt.Fprintln(os.Stderr, "warning: SetRecoveryActions:", err)
	}

	// NOTE: default-deny is NOT applied here. The service's reconciler
	// gates enforcement on IsPasswordSet() and stays in stand-down until
	// the user completes /setup. This prevents the box from sitting in
	// "default-deny with no UI to manage rules" right after install. Once
	// the password is saved, the reconciler's next tick (≤ 5s later)
	// applies blockinbound,blockoutbound automatically.

	// Loopback allow so the service can talk to itself / dashboard reaches the listener.
	_ = runNetsh("advfirewall", "firewall", "delete", "rule", "name="+loopbackRule)
	if err := runNetsh(
		"advfirewall", "firewall", "add", "rule",
		"name="+loopbackRule,
		"dir=out",
		"action=allow",
		"protocol=any",
		"remoteip=127.0.0.1",
		"enable=yes",
		"profile=any",
	); err != nil {
		return fmt.Errorf("add loopback rule: %w", err)
	}

	// skfilter.exe itself needs outbound for DNS resolution (so it can
	// resolve the domains the user adds to the allowlist). Without this
	// rule, default-deny blocks the resolver's net.LookupIP calls and
	// rules sit with empty IPs forever.
	_ = runNetsh("advfirewall", "firewall", "delete", "rule", "name="+selfProgramRule)
	if err := runNetsh(
		"advfirewall", "firewall", "add", "rule",
		"name="+selfProgramRule,
		"dir=out",
		"action=allow",
		"program="+exePath,
		"enable=yes",
		"profile=any",
	); err != nil {
		return fmt.Errorf("add self-program rule: %w", err)
	}

	// Preserve any remote-management tool the user is currently using on
	// this box (AnyDesk, TeamViewer, RustDesk). Without this, flipping
	// default-deny would terminate the very session the user is on.
	addPreserveRules()

	// Browser lockdown — Chrome / Edge force-install + Incognito off,
	// DevTools off, only-our-extension allowed, no new profiles. Non-fatal
	// if it partly fails; the reconciler will keep trying on every tick.
	if err := policies.WriteBrowserPolicies(); err != nil {
		fmt.Fprintln(os.Stderr, "warning: write browser policies:", err)
	}

	if err := s.Start(); err != nil {
		return fmt.Errorf("start service: %w", err)
	}

	fmt.Println("skfilter installed and running.")
	fmt.Println("Open http://localhost:8764 to set your password.")

	// Pop a live status monitor in its own console window so the user can
	// see the filter is alive. The status command is read-only — closing
	// the window doesn't affect the running service.
	spawnStatusWindow(exePath)

	return nil
}

// spawnStatusWindow launches `skfilter.exe -status` in a fresh detached
// console. Best-effort: a failure here is just cosmetic — the service is
// already running and can be monitored by re-running -status manually.
func spawnStatusWindow(exePath string) {
	const CREATE_NEW_CONSOLE = 0x00000010
	c := exec.Command(exePath, "-status")
	c.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: CREATE_NEW_CONSOLE,
	}
	if err := c.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "warning: status window:", err)
		return
	}
	// Don't wait for it — it's its own process now.
	_ = c.Process.Release()
}

// Uninstall verifies the dashboard password, then stops + deletes the service
// and restores the default firewall policy.
func Uninstall() error {
	pw, err := readPasswordPrompt("Dashboard password (required to uninstall): ")
	if err != nil {
		return err
	}
	if pw == "" {
		return errors.New("password required")
	}

	store, err := db.Open(config.DBPath())
	if err != nil {
		return fmt.Errorf("open db (is skfilter installed?): %w", err)
	}
	hash, err := store.Settings.GetPasswordHash()
	_ = store.Close()
	if err != nil {
		return fmt.Errorf("read password hash: %w", err)
	}
	if len(hash) == 0 {
		return errors.New("no dashboard password set yet — refusing to auto-uninstall; stop the service manually if desired")
	}
	if !auth.VerifyPassword(hash, pw) {
		return errors.New("password mismatch")
	}

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect SCM (run as Administrator?): %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		fmt.Fprintln(os.Stderr, "warning: open service:", err)
	} else {
		_ = stopServiceWait(s, 15*time.Second)
		if err := s.Delete(); err != nil {
			fmt.Fprintln(os.Stderr, "warning: delete service:", err)
		}
		_ = s.Close()
	}

	// "blockinbound,allowoutbound" is the Windows factory default for the
	// local store. "notconfigured" is GPO-only.
	if err := runNetsh("advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,allowoutbound"); err != nil {
		fmt.Fprintln(os.Stderr, "warning: restore default policy:", err)
	}
	_ = runNetsh("advfirewall", "firewall", "delete", "rule", "name="+loopbackRule)
	_ = runNetsh("advfirewall", "firewall", "delete", "rule", "name="+selfProgramRule)
	removePreserveRules()

	// Strip the HKLM browser policy keys we installed. Best-effort.
	if err := policies.RemoveBrowserPolicies(); err != nil {
		fmt.Fprintln(os.Stderr, "warning: remove browser policies:", err)
	}

	fmt.Println("skfilter service removed and default firewall policy restored.")
	fmt.Printf("State directory left intact at %s (delete manually if you want a clean slate).\n", config.DataDir())
	return nil
}

func runNetsh(args ...string) error {
	cmd := exec.Command("netsh", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("netsh %s: %w (%s)", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func readPasswordPrompt(prompt string) (string, error) {
	fmt.Print(prompt)
	fd := int(syscall.Stdin)
	if term.IsTerminal(fd) {
		b, err := term.ReadPassword(fd)
		fmt.Println()
		if err != nil {
			return "", fmt.Errorf("read password: %w", err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	r := bufio.NewReader(os.Stdin)
	line, err := r.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	return strings.TrimSpace(line), nil
}
