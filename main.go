// skfilter — netsh-backed allowlist firewall for a single Windows machine.
//
// Run modes:
//
//	skfilter.exe              "just make it work":
//	                            • SCM-launched  → service mode
//	                            • Admin user    → install (if needed) + start service
//	                            • Non-admin     → print elevate-and-rerun message, exit
//	skfilter.exe -dev         foreground for development (Ctrl-C to stop, no admin needed)
//	skfilter.exe -test        flip default-deny + run dashboard for 5 min, then auto-revert (admin)
//	skfilter.exe -install     register as a Windows service and lock the firewall
//	skfilter.exe -uninstall   prompts for the dashboard password, then removes
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/Shalom-Karr/skfilter/cmd"
	"golang.org/x/sys/windows/svc"
)

func main() {
	install := flag.Bool("install", false, "install as Windows service")
	uninstall := flag.Bool("uninstall", false, "uninstall the service (prompts for password)")
	dev := flag.Bool("dev", false, "run in foreground (development mode)")
	test := flag.Bool("test", false, "5-minute self-disarming default-deny run (admin required)")
	status := flag.Bool("status", false, "open a live status monitor window (read-only)")
	flag.Parse()

	switch {
	case *install:
		if err := cmd.Install(); err != nil {
			fail(err)
		}
	case *uninstall:
		if err := cmd.Uninstall(); err != nil {
			fail(err)
		}
	case *dev:
		if err := cmd.RunDev(); err != nil {
			fail(err)
		}
	case *test:
		if err := cmd.RunTest(); err != nil {
			fail(err)
		}
	case *status:
		if err := cmd.RunStatus(); err != nil {
			fail(err)
		}
	default:
		// Are we being launched by the Service Control Manager?
		isService, err := svc.IsWindowsService()
		if err != nil {
			fail(err)
		}
		if isService {
			if err := cmd.RunService(); err != nil {
				fail(err)
			}
			return
		}

		// Interactive launch (double-click, command line). The default for the
		// admin case is "auto-install + start"; for non-admin it's "tell the
		// user how to elevate."
		if !cmd.IsAdmin() {
			fmt.Println("skfilter needs Administrator privileges to manage Windows Firewall.")
			fmt.Println()
			fmt.Println("  Right-click skfilter.exe → Run as administrator")
			fmt.Println()
			fmt.Println("Or, for dashboard-only testing (no firewall changes):")
			fmt.Println("  skfilter.exe -dev")
			os.Exit(1)
		}
		// Admin path: ensure installed + running, then exit.
		if err := cmd.EnsureInstalledAndRunning(); err != nil {
			fail(err)
		}
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
