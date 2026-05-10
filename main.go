// skfilter — netsh-backed allowlist firewall for a single Windows machine.
//
// Run modes:
//
//	skfilter.exe              service mode (only valid when launched by SCM)
//	skfilter.exe -dev         foreground for development (Ctrl-C to stop)
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
	default:
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
		fmt.Println("skfilter usage:")
		fmt.Println("  -install     install as Windows service")
		fmt.Println("  -uninstall   uninstall the service (prompts for password)")
		fmt.Println("  -dev         run in foreground (development mode)")
		os.Exit(1)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
