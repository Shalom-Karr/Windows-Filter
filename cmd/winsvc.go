package cmd

import (
	"fmt"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// windowsServiceWin32OwnProcess is the constant value for SERVICE_WIN32_OWN_PROCESS.
// (mgr.Config.ServiceType is uint32; the typed constant lives in x/sys/windows.)
const windowsServiceWin32OwnProcess = uint32(windows.SERVICE_WIN32_OWN_PROCESS)

// stopServiceWait sends a Stop and polls until the service reports Stopped or
// the timeout elapses.
func stopServiceWait(s *mgr.Service, timeout time.Duration) error {
	status, err := s.Control(svc.Stop)
	if err != nil {
		return fmt.Errorf("stop control: %w", err)
	}
	deadline := time.Now().Add(timeout)
	for status.State != svc.Stopped {
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for service to stop")
		}
		time.Sleep(300 * time.Millisecond)
		status, err = s.Query()
		if err != nil {
			return fmt.Errorf("query status: %w", err)
		}
	}
	return nil
}
