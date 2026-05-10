package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

// RunDev runs the service body in the foreground until Ctrl-C. Logs to stderr.
func RunDev() error {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	slog.Info("skfilter -dev starting", "addr", "http://"+listenAddr)
	// Dev mode: do NOT enforce default-deny — that requires admin and would
	// spam the log with elevation errors. Test the dashboard freely; flip the
	// firewall manually in a separate Admin shell when you want to test rule
	// enforcement.
	if err := runMainLoop(ctx, runMode{enforceDefaultDeny: false}); err != nil {
		return fmt.Errorf("dev loop: %w", err)
	}
	slog.Info("skfilter -dev stopped")
	return nil
}
