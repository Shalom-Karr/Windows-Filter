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

	slog.Info("skfilter -dev starting", "addr", "https://"+listenAddr)
	if err := runMainLoop(ctx); err != nil {
		return fmt.Errorf("dev loop: %w", err)
	}
	slog.Info("skfilter -dev stopped")
	return nil
}
