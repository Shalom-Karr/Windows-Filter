// Package cmd contains the entry-point glue: service handler, install/uninstall,
// and -dev foreground runner. The actual business logic lives under internal/.
package cmd

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/Shalom-Karr/skfilter/internal/auth"
	"github.com/Shalom-Karr/skfilter/internal/config"
	"github.com/Shalom-Karr/skfilter/internal/db"
	"github.com/Shalom-Karr/skfilter/internal/firewall"
	"github.com/Shalom-Karr/skfilter/internal/httpapi"
	"github.com/Shalom-Karr/skfilter/internal/resolver"

	"golang.org/x/sys/windows/svc"
)

const (
	serviceName = "skfilter"
	listenAddr  = "127.0.0.1:8765"
)

// RunService is the entry point in service mode (called when SCM starts the
// EXE with no flags). It blocks until the SCM signals stop or shutdown.
func RunService() error {
	return svc.Run(serviceName, &skfilterService{})
}

type skfilterService struct{}

// Execute satisfies svc.Handler. The SCM calls this on a worker goroutine.
func (s *skfilterService) Execute(_ []string, r <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown
	status <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	loopErr := make(chan error, 1)
	go func() { loopErr <- runMainLoop(ctx) }()

	status <- svc.Status{State: svc.Running, Accepts: accepted}

	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				// wait for clean shutdown (best-effort)
				select {
				case err := <-loopErr:
					if err != nil {
						slog.Error("service loop exited with error", "err", err)
						status <- svc.Status{State: svc.Stopped}
						return false, 1
					}
				case <-time.After(8 * time.Second):
					slog.Warn("service loop did not exit within 8s")
				}
				status <- svc.Status{State: svc.Stopped}
				return false, 0
			}
		case err := <-loopErr:
			// Loop exited on its own (probably a fatal startup error). Crash so
			// SCM's failure-action policy restarts us.
			if err != nil {
				slog.Error("service loop exited unexpectedly", "err", err)
				status <- svc.Status{State: svc.Stopped}
				return false, 1
			}
			status <- svc.Status{State: svc.Stopped}
			return false, 0
		}
	}
}

// runMainLoop is the shared body of the service. It builds every runtime
// dependency, starts background workers (resolver + reconciler), serves HTTPS
// at 127.0.0.1:8765, and blocks until ctx is canceled.
func runMainLoop(ctx context.Context) error {
	if err := config.EnsureDirs(); err != nil {
		return fmt.Errorf("ensure dirs: %w", err)
	}

	store, err := db.Open(config.DBPath())
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer store.Close()

	if err := ensureCert(); err != nil {
		return fmt.Errorf("ensure tls cert: %w", err)
	}

	signingKey, err := store.Settings.EnsureSigningKey()
	if err != nil {
		return fmt.Errorf("signing key: %w", err)
	}
	sess := auth.NewSessions(signingKey)

	fw := firewall.NewNetshFirewall()
	rsv := resolver.NewResolver(store.Rules, store.Audit, fw)

	// Background workers — both honor ctx.Done().
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		firewall.NewReconciler(store, fw).Run(ctx)
	}()
	go func() {
		defer wg.Done()
		rsv.Run(ctx)
	}()

	handler := httpapi.Mount(httpapi.Deps{
		Store:    store,
		Sessions: sess,
		Firewall: fw,
		Resolver: rsv,
	})

	cert, err := tls.LoadX509KeyPair(config.TLSCertPath(), config.TLSKeyPath())
	if err != nil {
		return fmt.Errorf("load tls keypair: %w", err)
	}
	server := &http.Server{
		Addr:    listenAddr,
		Handler: handler,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		},
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	serverErr := make(chan error, 1)
	go func() {
		slog.Info("dashboard listening", "addr", "https://"+listenAddr)
		err := server.ListenAndServeTLS("", "")
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
		close(serverErr)
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			slog.Warn("http shutdown", "err", err)
		}
	case err, ok := <-serverErr:
		if ok && err != nil {
			return fmt.Errorf("http server: %w", err)
		}
	}

	wg.Wait()
	return nil
}

// ensureCert generates a self-signed 4096-bit RSA cert (CN=127.0.0.1, IP SAN
// 127.0.0.1, valid 10 years) at config.TLSCertPath / TLSKeyPath if either is
// missing.
func ensureCert() error {
	certPath := config.TLSCertPath()
	keyPath := config.TLSKeyPath()
	if fileExists(certPath) && fileExists(keyPath) {
		return nil
	}

	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return fmt.Errorf("gen rsa key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("serial: %w", err)
	}
	now := time.Now()
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "127.0.0.1", Organization: []string{"skfilter"}},
		NotBefore:    now.Add(-1 * time.Hour),
		NotAfter:     now.AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		DNSNames:     []string{"localhost"},
		IsCA:         true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("create cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		return fmt.Errorf("write cert: %w", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return fmt.Errorf("write key: %w", err)
	}
	return nil
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}
