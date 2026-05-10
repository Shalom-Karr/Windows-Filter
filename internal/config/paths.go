// Package config resolves filesystem paths skfilter uses for persistent state.
//
// In production the data directory is %PROGRAMDATA%\skfilter\. When the binary
// is run with -dev (no PROGRAMDATA / not elevated), callers may opt into a
// user-temp fallback by calling UseDevDir.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

const dirName = "skfilter"

var (
	mu     sync.RWMutex
	devDir string // when non-empty, overrides %PROGRAMDATA% lookup
)

// UseDevDir overrides the data directory; intended for -dev mode.
// Pass an empty string to clear the override.
func UseDevDir(dir string) {
	mu.Lock()
	defer mu.Unlock()
	devDir = dir
}

// DataDir returns the root data directory: %PROGRAMDATA%\skfilter\, or the
// dev override if set, or a user-temp fallback if neither is available.
func DataDir() string {
	mu.RLock()
	override := devDir
	mu.RUnlock()
	if override != "" {
		return override
	}
	if pd := os.Getenv("ProgramData"); pd != "" {
		return filepath.Join(pd, dirName)
	}
	if pd := os.Getenv("PROGRAMDATA"); pd != "" {
		return filepath.Join(pd, dirName)
	}
	return filepath.Join(os.TempDir(), dirName)
}

// DBPath is the SQLite store path.
func DBPath() string {
	return filepath.Join(DataDir(), "skfilter.db")
}

// TLSDir is the directory holding the self-signed cert + key.
func TLSDir() string {
	return filepath.Join(DataDir(), "tls")
}

// TLSCertPath returns the dashboard TLS certificate path.
func TLSCertPath() string {
	return filepath.Join(TLSDir(), "cert.pem")
}

// TLSKeyPath returns the dashboard TLS key path.
func TLSKeyPath() string {
	return filepath.Join(TLSDir(), "key.pem")
}

// EnsureDirs creates the data + TLS directories if they don't exist.
func EnsureDirs() error {
	for _, d := range []string{DataDir(), TLSDir()} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			return fmt.Errorf("mkdir %s: %w", d, err)
		}
	}
	return nil
}
