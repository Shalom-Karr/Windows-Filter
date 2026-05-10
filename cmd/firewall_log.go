// Firewall-log tailing for -test mode.
//
// Windows Defender Firewall can write every allow/drop decision to a log
// file (W3C-ish format). We enable that log on -test entry, tail the file
// in a goroutine, parse each line, cross-reference the destination IP
// against the user's rules table, and print a human-readable line per
// decision. On exit we disable logging so we don't leak a growing file.
package cmd

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Shalom-Karr/skfilter/internal/db"
)

const firewallLogPath = `C:\Windows\System32\LogFiles\Firewall\pfirewall.log`

// enableFirewallLogging configures netsh to write allow + drop events to
// pfirewall.log with a 4 MB rotation cap. Best-effort: prints warnings for
// individual failures but doesn't bail out — partial logging is still
// useful.
func enableFirewallLogging() {
	if err := runNetsh("advfirewall", "set", "allprofiles", "logging", "filename", firewallLogPath); err != nil {
		fmt.Fprintln(os.Stderr, "warning: set log filename:", err)
	}
	if err := runNetsh("advfirewall", "set", "allprofiles", "logging", "maxfilesize", "4096"); err != nil {
		fmt.Fprintln(os.Stderr, "warning: set log maxfilesize:", err)
	}
	if err := runNetsh("advfirewall", "set", "allprofiles", "logging", "droppedconnections", "enable"); err != nil {
		fmt.Fprintln(os.Stderr, "warning: enable dropped logging:", err)
	}
	if err := runNetsh("advfirewall", "set", "allprofiles", "logging", "allowedconnections", "enable"); err != nil {
		fmt.Fprintln(os.Stderr, "warning: enable allowed logging:", err)
	}
}

// disableFirewallLogging undoes enableFirewallLogging on -test exit.
func disableFirewallLogging() {
	_ = runNetsh("advfirewall", "set", "allprofiles", "logging", "droppedconnections", "disable")
	_ = runNetsh("advfirewall", "set", "allprofiles", "logging", "allowedconnections", "disable")
}

// ipDomainCache snapshots the rules table so the tailer can quickly map a
// destination IP back to the rule that allowed it (label every ALLOW line
// with the matching domain). Refreshed every 5 seconds.
type ipDomainCache struct {
	mu       sync.RWMutex
	byIP     map[string]string
	lastLoad time.Time
}

func (c *ipDomainCache) refresh(store *db.Store) {
	rules, err := store.Rules.AllEnabled()
	if err != nil {
		return
	}
	m := make(map[string]string, 64)
	for _, r := range rules {
		for _, ip := range r.IPs {
			m[ip] = r.Domain
		}
	}
	c.mu.Lock()
	c.byIP = m
	c.lastLoad = time.Now()
	c.mu.Unlock()
}

func (c *ipDomainCache) lookup(ip string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.byIP[ip]
}

// tailFirewallLog streams pfirewall.log entries to stdout, in real time.
// Blocks until ctx is canceled. The first ~5 seconds may be empty while
// Windows Firewall writes its file header.
func tailFirewallLog(ctx context.Context, store *db.Store) {
	cache := &ipDomainCache{byIP: map[string]string{}}
	cache.refresh(store)

	// Refresh the IP-domain map on a slow tick.
	go func() {
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				cache.refresh(store)
			}
		}
	}()

	// Wait for the file to exist (Windows Firewall creates it lazily after
	// the next logged decision).
	var f *os.File
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		var err error
		f, err = os.Open(firewallLogPath)
		if err == nil {
			break
		}
		time.Sleep(1 * time.Second)
	}
	defer f.Close()

	// Skip whatever already-written lines exist — only follow new entries
	// that occur during this -test session.
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		fmt.Fprintln(os.Stderr, "warning: seek log:", err)
		return
	}

	reader := bufio.NewReader(f)
	fmt.Println("[firewall-log] streaming decisions to console below (Ctrl-C to stop early)...")
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		line, err := reader.ReadString('\n')
		if err == io.EOF || line == "" {
			time.Sleep(250 * time.Millisecond)
			continue
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "warning: read log:", err)
			time.Sleep(1 * time.Second)
			continue
		}
		printDecision(line, cache)
	}
}

// printDecision parses one pfirewall.log line and emits a human line to stdout.
//
// Log fields (space-separated, fixed order per W3C log spec):
//
//	#Fields: date time action protocol src-ip dst-ip src-port dst-port
//	         size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path
//
// We care about: action, protocol, dst-ip, dst-port, path (SEND = outbound).
func printDecision(line string, cache *ipDomainCache) {
	line = strings.TrimRight(line, "\r\n")
	if line == "" || strings.HasPrefix(line, "#") {
		return
	}
	fields := strings.Fields(line)
	if len(fields) < 17 {
		return
	}
	date, ts := fields[0], fields[1]
	action := fields[2]
	proto := fields[3]
	dst := fields[5]
	dport := fields[7]
	path := fields[16] // SEND / RECEIVE

	// Only outbound decisions are interesting — inbound spam is mostly
	// scanners hitting closed ports.
	if path != "SEND" {
		return
	}

	domain := cache.lookup(dst)

	var tag, color, reason string
	switch action {
	case "ALLOW":
		tag = "[ALLOW]"
		color = "\x1b[32m"
		if domain != "" {
			reason = "rule: " + domain
		} else {
			// An ALLOW with no matching rule means it matched a Windows-
			// built-in allow (DHCP, loopback, etc.) or our self-program
			// rule. Tag it as system-allowed.
			reason = "system / built-in"
		}
	case "DROP":
		tag = "[BLOCK]"
		color = "\x1b[31m"
		reason = "no rule for " + dst
	default:
		return
	}

	reset := "\x1b[0m"
	when := date + " " + ts
	fmt.Printf("%s%s%s %s %s %s:%s — %s\n", color, tag, reset, when, proto, dst, dport, reason)
}
