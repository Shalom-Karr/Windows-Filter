// Package resolver re-resolves every enabled rule's domain on a 15-minute
// ticker, diffs the new IPs against the stored set, and rewrites the
// underlying firewall rule when they drift.
package resolver

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"time"

	"github.com/Shalom-Karr/skfilter/internal/db"
	"github.com/Shalom-Karr/skfilter/internal/firewall"
)

const tickInterval = 15 * time.Minute

// Resolver drives the periodic DNS-refresh loop.
type Resolver struct {
	rules *db.RulesRepo
	audit *db.AuditRepo
	fw    firewall.Firewall

	resolver *net.Resolver
	timeout  time.Duration
}

// NewResolver wires the dependencies.
func NewResolver(rules *db.RulesRepo, audit *db.AuditRepo, fw firewall.Firewall) *Resolver {
	return &Resolver{
		rules:    rules,
		audit:    audit,
		fw:       fw,
		resolver: net.DefaultResolver,
		timeout:  10 * time.Second,
	}
}

// Run blocks until ctx is cancelled, ticking every 15 min. The first tick
// fires immediately so service restarts re-converge fast.
func (rv *Resolver) Run(ctx context.Context) {
	rv.refreshAll(ctx)
	t := time.NewTicker(tickInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			rv.refreshAll(ctx)
		}
	}
}

func (rv *Resolver) refreshAll(ctx context.Context) {
	rules, err := rv.rules.AllEnabled()
	if err != nil {
		slog.Error("resolver: list rules", "err", err)
		return
	}
	for _, r := range rules {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if err := rv.ResolveAndApply(r.ID); err != nil {
			slog.Warn("resolver: refresh rule", "id", r.ID, "domain", r.Domain, "err", err)
		}
	}
}

// ResolveAndApply re-resolves a single rule's domain, and if the IP set
// drifted or the rule has never been resolved, rewrites the netsh rule.
func (rv *Resolver) ResolveAndApply(id int64) error {
	rule, err := rv.rules.Get(id)
	if err != nil {
		return fmt.Errorf("resolver: get rule %d: %w", id, err)
	}

	ipv4, ipv6, err := rv.lookupBoth(rule.Domain)
	if err != nil {
		return fmt.Errorf("resolver: lookup %s: %w", rule.Domain, err)
	}

	newAll := append(append([]string{}, ipv4...), ipv6...)
	sort.Strings(newAll)

	old := append([]string{}, rule.IPs...)
	sort.Strings(old)

	unchanged := equalStrings(old, newAll)
	if unchanged && rule.LastResolvedAt != nil {
		return nil
	}

	name := ruleName(id)
	// Best-effort delete: a missing rule is fine, we're about to add it.
	if err := rv.fw.DeleteRule(name); err != nil {
		slog.Warn("resolver: delete before re-add", "name", name, "err", err)
	}
	if len(newAll) > 0 {
		if err := rv.fw.AddAllowRule(name, ipv4, ipv6); err != nil {
			return fmt.Errorf("resolver: add %s: %w", name, err)
		}
	}
	if err := rv.rules.UpdateIPs(id, newAll); err != nil {
		return fmt.Errorf("resolver: persist ips: %w", err)
	}
	_ = rv.audit.Log("system", "ips_refreshed", map[string]any{
		"id":     id,
		"domain": rule.Domain,
		"old":    old,
		"new":    newAll,
	})
	return nil
}

// lookupBoth resolves the domain and splits results by family.
func (rv *Resolver) lookupBoth(domain string) ([]string, []string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), rv.timeout)
	defer cancel()
	addrs, err := rv.resolver.LookupIP(ctx, "ip", domain)
	if err != nil {
		return nil, nil, err
	}
	var v4, v6 []string
	for _, a := range addrs {
		if a4 := a.To4(); a4 != nil {
			v4 = append(v4, a4.String())
		} else {
			v6 = append(v6, a.String())
		}
	}
	return dedup(v4), dedup(v6), nil
}

func dedup(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := in[:0]
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ruleName produces the canonical "skfilter_<id>" identifier. Other packages
// import resolver only for Run/ResolveAndApply, but reconciler will pick up
// this naming convention via firewall.ListSkfilterRules.
func ruleName(id int64) string {
	return fmt.Sprintf("skfilter_%d", id)
}
