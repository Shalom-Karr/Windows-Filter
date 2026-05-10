package firewall

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"time"

	"github.com/Shalom-Karr/skfilter/internal/db"
)

// Reconciler is Phase 7h: every interval, it diffs the SQLite-declared
// allowlist against what Windows Defender Firewall actually has and rewrites
// any drift. It also re-asserts the default-deny outbound policy.
type Reconciler struct {
	store    *db.Store
	fw       Firewall
	interval time.Duration
}

// NewReconciler builds a reconciler with a 10-second tick.
func NewReconciler(store *db.Store, fw Firewall) *Reconciler {
	return &Reconciler{store: store, fw: fw, interval: 10 * time.Second}
}

// Run blocks until ctx is canceled, ticking once immediately and then every
// interval.
func (r *Reconciler) Run(ctx context.Context) {
	t := time.NewTicker(r.interval)
	defer t.Stop()
	r.tick()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.tick()
		}
	}
}

func (r *Reconciler) tick() {
	desired, err := r.store.Rules.AllEnabled()
	if err != nil {
		slog.Error("reconciler: list rules", "err", err)
		return
	}
	actual, err := r.fw.ListSkfilterRules()
	if err != nil {
		slog.Error("reconciler: list firewall", "err", err)
		return
	}

	desiredByName := make(map[string][]string, len(desired))
	for _, d := range desired {
		if !d.Enabled {
			continue
		}
		name := fmt.Sprintf("skfilter_%d", d.ID)
		desiredByName[name] = sortedCopy(d.IPs)
	}
	actualByName := make(map[string][]string, len(actual))
	for _, a := range actual {
		actualByName[a.Name] = sortedCopy(a.IPs)
	}

	// Repair / add: anything in desired not matching actual.
	for name, want := range desiredByName {
		got, ok := actualByName[name]
		if ok && sliceEqual(want, got) {
			continue
		}
		ipv4, ipv6 := splitFamilies(want)
		_ = r.fw.DeleteRule(name)
		if err := r.fw.AddAllowRule(name, ipv4, ipv6); err != nil {
			_ = r.store.Audit.Log("reconciler", "rule_repair_failed", map[string]any{
				"name": name, "err": err.Error(),
			})
			continue
		}
		_ = r.store.Audit.Log("reconciler", "rule_repaired", map[string]any{
			"name": name, "ips": want, "previous": got,
		})
	}

	// Sweep rogue / orphaned skfilter_* rules.
	for name := range actualByName {
		if _, ok := desiredByName[name]; ok {
			continue
		}
		if err := r.fw.DeleteRule(name); err != nil {
			slog.Warn("reconciler: delete orphan", "name", name, "err", err)
			continue
		}
		_ = r.store.Audit.Log("reconciler", "rogue_rule_deleted", map[string]any{"name": name})
	}

	// Default-policy drift.
	cur, err := r.fw.GetDefaultOutbound()
	if err != nil {
		slog.Error("reconciler: read default policy", "err", err)
		return
	}
	if cur != "block" {
		if err := r.fw.SetDefaultOutboundBlock(); err != nil {
			slog.Error("reconciler: re-apply default-deny", "err", err)
			return
		}
		_ = r.store.Audit.Log("reconciler", "policy_drift_recovered", map[string]any{"observed": cur})
	}
}

func sortedCopy(in []string) []string {
	out := make([]string, len(in))
	copy(out, in)
	sort.Strings(out)
	return out
}

func sliceEqual(a, b []string) bool {
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

// splitFamilies separates a merged IP list back into IPv4 and IPv6 buckets.
// Anything that fails to parse is dropped silently — netsh would reject it
// anyway and the resolver already filters obvious garbage.
func splitFamilies(ips []string) (ipv4, ipv6 []string) {
	for _, s := range ips {
		ip := net.ParseIP(s)
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			ipv4 = append(ipv4, s)
		} else {
			ipv6 = append(ipv6, s)
		}
	}
	return
}
