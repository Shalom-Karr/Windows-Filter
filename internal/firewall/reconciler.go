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
// any drift. It also re-asserts the default-deny outbound policy when
// EnforceDefaultDeny is true (production / service mode).
type Reconciler struct {
	store              *db.Store
	fw                 Firewall
	interval           time.Duration
	enforceDefaultDeny bool
	policyRepairer     func() error
	lastPolicyErr      string // last non-nil err message, used to dedupe audit entries
	policyHealthy      bool   // last known good/bad state, drives transition audits
}

// ReconcilerOptions tunes the reconciler. Zero values are safe for dev mode.
type ReconcilerOptions struct {
	// Interval between ticks. Defaults to 5s if zero. Floor with the
	// netsh-shell-out approach is ~5s; below that the box wastes CPU on
	// netsh parsing without gaining real-time-ness.
	Interval time.Duration
	// EnforceDefaultDeny re-applies blockoutbound on every tick if the
	// firewall's default policy has drifted. Requires admin. Set true in
	// service mode (the installer set the policy at install time and the
	// reconciler keeps it pinned). Set false in dev mode so dashboards can
	// be tested without elevation.
	EnforceDefaultDeny bool

	// PolicyRepairer, when non-nil, is invoked on every tick (after the
	// firewall reconciliation) to re-assert HKLM browser policy keys. The
	// runtime wires this to cmd/internal-policies WriteBrowserPolicies so
	// the firewall package itself stays free of registry / cmd imports.
	// Only invoked when EnforceDefaultDeny is true (service mode).
	PolicyRepairer func() error
}

// NewReconciler builds a reconciler. Pass options to tune.
func NewReconciler(store *db.Store, fw Firewall, opts ReconcilerOptions) *Reconciler {
	interval := opts.Interval
	if interval <= 0 {
		interval = 5 * time.Second
	}
	return &Reconciler{
		store:              store,
		fw:                 fw,
		interval:           interval,
		enforceDefaultDeny: opts.EnforceDefaultDeny,
		policyRepairer:     opts.PolicyRepairer,
		policyHealthy:      true, // optimistic; first failure flips it
	}
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

	// Sweep rogue / orphaned skfilter_* rules. Two categories of name are
	// owned by the system, NOT by the DB, and must not be swept:
	//   skfilter_self_loopback — added by Install/test to allow 127.0.0.1
	//   skfilter_self_program  — added by Install/test to let skfilter.exe
	//                            do DNS lookups under default-deny
	for name := range actualByName {
		if _, ok := desiredByName[name]; ok {
			continue
		}
		if isSystemReservedRuleName(name) {
			continue
		}
		if err := r.fw.DeleteRule(name); err != nil {
			slog.Warn("reconciler: delete orphan", "name", name, "err", err)
			continue
		}
		_ = r.store.Audit.Log("reconciler", "rogue_rule_deleted", map[string]any{"name": name})
	}

	// Default-policy drift — only enforced when EnforceDefaultDeny is on.
	// In dev mode this is skipped so the user can test the dashboard
	// without admin privileges.
	if !r.enforceDefaultDeny {
		return
	}
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

	// Browser policy keys (HKLM Chrome/Edge force-install + lockdown).
	// We re-assert on every tick — registry writes are cheap and idempotent.
	// Audit log fires only on state transitions (healthy → failing, failing
	// → healthy) so we don't spam an entry every 5s.
	if r.policyRepairer != nil {
		err := r.policyRepairer()
		switch {
		case err == nil && !r.policyHealthy:
			_ = r.store.Audit.Log("reconciler", "policy_keys_repaired", map[string]any{
				"previous_err": r.lastPolicyErr,
			})
			r.policyHealthy = true
			r.lastPolicyErr = ""
		case err != nil && r.policyHealthy:
			r.policyHealthy = false
			r.lastPolicyErr = err.Error()
			_ = r.store.Audit.Log("reconciler", "policy_keys_repair_failed", map[string]any{
				"err": err.Error(),
			})
			slog.Warn("reconciler: policy repair", "err", err)
		case err != nil && !r.policyHealthy:
			// Still failing with possibly a new message; just track it.
			r.lastPolicyErr = err.Error()
		}
	}
}

// isSystemReservedRuleName returns true for rule names that the install /
// test plumbing manages directly outside the DB. The reconciler must NOT
// sweep these even though they match the skfilter_ prefix.
func isSystemReservedRuleName(name string) bool {
	switch name {
	case "skfilter_self_loopback", "skfilter_self_program":
		return true
	}
	return false
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
