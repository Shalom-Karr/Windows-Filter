package firewall

import (
	"bufio"
	"regexp"
	"sort"
	"strings"
)

// ruleNameRE constrains rule names we own. Enforced before every netsh shell-out.
var ruleNameRE = regexp.MustCompile(`^skfilter_[a-z0-9_]+$`)

// validRuleName reports whether name is in the skfilter_ namespace and safe to
// pass as a netsh argv token. It rejects spaces, quotes, slashes, etc.
func validRuleName(name string) bool {
	return ruleNameRE.MatchString(name)
}

// formatRemoteIPs joins IPs into the comma form netsh expects ("1.2.3.4,5.6.7.8").
// Caller is responsible for having validated each IP first.
func formatRemoteIPs(ips []string) string {
	cleaned := make([]string, 0, len(ips))
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip != "" {
			cleaned = append(cleaned, ip)
		}
	}
	return strings.Join(cleaned, ",")
}

// parseRulesOutput walks `netsh advfirewall firewall show rule name=all` output
// and returns every rule whose name starts with "skfilter_". v4/v6 siblings
// (suffix _v4 / _v6) are merged into a single Rule keyed by base name.
//
// The netsh output is line-based, one block per rule, separated by blank lines.
// Relevant lines for us:
//
//	Rule Name:                            skfilter_42_v4
//	RemoteIP:                             1.2.3.4/32,5.6.7.8/32
//
// Trailing "/32" / "/128" suffixes are stripped so callers see plain IP literals.
func parseRulesOutput(out string) []Rule {
	type acc struct {
		ips map[string]struct{}
	}
	merged := map[string]*acc{}

	addRule := func(name string, ips []string) {
		base := strings.TrimSuffix(strings.TrimSuffix(name, "_v4"), "_v6")
		if !strings.HasPrefix(base, "skfilter_") {
			return
		}
		a, ok := merged[base]
		if !ok {
			a = &acc{ips: map[string]struct{}{}}
			merged[base] = a
		}
		for _, ip := range ips {
			a.ips[ip] = struct{}{}
		}
	}

	var (
		curName string
		curIPs  []string
	)
	flush := func() {
		if curName != "" {
			addRule(curName, curIPs)
		}
		curName = ""
		curIPs = nil
	}

	scanner := bufio.NewScanner(strings.NewReader(out))
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			flush()
			continue
		}
		key, val, ok := splitRuleLine(line)
		if !ok {
			continue
		}
		switch strings.ToLower(key) {
		case "rule name":
			// Each "Rule Name:" begins a new block. Flush any prior accumulator.
			flush()
			curName = val
		case "remoteip":
			curIPs = append(curIPs, parseRemoteIPField(val)...)
		}
	}
	flush()

	out2 := make([]Rule, 0, len(merged))
	for name, a := range merged {
		ips := make([]string, 0, len(a.ips))
		for ip := range a.ips {
			ips = append(ips, ip)
		}
		sort.Strings(ips)
		out2 = append(out2, Rule{Name: name, IPs: ips})
	}
	sort.Slice(out2, func(i, j int) bool { return out2[i].Name < out2[j].Name })
	return out2
}

// splitRuleLine parses a "Key: value" line. Returns ("", "", false) on miss.
func splitRuleLine(line string) (string, string, bool) {
	idx := strings.Index(line, ":")
	if idx < 0 {
		return "", "", false
	}
	key := strings.TrimSpace(line[:idx])
	val := strings.TrimSpace(line[idx+1:])
	if key == "" {
		return "", "", false
	}
	return key, val, true
}

// parseRemoteIPField parses values like:
//
//	"1.2.3.4/32,5.6.7.8/32"
//	"2001:db8::1-2001:db8::1"               (single IPv6 rendered as range)
//	"2001:db8::1-2001:db8::8"               (genuine range)
//	"Any"
//
// Behavior:
//   - "Any" → nil (means "no remoteip scoping" — netsh sometimes prints this)
//   - "/N"  → strip the CIDR suffix
//   - "X-X" → normalize to just "X" (netsh stores single IPv6 addresses as
//     degenerate ranges; without this normalization the reconciler sees a
//     mismatch between desired "X" and actual "X-X" and loops forever
//     trying to "repair" rules that are already correct)
//   - "X-Y" → keep as-is (genuine multi-address range)
func parseRemoteIPField(v string) []string {
	if v == "" || strings.EqualFold(v, "Any") {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if i := strings.Index(p, "/"); i >= 0 {
			p = p[:i]
		}
		if i := strings.Index(p, "-"); i >= 0 {
			start := strings.TrimSpace(p[:i])
			end := strings.TrimSpace(p[i+1:])
			if start == end && start != "" {
				p = start
			}
		}
		out = append(out, p)
	}
	return out
}
