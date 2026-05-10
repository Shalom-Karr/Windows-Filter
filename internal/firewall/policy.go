package firewall

import "strings"

// parseDefaultOutbound walks `netsh advfirewall show allprofiles state` output
// and returns "block" only when every profile reports outbound = block; else
// "allow".
//
// netsh prints stanzas like:
//
//	Domain Profile Settings:
//	----------------------------------------------------------------------
//	State                                 ON
//	Firewall Policy                       BlockInbound,BlockOutbound
//	...
//
// We only need the "Firewall Policy" line per profile.
func parseDefaultOutbound(out string) string {
	policies := []string{}
	for _, line := range strings.Split(out, "\n") {
		key, val, ok := splitRuleLine(line)
		if !ok {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(key), "Firewall Policy") {
			policies = append(policies, strings.TrimSpace(val))
		}
	}
	if len(policies) == 0 {
		return "allow"
	}
	for _, p := range policies {
		if !strings.Contains(strings.ToLower(p), "blockoutbound") {
			return "allow"
		}
	}
	return "block"
}
