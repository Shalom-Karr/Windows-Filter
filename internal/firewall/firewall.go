// Package firewall is the contract every consumer (httpapi, resolver,
// reconciler) uses to manipulate the host firewall. The concrete
// implementation is in netsh.go.
//
// The Firewall interface is the only seam into the OS firewall — keep it
// small, deterministic, and free of leaky platform types.
package firewall

// Rule is one logical skfilter rule, as observed in the firewall. A logical
// rule may map to two underlying netsh rules (an _v4 and a _v6); ListSkfilterRules
// merges them.
type Rule struct {
	Name string   // e.g. "skfilter_42"
	IPs  []string // merged v4 + v6 IPs
}

// Firewall is the contract every consumer uses.
type Firewall interface {
	// AddAllowRule creates an outbound-allow rule named "<name>_v4" (when ipv4
	// is non-empty) and "<name>_v6" (when ipv6 is non-empty). name must match
	// ^skfilter_[a-z0-9_]+$. Each IP is validated with net.ParseIP.
	AddAllowRule(name string, ipv4 []string, ipv6 []string) error

	// DeleteRule removes both "<name>_v4" and "<name>_v6". A missing rule is
	// not an error.
	DeleteRule(name string) error

	// ListSkfilterRules returns every rule whose name starts with "skfilter_",
	// merging v4/v6 pairs by base name.
	ListSkfilterRules() ([]Rule, error)

	// GetDefaultOutbound returns "block" when every profile reports
	// outbound-block, otherwise "allow".
	GetDefaultOutbound() (string, error)

	// SetDefaultOutboundBlock sets the firewall policy to
	// blockinboundalways,blockoutbound across all profiles.
	SetDefaultOutboundBlock() error
}
