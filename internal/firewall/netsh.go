package firewall

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"
)

// netshTimeout caps every netsh invocation. netsh is normally < 1s; if it
// hangs we'd rather fail loud than block the reconciler.
const netshTimeout = 30 * time.Second

// netshExecutor invokes netsh with the given args and returns combined output.
// Split out so tests can substitute. Default: real exec.
type netshExecutor func(ctx context.Context, args ...string) ([]byte, error)

func realNetsh(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "netsh", args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.Bytes(), err
}

// NetshFirewall implements Firewall by shelling out to netsh.exe.
type NetshFirewall struct {
	exec netshExecutor
}

// NewNetshFirewall returns the production Firewall implementation.
func NewNetshFirewall() Firewall {
	return &NetshFirewall{exec: realNetsh}
}

func (n *NetshFirewall) run(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), netshTimeout)
	defer cancel()
	out, err := n.exec(ctx, args...)
	if err != nil {
		return out, fmt.Errorf("netsh %s: %w (output: %s)",
			strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

// AddAllowRule creates outbound-allow rules for the v4 and v6 IP lists.
// Empty families are skipped — we never create a rule with no remoteip scope.
func (n *NetshFirewall) AddAllowRule(name string, ipv4 []string, ipv6 []string) error {
	if !validRuleName(name) {
		return fmt.Errorf("firewall.AddAllowRule: invalid name %q", name)
	}
	v4, err := filterIPs(ipv4, true)
	if err != nil {
		return fmt.Errorf("firewall.AddAllowRule v4: %w", err)
	}
	v6, err := filterIPs(ipv6, false)
	if err != nil {
		return fmt.Errorf("firewall.AddAllowRule v6: %w", err)
	}
	if len(v4) == 0 && len(v6) == 0 {
		return fmt.Errorf("firewall.AddAllowRule: no valid IPs supplied")
	}
	if len(v4) > 0 {
		if err := n.addOne(name+"_v4", v4); err != nil {
			return err
		}
	}
	if len(v6) > 0 {
		if err := n.addOne(name+"_v6", v6); err != nil {
			return err
		}
	}
	return nil
}

func (n *NetshFirewall) addOne(fullName string, ips []string) error {
	args := []string{
		"advfirewall", "firewall", "add", "rule",
		"name=" + fullName,
		"dir=out",
		"action=allow",
		"protocol=any",
		"remoteip=" + formatRemoteIPs(ips),
		"enable=yes",
		"profile=any",
	}
	if _, err := n.run(args...); err != nil {
		return err
	}
	return nil
}

// DeleteRule removes both the v4 and v6 sub-rules. A "no rules match" exit
// code is swallowed; netsh prints "No rules match the specified criteria."
// to stdout but returns non-zero — both signals are treated as success.
func (n *NetshFirewall) DeleteRule(name string) error {
	if !validRuleName(name) {
		return fmt.Errorf("firewall.DeleteRule: invalid name %q", name)
	}
	for _, suffix := range []string{"_v4", "_v6"} {
		_, err := n.run("advfirewall", "firewall", "delete", "rule", "name="+name+suffix)
		if err != nil && !isNoMatchErr(err) {
			return fmt.Errorf("firewall.DeleteRule %s%s: %w", name, suffix, err)
		}
	}
	return nil
}

// ListSkfilterRules dumps every rule and filters/merges by skfilter_ prefix.
func (n *NetshFirewall) ListSkfilterRules() ([]Rule, error) {
	out, err := n.run("advfirewall", "firewall", "show", "rule", "name=all")
	if err != nil {
		return nil, fmt.Errorf("firewall.ListSkfilterRules: %w", err)
	}
	return parseRulesOutput(string(out)), nil
}

// GetDefaultOutbound returns "block" or "allow".
//
// IMPORTANT: this calls "show allprofiles" (no trailing "state"). The "state"
// subverb only emits the ON/OFF column; the "Firewall Policy" line we parse
// for the BlockInbound,BlockOutbound tuple is only printed by the full
// "show allprofiles" form. Earlier versions used "state" and the parser
// always returned "allow" — reconciler then re-applied default-deny every
// tick and audit-logged policy_drift_recovered on a 5-second loop.
func (n *NetshFirewall) GetDefaultOutbound() (string, error) {
	out, err := n.run("advfirewall", "show", "allprofiles")
	if err != nil {
		return "", fmt.Errorf("firewall.GetDefaultOutbound: %w", err)
	}
	return parseDefaultOutbound(string(out)), nil
}

// SetDefaultOutboundBlock applies block-inbound + block-outbound across all profiles.
func (n *NetshFirewall) SetDefaultOutboundBlock() error {
	if _, err := n.run(
		"advfirewall", "set", "allprofiles",
		"firewallpolicy", "blockinboundalways,blockoutbound",
	); err != nil {
		return fmt.Errorf("firewall.SetDefaultOutboundBlock: %w", err)
	}
	return nil
}

// filterIPs validates each entry and ensures it's the expected family.
// Accepts both plain IPs ("1.2.3.4", "::1") and CIDR ranges ("1.2.3.0/24",
// "2001:db8::/32"). netsh advfirewall's `remoteip=` accepts either form, so
// we pass them through unchanged after validation. wantV4=true keeps only
// IPv4 entries; wantV4=false keeps only IPv6.
func filterIPs(entries []string, wantV4 bool) ([]string, error) {
	out := make([]string, 0, len(entries))
	for _, raw := range entries {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		var ip net.IP
		if strings.Contains(raw, "/") {
			parsedIP, _, err := net.ParseCIDR(raw)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %q: %w", raw, err)
			}
			ip = parsedIP
		} else {
			ip = net.ParseIP(raw)
			if ip == nil {
				return nil, fmt.Errorf("invalid IP %q", raw)
			}
		}
		isV4 := ip.To4() != nil
		if wantV4 && !isV4 {
			continue
		}
		if !wantV4 && isV4 {
			continue
		}
		out = append(out, raw)
	}
	return out, nil
}

// isNoMatchErr returns true if the netsh error is the "No rules match" form
// we treat as a successful no-op delete.
func isNoMatchErr(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "no rules match")
}
