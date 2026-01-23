package main

import (
	"net"
	"strings"

	"github.com/ops/defender/pkg/extensions"
)

// AllowlistExtension provides IP-based allowlisting with support for:
// - Individual IPv4/IPv6 addresses (e.g., "192.168.1.1", "2001:db8::1")
// - CIDR ranges (e.g., "10.0.0.0/8", "66.249.64.0/19")
type AllowlistExtension struct {
	allowedIPs     map[string]bool // Individual IPs
	allowedRanges  []*net.IPNet    // CIDR ranges
}

// NewAllowlistExtension creates a new allowlist extension from a list of IPs and CIDR ranges
func NewAllowlistExtension(ips []string) *AllowlistExtension {
	ext := &AllowlistExtension{
		allowedIPs:    make(map[string]bool),
		allowedRanges: make([]*net.IPNet, 0),
	}

	for _, ipStr := range ips {
		ipStr = strings.TrimSpace(ipStr)
		if ipStr == "" {
			continue
		}

		// Check if it's a CIDR range
		if strings.Contains(ipStr, "/") {
			_, ipNet, err := net.ParseCIDR(ipStr)
			if err == nil {
				ext.allowedRanges = append(ext.allowedRanges, ipNet)
			}
		} else {
			// Individual IP address
			ext.allowedIPs[ipStr] = true
		}
	}

	return ext
}

// Name returns the extension identifier
func (e *AllowlistExtension) Name() string {
	return "ip-allowlist"
}

// PreHandleRequest checks if the request IP is on the allowlist
func (e *AllowlistExtension) PreHandleRequest(req extensions.RequestInfo) (extensions.PreHandlerResult, error) {
	// Check individual IPs first (fastest)
	if e.allowedIPs[req.IP] {
		return extensions.PreHandlerResult{
			ShouldBypass: true,
			Reason:       "IP in allowlist",
		}, nil
	}

	// Check CIDR ranges
	ip := net.ParseIP(req.IP)
	if ip != nil {
		for _, ipNet := range e.allowedRanges {
			if ipNet.Contains(ip) {
				return extensions.PreHandlerResult{
					ShouldBypass: true,
					Reason:       "IP in allowlist range",
				}, nil
			}
		}
	}

	// Not in allowlist - continue normal processing
	return extensions.PreHandlerResult{ShouldBypass: false}, nil
}
