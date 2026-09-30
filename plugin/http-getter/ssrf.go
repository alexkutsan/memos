package getter

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// isDisallowedIP reports whether the given IP address should not be reachable
// from a server-side request (loopback, private, link-local, multicast, or
// otherwise non-public addresses). This mitigates SSRF attacks that target
// internal infrastructure (e.g. cloud metadata endpoints, internal services).
func isDisallowedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}
	// Explicitly reject the common cloud metadata address.
	if ip.Equal(net.IPv4(169, 254, 169, 254)) {
		return true
	}
	return false
}

// allowedHosts returns the set of host suffixes that outbound requests are
// permitted to target. It is sourced from the HTTP_GETTER_ALLOWED_HOSTS
// environment variable (a comma-separated list of hostnames or domain
// suffixes, e.g. "example.com,cdn.example.org"). When the variable is empty
// the allowlist is considered unconfigured.
func allowedHosts() []string {
	raw := strings.TrimSpace(os.Getenv("HTTP_GETTER_ALLOWED_HOSTS"))
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	hosts := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(strings.ToLower(p))
		if p != "" {
			hosts = append(hosts, p)
		}
	}
	return hosts
}

// isAllowedHost reports whether the given host is permitted by the configured
// allowlist. A host matches if it equals an allowlist entry exactly, or is a
// subdomain of an allowlist entry. When no allowlist is configured, all hosts
// are rejected: fetching metadata/images is an explicitly opt-in feature, so
// the safe default is to deny arbitrary outbound requests (blind SSRF).
func isAllowedHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, allowed := range allowedHosts() {
		if host == allowed || strings.HasSuffix(host, "."+allowed) {
			return true
		}
	}
	return false
}

// validateOutboundURL performs syntax and destination validation on a
// user-supplied URL before it is used to make a server-side HTTP request.
// It restricts the scheme to http/https, rejects credentials in the URL,
// resolves the hostname, and rejects any resolved address that points to a
// loopback/private/link-local/metadata address, in order to prevent SSRF.
func validateOutboundURL(urlStr string) (*url.URL, error) {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, errors.New("only http and https URLs are allowed")
	}
	if parsed.User != nil {
		return nil, errors.New("URLs with embedded credentials are not allowed")
	}
	host := parsed.Hostname()
	if host == "" {
		return nil, errors.New("URL is missing a host")
	}
	if strings.EqualFold(host, "localhost") {
		return nil, errors.New("requests to localhost are not allowed")
	}
	if !isAllowedHost(host) {
		return nil, errors.New("host is not on the outbound request allowlist")
	}

	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve host: %w", err)
	}
	if len(ips) == 0 {
		return nil, errors.New("host did not resolve to any address")
	}
	for _, ip := range ips {
		if isDisallowedIP(ip) {
			return nil, errors.New("requests to internal or private network addresses are not allowed")
		}
	}

	return parsed, nil
}

// safeHTTPClient returns an http.Client configured to defend against SSRF:
// it enforces a request timeout, limits/validates redirects, and re-validates
// the destination address at dial time to avoid TOCTOU/DNS-rebinding bypass
// of the hostname-based checks performed above.
func safeHTTPClient() *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second}

	safeDialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		ips, err := net.LookupIP(host)
		if err != nil {
			return nil, err
		}
		for _, ip := range ips {
			if isDisallowedIP(ip) {
				return nil, fmt.Errorf("connections to %s are not allowed", ip.String())
			}
		}
		return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
	}

	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: safeDialContext,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("too many redirects")
			}
			if _, err := validateOutboundURL(req.URL.String()); err != nil {
				return fmt.Errorf("redirect target not allowed: %w", err)
			}
			return nil
		},
	}
}
