package getter

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
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
