// Package oauth2 is the plugin for OAuth2 Identity Provider.
package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/oauth2"

	"github.com/usememos/memos/plugin/idp"
	"github.com/usememos/memos/store"
)

// IdentityProvider represents an OAuth2 Identity Provider.
type IdentityProvider struct {
	config *store.IdentityProviderOAuth2Config
}

// NewIdentityProvider initializes a new OAuth2 Identity Provider with the given configuration.
func NewIdentityProvider(config *store.IdentityProviderOAuth2Config) (*IdentityProvider, error) {
	for v, field := range map[string]string{
		config.ClientID:                "clientId",
		config.ClientSecret:            "clientSecret",
		config.TokenURL:                "tokenUrl",
		config.UserInfoURL:             "userInfoUrl",
		config.FieldMapping.Identifier: "fieldMapping.identifier",
	} {
		if v == "" {
			return nil, errors.Errorf(`the field "%s" is empty but required`, field)
		}
	}

	// Validate that the configured endpoints are well-formed, use an allowed
	// scheme, and do not point at internal/private network resources. This
	// mitigates Server-Side Request Forgery (SSRF) via attacker-controlled
	// or misconfigured identity provider URLs.
	for _, u := range []string{config.AuthURL, config.TokenURL, config.UserInfoURL} {
		if u == "" {
			continue
		}
		if err := validatePublicURL(u); err != nil {
			return nil, errors.Wrapf(err, "invalid identity provider URL %q", u)
		}
	}

	return &IdentityProvider{
		config: config,
	}, nil
}

// validatePublicURL ensures the given URL uses an allowed scheme and resolves
// to a public, non-internal IP address. It is used to guard against SSRF
// attacks where a user-controllable URL is used to make server-side requests.
func validatePublicURL(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return errors.Wrap(err, "failed to parse URL")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return errors.Errorf("unsupported URL scheme %q, only http/https are allowed", parsed.Scheme)
	}
	host := parsed.Hostname()
	if host == "" {
		return errors.New("URL is missing a host")
	}
	if strings.EqualFold(host, "localhost") {
		return errors.New("requests to localhost are not allowed")
	}

	// Enforce an allowlist of permitted identity provider hosts/domains. This
	// is the primary SSRF control: only explicitly trusted hosts may be the
	// target of server-side requests. The blocklist below (isDisallowedIP) is
	// retained purely as defense-in-depth. Fail closed when no host is
	// allowed so that an attacker-controlled public host can never be reached.
	if !isAllowedHost(host) {
		return errors.Errorf("host %q is not in the allowlist of permitted identity provider hosts", host)
	}

	ips, err := net.LookupIP(host)
	if err != nil {
		return errors.Wrap(err, "failed to resolve host")
	}
	if len(ips) == 0 {
		return errors.New("host did not resolve to any IP address")
	}
	for _, ip := range ips {
		if isDisallowedIP(ip) {
			return errors.Errorf("host %q resolves to a disallowed internal/private IP address", host)
		}
	}
	return nil
}

// allowedHosts returns the configured allowlist of permitted identity provider
// hosts. It is sourced from the MEMOS_OAUTH2_ALLOWED_HOSTS environment
// variable, a comma-separated list of exact hostnames and/or trusted parent
// domains (e.g. "accounts.google.com,login.example.com,.okta.com"). When the
// variable is unset or empty the allowlist is empty, which causes
// validatePublicURL to reject every host (fail closed).
func allowedHosts() []string {
	raw := os.Getenv("MEMOS_OAUTH2_ALLOWED_HOSTS")
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	hosts := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			hosts = append(hosts, strings.ToLower(p))
		}
	}
	return hosts
}

// isAllowedHost reports whether the given host matches the configured
// allowlist. A list entry starting with "." (e.g. ".example.com") matches the
// domain itself and any of its subdomains; any other entry must match exactly.
func isAllowedHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, allowed := range allowedHosts() {
		if strings.HasPrefix(allowed, ".") {
			domain := strings.TrimPrefix(allowed, ".")
			if host == domain || strings.HasSuffix(host, "."+domain) {
				return true
			}
			continue
		}
		if host == allowed {
			return true
		}
	}
	return false
}

// isDisallowedIP reports whether the given IP address is a loopback,
// private, link-local, unspecified, or otherwise internal/reserved address
// (including common cloud metadata endpoints) that should not be reachable
// via server-side requests.
func isDisallowedIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}
	// Cloud metadata service address (AWS/GCP/Azure/etc.).
	if ip.Equal(net.IPv4(169, 254, 169, 254)) {
		return true
	}
	return false
}

// ExchangeToken returns the exchanged OAuth2 token using the given authorization code.
func (p *IdentityProvider) ExchangeToken(ctx context.Context, redirectURL, code string) (string, error) {
	conf := &oauth2.Config{
		ClientID:     p.config.ClientID,
		ClientSecret: p.config.ClientSecret,
		RedirectURL:  redirectURL,
		Scopes:       p.config.Scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:   p.config.AuthURL,
			TokenURL:  p.config.TokenURL,
			AuthStyle: oauth2.AuthStyleInParams,
		},
	}

	token, err := conf.Exchange(ctx, code)
	if err != nil {
		return "", errors.Wrap(err, "failed to exchange access token")
	}

	accessToken, ok := token.Extra("access_token").(string)
	if !ok {
		return "", errors.New(`missing "access_token" from authorization response`)
	}

	return accessToken, nil
}

// UserInfo returns the parsed user information using the given OAuth2 token.
func (p *IdentityProvider) UserInfo(token string) (*idp.IdentityProviderUserInfo, error) {
	// Re-validate the URL at request time to defend against DNS rebinding /
	// TOCTOU attacks where the host resolves to an internal address only
	// after the initial configuration validation.
	if err := validatePublicURL(p.config.UserInfoURL); err != nil {
		return nil, errors.Wrap(err, "refusing to request user info")
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			if err := validatePublicURL(req.URL.String()); err != nil {
				return errors.Wrap(err, "refusing to follow redirect")
			}
			return nil
		},
	}
	req, err := http.NewRequest(http.MethodGet, p.config.UserInfoURL, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to new http request")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get user information")
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read response body")
	}
	defer resp.Body.Close()

	var claims map[string]any
	err = json.Unmarshal(body, &claims)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal response body")
	}

	userInfo := &idp.IdentityProviderUserInfo{}
	if v, ok := claims[p.config.FieldMapping.Identifier].(string); ok {
		userInfo.Identifier = v
	}
	if userInfo.Identifier == "" {
		return nil, errors.Errorf("the field %q is not found in claims or has empty value", p.config.FieldMapping.Identifier)
	}

	// Best effort to map optional fields
	if p.config.FieldMapping.DisplayName != "" {
		if v, ok := claims[p.config.FieldMapping.DisplayName].(string); ok {
			userInfo.DisplayName = v
		}
	}
	if userInfo.DisplayName == "" {
		userInfo.DisplayName = userInfo.Identifier
	}
	if p.config.FieldMapping.Email != "" {
		if v, ok := claims[p.config.FieldMapping.Email].(string); ok {
			userInfo.Email = v
		}
	}
	return userInfo, nil
}
