package main

import (
	"net"
	"net/url"
	"testing"
)

func mustParse(t *testing.T, lines []string) *Scope {
	t.Helper()
	s, err := Parse(lines)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return s
}

func TestEmptyRefused(t *testing.T) {
	if _, err := Parse([]string{"# only comments", ""}); err == nil {
		t.Fatal("empty allowlist must be refused")
	}
}

func TestHostAndCIDR(t *testing.T) {
	s := mustParse(t, []string{"example.com", "10.0.0.0/24", "192.0.2.7"})
	if !s.AllowsHost("example.com") {
		t.Fatal("example.com should be allowed")
	}
	if !s.AllowsIP(net.ParseIP("10.0.0.44")) {
		t.Fatal("10.0.0.44 should be allowed via CIDR")
	}
	if s.AllowsIP(net.ParseIP("10.0.1.44")) {
		t.Fatal("10.0.1.44 is outside the CIDR")
	}
	if !s.AllowsHost("192.0.2.7") {
		t.Fatal("exact IP should be allowed")
	}
	if s.AllowsHost("evil.example") {
		t.Fatal("unlisted host must not be allowed")
	}
}

func TestURLPathPrefix(t *testing.T) {
	s := mustParse(t, []string{"https://example.com/app/"})
	ok, _ := url.Parse("https://example.com/app/login")
	if !s.AllowsURL(ok) {
		t.Fatal("path under the prefix should be allowed")
	}
	outside, _ := url.Parse("https://example.com/admin")
	if s.AllowsURL(outside) {
		t.Fatal("path outside the prefix must be refused")
	}
	other, _ := url.Parse("https://other.example/app/")
	if s.AllowsURL(other) {
		t.Fatal("other host must be refused")
	}
}

func TestBareHostAllowsAnyPath(t *testing.T) {
	s := mustParse(t, []string{"example.com"})
	u, _ := url.Parse("https://example.com/anything/here")
	if !s.AllowsURL(u) {
		t.Fatal("bare host entry should allow every path")
	}
}

func TestBadEntries(t *testing.T) {
	if _, err := Parse([]string{"gopher://x/"}); err == nil {
		t.Fatal("non-http scheme must be rejected")
	}
	if _, err := Parse([]string{"not a host!!"}); err == nil {
		t.Fatal("garbage entry must be rejected")
	}
}
