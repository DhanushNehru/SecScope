// Package scope parses and enforces the explicit target allowlist.
//
// The allowlist is the contract between the operator and secscope: only
// hosts, addresses, ranges and URLs written in that file are ever touched.
package main

import (
	"bufio"
	"fmt"
	"net"
	"net/url"
	"os"
	"sort"
	"strings"
)

// Scope is the set of targets the operator has authorized.
type Scope struct {
	hosts    map[string]bool     // bare hostnames: every port and path allowed
	ipvals   map[string]bool     // exact IP addresses
	nets     []*net.IPNet        // CIDR ranges
	urlents  []*url.URL          // URL entries, kept verbatim for planning
	prefixes map[string][]string // host -> path prefixes from URL entries
}

// ParseFile reads an allowlist file. One entry per line; blank lines and
// lines starting with '#' are ignored.
func ParseFile(path string) (*Scope, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return Parse(lines)
}

// Parse builds a Scope from raw allowlist lines.
func Parse(lines []string) (*Scope, error) {
	s := &Scope{
		hosts:    map[string]bool{},
		ipvals:   map[string]bool{},
		prefixes: map[string][]string{},
	}
	for i, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if err := s.add(line); err != nil {
			return nil, fmt.Errorf("allowlist line %d: %w", i+1, err)
		}
	}
	if s.Empty() {
		return nil, fmt.Errorf("allowlist has no entries; secscope only runs against an explicit allowlist")
	}
	return s, nil
}

func (s *Scope) add(line string) error {
	if strings.Contains(line, "://") {
		u, err := url.Parse(line)
		if err != nil {
			return err
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return fmt.Errorf("unsupported scheme %q (http and https only)", u.Scheme)
		}
		host := strings.ToLower(u.Hostname())
		if host == "" {
			return fmt.Errorf("URL %q has no host", line)
		}
		s.urlents = append(s.urlents, u)
		p := u.EscapedPath()
		if p == "" {
			p = "/"
		}
		s.prefixes[host] = append(s.prefixes[host], p)
		return nil
	}
	if _, n, err := net.ParseCIDR(line); err == nil {
		s.nets = append(s.nets, n)
		return nil
	}
	if ip := net.ParseIP(line); ip != nil {
		s.ipvals[ip.String()] = true
		return nil
	}
	if strings.ContainsAny(line, " /	\\") {
		return fmt.Errorf("cannot understand entry %q", line)
	}
	s.hosts[strings.ToLower(line)] = true
	return nil
}

// Empty reports whether the scope has no entries at all.
func (s *Scope) Empty() bool {
	return len(s.hosts) == 0 && len(s.ipvals) == 0 && len(s.nets) == 0 && len(s.urlents) == 0
}

// AllowsHost reports whether a hostname or IP string is inside the scope.
func (s *Scope) AllowsHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if s.hosts[host] || s.ipvals[host] || len(s.prefixes[host]) > 0 {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return s.AllowsIP(ip)
	}
	return false
}

// AllowsIP reports whether a resolved address is inside the scope.
func (s *Scope) AllowsIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if s.ipvals[ip.String()] {
		return true
	}
	for _, n := range s.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// AllowsURL reports whether every part of u stays inside the scope:
// the host must be allowed and, when URL entries exist for that host,
// the path must sit under one of the allowed prefixes.
func (s *Scope) AllowsURL(u *url.URL) bool {
	host := strings.ToLower(u.Hostname())
	if !s.AllowsHost(host) {
		return false
	}
	prefs, hasPrefs := s.prefixes[host]
	if s.hosts[host] && !hasPrefs {
		return true
	}
	if !hasPrefs {
		// Host allowed only via IP/CIDR entry: path is unrestricted.
		return true
	}
	p := u.EscapedPath()
	if p == "" {
		p = "/"
	}
	for _, pref := range prefs {
		base := strings.TrimSuffix(pref, "/")
		if p == pref || p == base || strings.HasPrefix(p, base+"/") {
			return true
		}
	}
	return false
}

// URLEntries returns the verbatim URL entries from the allowlist.
func (s *Scope) URLEntries() []*url.URL {
	out := make([]*url.URL, len(s.urlents))
	copy(out, s.urlents)
	return out
}

// Describe returns one sorted line per entry, for reports and dry runs.
func (s *Scope) Describe() []string {
	var out []string
	for h := range s.hosts {
		out = append(out, "host "+h)
	}
	for ip := range s.ipvals {
		out = append(out, "ip "+ip)
	}
	for _, n := range s.nets {
		out = append(out, "cidr "+n.String())
	}
	for _, u := range s.urlents {
		out = append(out, "url "+u.String())
	}
	sort.Strings(out)
	return out
}
