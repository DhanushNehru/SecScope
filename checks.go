// Package checks holds the individual non-destructive assessments.
//
// Every check here is read-only by design: TCP connects, TLS handshakes,
// banner reads and plain HTTP GET/HEAD requests. No payloads, no credential
// attempts, no writes.
package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Finding is one observation about a target.
type Finding struct {
	Target   string `json:"target"`
	Check    string `json:"check"`
	Severity string `json:"severity"` // info, low, medium, high
	Title    string `json:"title"`
	Evidence string `json:"evidence"`
	Fix      string `json:"fix,omitempty"`
}

// DefaultPorts is the small curated set probed per host.
var DefaultPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 587, 993, 995,
	1433, 1521, 2375, 3000, 3306, 3389, 5432, 5900, 6379,
	8000, 8080, 8443, 9000, 9200, 27017,
}

// riskyPorts names services whose exposure deserves a second look.
var riskyPorts = map[int]string{
	23:    "Telnet is unencrypted; confirm it is intentional",
	2375:  "Docker API without TLS; confirm it is not reachable from untrusted networks",
	3306:  "MySQL; confirm exposure is intended",
	5432:  "PostgreSQL; confirm exposure is intended",
	6379:  "Redis; confirm exposure is intended",
	9200:  "Elasticsearch; confirm exposure is intended",
	27017: "MongoDB; confirm exposure is intended",
	3389:  "RDP; confirm exposure is intended",
	5900:  "VNC; confirm exposure is intended",
}

// DialFunc lets tests substitute dialing. It must honor the deadline.
type DialFunc func(network, addr string, timeout time.Duration) (net.Conn, error)

// PortScan connects to each port and reads a short banner where one is
// offered. Open risky-service ports become findings.
func PortScan(target string, ports []int, dial DialFunc, timeout time.Duration) []Finding {
	var out []Finding
	for _, p := range ports {
		addr := net.JoinHostPort(target, fmt.Sprint(p))
		c, err := dial("tcp", addr, timeout)
		if err != nil {
			continue // closed or filtered; not a finding
		}
		banner := readBanner(c)
		c.Close()
		if note, risky := riskyPorts[p]; risky {
			out = append(out, Finding{Target: addr, Check: "ports", Severity: "medium",
				Title: fmt.Sprintf("port %d open: %s", p, note), Evidence: banner})
		} else {
			title := fmt.Sprintf("port %d open", p)
			out = append(out, Finding{Target: addr, Check: "ports", Severity: "info", Title: title, Evidence: banner})
		}
	}
	return out
}

func readBanner(c net.Conn) string {
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 256)
	n, err := c.Read(buf)
	if err != nil || n == 0 {
		return ""
	}
	return strings.TrimSpace(string(buf[:n]))
}

// TLSAudit handshakes and reports certificate and protocol problems.
// Verification is disabled on purpose: secscope records certificate facts
// instead of trusting chains, and self-signed certs are common in scope.
func TLSAudit(target string, port int, dial DialFunc, timeout time.Duration) []Finding {
	addr := net.JoinHostPort(target, fmt.Sprint(port))
	raw, err := dial("tcp", addr, timeout)
	if err != nil {
		return nil // no TLS service here; not a finding
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(timeout))
	tc := tls.Client(raw, &tls.Config{ServerName: target, MinVersion: tls.VersionTLS10, InsecureSkipVerify: true}) // audit, not authenticate
	if err := tc.Handshake(); err != nil {
		return nil
	}
	st := tc.ConnectionState()
	var out []Finding
	if st.Version < tls.VersionTLS12 {
		out = append(out, Finding{Target: addr, Check: "tls", Severity: "medium",
			Title: "TLS version below 1.2 negotiated", Evidence: tls.VersionName(st.Version)})
	}
	for _, cert := range st.PeerCertificates {
		days := int(time.Until(cert.NotAfter).Hours() / 24)
		switch {
		case days < 0:
			out = append(out, Finding{Target: addr, Check: "tls", Severity: "high",
				Title: "certificate expired", Evidence: cert.Subject.CommonName + " expired " + cert.NotAfter.Format("2006-01-02")})
		case days < 30:
			out = append(out, Finding{Target: addr, Check: "tls", Severity: "low",
				Title: fmt.Sprintf("certificate expires in %d days", days), Evidence: cert.Subject.CommonName})
		}
		break // leaf only
	}
	return out
}

// HTTPDoer lets tests substitute the HTTP client.
type HTTPDoer func(req *http.Request) (*http.Response, error)

// securityHeaders maps a header to the severity of its absence.
var securityHeaders = []struct {
	name, severity string
}{
	{"Content-Security-Policy", "medium"},
	{"Strict-Transport-Security", "medium"},
	{"X-Content-Type-Options", "low"},
	{"X-Frame-Options", "low"},
	{"Referrer-Policy", "info"},
	{"Permissions-Policy", "info"},
}

// ExposedPaths are fetched with plain GETs and matched loosely.
var ExposedPaths = []struct {
	path, severity, title string
}{
	{"/.git/HEAD", "high", "git metadata exposed"},
	{"/.env", "high", "environment file exposed"},
	{"/server-status", "medium", "server status page exposed"},
	{"/.well-known/security.txt", "info", "no security.txt published (informational)"},
}

// HeaderAudit fetches baseURL and reviews response headers and cookies.
// baseURL must already be allowlist-verified by the caller.
func HeaderAudit(baseURL string, do HTTPDoer) []Finding {
	req, err := http.NewRequest(http.MethodGet, baseURL, nil)
	if err != nil {
		return nil
	}
	resp, err := do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))

	var out []Finding
	isHTTPS := strings.HasPrefix(baseURL, "https://")
	for _, h := range securityHeaders {
		if h.name == "Strict-Transport-Security" && !isHTTPS {
			continue // only meaningful over HTTPS
		}
		if resp.Header.Get(h.name) == "" {
			out = append(out, Finding{Target: baseURL, Check: "headers", Severity: h.severity,
				Title: "missing header " + h.name, Evidence: "GET " + baseURL})
		}
	}
	for _, c := range resp.Header.Values("Set-Cookie") {
		lc := strings.ToLower(c)
		name := strings.SplitN(strings.TrimSpace(c), "=", 2)[0]
		if !strings.Contains(lc, "httponly") {
			out = append(out, Finding{Target: baseURL, Check: "cookies", Severity: "low",
				Title: "cookie without HttpOnly", Evidence: name})
		}
		if isHTTPS && !strings.Contains(lc, "secure") {
			out = append(out, Finding{Target: baseURL, Check: "cookies", Severity: "low",
				Title: "cookie without Secure flag", Evidence: name})
		}
		if !strings.Contains(lc, "samesite") {
			out = append(out, Finding{Target: baseURL, Check: "cookies", Severity: "info",
				Title: "cookie without SameSite", Evidence: name})
		}
	}
	if srv := resp.Header.Get("Server"); srv != "" {
		out = append(out, Finding{Target: baseURL, Check: "headers", Severity: "info",
			Title: "server banner disclosed", Evidence: srv})
	}
	return out
}

// ExposureAudit GETs each known sensitive path under baseURL and records
// the ones that answer like real content.
func ExposureAudit(baseURL string, do HTTPDoer) []Finding {
	var out []Finding
	for _, ep := range ExposedPaths {
		u := strings.TrimRight(baseURL, "/") + ep.path
		req, err := http.NewRequest(http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		resp, err := do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		resp.Body.Close()
		if ep.path == "/.well-known/security.txt" {
			if resp.StatusCode == 404 {
				out = append(out, Finding{Target: u, Check: "exposure", Severity: "info",
					Title: ep.title, Evidence: "HTTP 404"})
			}
			continue
		}
		if resp.StatusCode == 200 && looksReal(ep.path, body) {
			out = append(out, Finding{Target: u, Check: "exposure", Severity: ep.severity,
				Title: ep.title, Evidence: fmt.Sprintf("HTTP 200, %d bytes", len(body))})
		}
	}
	return out
}

func looksReal(path string, body []byte) bool {
	s := string(body)
	switch path {
	case "/.git/HEAD":
		return strings.HasPrefix(s, "ref:") || len(strings.TrimSpace(s)) == 40
	case "/.env":
		return strings.Contains(s, "=")
	}
	return len(body) > 0
}
