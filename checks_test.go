package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPortScanFindsListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	fs := PortScan("127.0.0.1", []int{port}, net.DialTimeout, 2*time.Second)
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
	if fs[0].Check != "ports" {
		t.Fatalf("unexpected check %q", fs[0].Check)
	}

	closed := PortScan("127.0.0.1", []int{port + 1}, net.DialTimeout, 500*time.Millisecond)
	if len(closed) != 0 {
		t.Fatalf("closed port should not be a finding, got %+v", closed)
	}
}

func TestRiskyPortSeverity(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	fs := PortScan("127.0.0.1", []int{23}, func(network, addr string, timeout time.Duration) (net.Conn, error) {
		return net.DialTimeout(network, ln.Addr().String(), timeout)
	}, time.Second)
	if len(fs) != 1 || fs[0].Severity != "medium" {
		t.Fatalf("telnet port should be a medium finding, got %+v", fs)
	}
}

func TestHeaderAuditMissingHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "sid=abc")
		w.WriteHeader(200)
	}))
	defer srv.Close()
	fs := HeaderAudit(srv.URL, http.DefaultClient.Do)
	var csp, cookie bool
	for _, f := range fs {
		if strings.Contains(f.Title, "Content-Security-Policy") {
			csp = true
		}
		if f.Check == "cookies" && strings.Contains(f.Title, "HttpOnly") {
			cookie = true
		}
	}
	if !csp {
		t.Fatal("missing CSP should be flagged")
	}
	if !cookie {
		t.Fatal("cookie without HttpOnly should be flagged")
	}
	for _, f := range fs {
		if f.Title == "missing header Strict-Transport-Security" {
			t.Fatal("HSTS must not be required over plain http")
		}
	}
}

func TestHeaderAuditCleanServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=()")
		w.WriteHeader(200)
	}))
	defer srv.Close()
	fs := HeaderAudit(srv.URL, http.DefaultClient.Do)
	for _, f := range fs {
		if f.Severity == "medium" || f.Severity == "low" {
			t.Fatalf("well-configured server should have no medium/low finding, got %+v", f)
		}
	}
}

func TestExposureAuditGitHead(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.git/HEAD" {
			w.Write([]byte("ref: refs/heads/main\n"))
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()
	fs := ExposureAudit(srv.URL, http.DefaultClient.Do)
	var git, secTxt bool
	for _, f := range fs {
		if f.Title == "git metadata exposed" && f.Severity == "high" {
			git = true
		}
		if strings.Contains(f.Title, "security.txt") {
			secTxt = true
		}
	}
	if !git {
		t.Fatal("exposed .git/HEAD should be a high finding")
	}
	if !secTxt {
		t.Fatal("missing security.txt should be recorded as informational")
	}
}

func TestTLSAuditSelfSigned(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "https://")
	host, port, _ := net.SplitHostPort(addr)
	var p int
	for _, c := range port {
		p = p*10 + int(c-'0')
	}
	// Must not error or report expiry for a fresh test cert; TLS version
	// depends on the test server and is 1.2+ in modern Go.
	fs := TLSAudit(host, p, net.DialTimeout, 3*time.Second)
	for _, f := range fs {
		if f.Severity == "high" {
			t.Fatalf("unexpected high finding on fresh test cert: %+v", f)
		}
	}
}
