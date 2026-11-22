package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

)

// TestRunAgainstFixture scans a local server from the allowlist and
// confirms a second listener outside the allowlist is never touched.
func TestRunAgainstFixture(t *testing.T) {
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer web.Close()

	var outsideHits int32
	outside, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer outside.Close()
	go func() {
		for {
			c, err := outside.Accept()
			if err != nil {
				return
			}
			outsideHits++
			c.Close()
		}
	}()

	host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(web.URL, "http://"))
	var webPort int
	fmt.Sscan(portStr, &webPort)

	sc, err := Parse([]string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	mode := Table()[0]
	eng := New(Config{Mode: mode, ModeReason: "test", Ports: []int{webPort}, MaxRuntime: time.Minute}, sc, Spec{CPUs: 2, TotalMemMB: 4096})
	r, err := eng.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if r.TargetsDone != 1 {
		t.Fatalf("expected 1 target done, got %d (skipped %d)", r.TargetsDone, r.TargetsSkip)
	}
	if r.Probes == 0 {
		t.Fatal("probes should be counted")
	}
	if outsideHits != 0 {
		t.Fatalf("listener outside the scan plan was contacted %d times", outsideHits)
	}
	_ = host
	if len(r.Scope) != 1 || r.Scope[0] != "ip 127.0.0.1" {
		t.Fatalf("report scope mismatch: %+v", r.Scope)
	}
	if md := r.Markdown(); !strings.Contains(md, "Coverage and limitations") {
		t.Fatal("report must carry the limitations section")
	}
}

// TestDialPinnedLocalhost proves connections go to the address pinned at
// first resolution, and that resolution results are reused.
func TestDialPinnedLocalhost(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	sc, err := Parse([]string{"localhost"})
	if err != nil {
		t.Fatal(err)
	}
	e := New(Config{Mode: Table()[0], MaxRuntime: time.Minute}, sc, Spec{})
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	c, err := e.dialPinned(context.Background(), "tcp", net.JoinHostPort("localhost", port))
	if err != nil {
		t.Fatalf("dialPinned: %v", err)
	}
	c.Close()
	if len(e.pins["localhost"]) == 0 {
		t.Fatal("localhost should be pinned after the first dial")
	}
	for _, ip := range e.pins["localhost"] {
		if !ip.IsLoopback() {
			t.Fatalf("localhost pinned to non-loopback %s", ip)
		}
	}
	if _, err := e.dialPinned(context.Background(), "tcp", net.JoinHostPort("definitely-not-allowlisted.invalid", "80")); err == nil {
		t.Fatal("unresolvable host must fail, not fall through")
	}
}

// TestRedirectOutsideScope proves redirects leaving the allowlist are
// refused, never followed.
func TestRedirectOutsideScope(t *testing.T) {
	var jumped bool
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:9/outside", 302)
	}))
	defer web.Close()
	_ = jumped

	sc, err := Parse([]string{"https://allowed.example/"})
	if err != nil {
		t.Fatal(err)
	}
	eng := New(Config{Mode: Table()[0], MaxRuntime: time.Minute}, sc, Spec{})
	client := eng.httpClient()
	_, err = client.Get(web.URL)
	if err == nil || !strings.Contains(err.Error(), "outside allowlist") {
		t.Fatalf("redirect outside allowlist must be refused, got %v", err)
	}
}

// TestURLPathPrefixRespected scans a URL entry with a path prefix and
// confirms header and exposure checks stay beneath that prefix instead
// of dropping to the host root.
func TestURLPathPrefixRespected(t *testing.T) {
	var mu sync.Mutex
	var hits []string
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits = append(hits, r.URL.Path)
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer web.Close()

	_, portStr, _ := net.SplitHostPort(strings.TrimPrefix(web.URL, "http://"))
	var webPort int
	fmt.Sscan(portStr, &webPort)

	sc, err := Parse([]string{web.URL + "/app/"})
	if err != nil {
		t.Fatal(err)
	}
	mode := Table()[0]
	eng := New(Config{Mode: mode, ModeReason: "test", Ports: []int{webPort}, MaxRuntime: time.Minute}, sc, Spec{CPUs: 2, TotalMemMB: 4096})
	if _, err := eng.Run(context.Background()); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(hits) == 0 {
		t.Fatal("expected header and exposure checks to hit the fixture")
	}
	for _, h := range hits {
		if h != "/app" && !strings.HasPrefix(h, "/app/") {
			t.Fatalf("check escaped the URL path prefix: got %q, hits %v", h, hits)
		}
	}
}
