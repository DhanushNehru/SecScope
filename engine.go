// Package engine schedules allowlisted assessments within resource limits.
package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

)

// Config tunes one run.
type Config struct {
	Mode       Mode
	ModeReason string
	Ports      []int
	MaxRuntime time.Duration
}

// Engine runs the assessment.
type Engine struct {
	cfg      Config
	sc       *Scope
	spec     Spec
	probes   atomic.Int64
	peakRSS  atomic.Uint64
	throttle atomic.Bool
	pinMu    sync.Mutex
	pins     map[string][]net.IP
}

// New builds an Engine for a validated scope.
func New(cfg Config, sc *Scope, spec Spec) *Engine {
	if len(cfg.Ports) == 0 {
		cfg.Ports = DefaultPorts
	}
	return &Engine{cfg: cfg, sc: sc, spec: spec, pins: map[string][]net.IP{}}
}

// target is one host to work through, sequentially.
type target struct {
	host string
	urls []*url.URL // allowlisted URL entries on this host
}

// Run executes the plan and returns the finished report.
func (e *Engine) Run(ctx context.Context) (*Run, error) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, e.cfg.MaxRuntime)
	defer cancel()
	go e.watchRSS(ctx)

	targets, err := e.plan()
	if err != nil {
		return nil, err
	}
	limiter := time.NewTicker(time.Second / time.Duration(e.cfg.Mode.GlobalRate))
	defer limiter.Stop()

	jobs := make(chan target)
	findings := make(chan []Finding, len(targets))
	var done, skipped atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < e.cfg.Mode.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range jobs {
				ok := e.assess(ctx, t, limiter, findings)
				if ok {
					done.Add(1)
				} else {
					skipped.Add(1)
				}
			}
		}()
	}
	for _, t := range targets {
		select {
		case jobs <- t:
		case <-ctx.Done():
		}
	}
	close(jobs)
	wg.Wait()
	close(findings)

	r := &Run{
		StartedAt: start, FinishedAt: time.Now(),
		Mode: e.cfg.Mode.Name, ModeReason: e.cfg.ModeReason,
		CPUs: e.spec.CPUs, MemoryMB: e.spec.TotalMemMB,
		Scope: e.sc.Describe(), Probes: int(e.probes.Load()),
		PeakRSSMB:   e.peakRSS.Load(),
		TargetsDone: int(done.Load()), TargetsSkip: int(skipped.Load()),
	}
	for fs := range findings {
		r.Findings = append(r.Findings, fs...)
	}
	return r, nil
}

// plan groups the allowlist into per-host targets. Every entry here was
// parsed from the allowlist file, so the plan can never reach beyond it.
func (e *Engine) plan() ([]target, error) {
	byHost := map[string]*target{}
	for _, line := range e.sc.Describe() {
		kind, val, _ := strings.Cut(line, " ")
		switch kind {
		case "host", "ip", "cidr":
			if kind == "cidr" {
				continue // CIDR entries validate resolved IPs; they are not enumerated
			}
			byHost[val] = &target{host: val}
		case "url":
			u, err := url.Parse(val)
			if err != nil {
				return nil, err
			}
			h := strings.ToLower(u.Hostname())
			t, ok := byHost[h]
			if !ok {
				t = &target{host: h}
				byHost[h] = t
			}
			t.urls = append(t.urls, u)
		}
	}
	out := make([]target, 0, len(byHost))
	for _, t := range byHost {
		out = append(out, *t)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("allowlist contains no scannable hosts (CIDR-only scope validates URLs but cannot be enumerated)")
	}
	return out, nil
}

// acquire waits for one probe slot, easing off while memory is high.
func (e *Engine) acquire(ctx context.Context, limiter *time.Ticker) bool {
	select {
	case <-limiter.C:
	case <-ctx.Done():
		return false
	}
	for e.throttle.Load() {
		select {
		case <-time.After(500 * time.Millisecond):
		case <-ctx.Done():
			return false
		}
	}
	e.probes.Add(1)
	return true
}

// assess works one host end to end. A circuit breaker drops the rest of a
// host whose first probes all fail, so dead targets cost almost nothing.
func (e *Engine) assess(ctx context.Context, t target, limiter *time.Ticker, out chan<- []Finding) bool {
	var all []Finding
	var fails int

	open := map[int]bool{}
	for _, p := range e.cfg.Ports {
		if !e.acquire(ctx, limiter) {
			out <- all
			return false
		}
		addr := net.JoinHostPort(t.host, fmt.Sprint(p))
		fs := PortScan(t.host, []int{p}, e.dialer(ctx), e.cfg.Mode.DialTimeout)
		if len(fs) == 0 {
			fails++
			if fails >= 5 && len(all) == 0 {
				out <- all // dead host; stop spending on it
				return false
			}
			continue
		}
		open[p] = true
		_ = addr
		all = append(all, fs...)
	}

	httpBase := func(port int, tls bool) string {
		scheme := "http"
		if tls {
			scheme = "https"
		}
		def := 80
		if tls {
			def = 443
		}
		if port == def {
			return scheme + "://" + t.host
		}
		return fmt.Sprintf("%s://%s:%d", scheme, t.host, port)
	}

	client := e.httpClient()
	do := func(req *http.Request) (*http.Response, error) {
		if !e.acquire(ctx, limiter) {
			return nil, context.DeadlineExceeded
		}
		return client.Do(req)
	}

	webPorts := map[int]bool{80: false, 8080: false, 8000: false, 443: true, 8443: true}
	for _, u := range t.urls {
		port := 80
		isTLS := u.Scheme == "https"
		if isTLS {
			port = 443
		}
		if p := u.Port(); p != "" {
			fmt.Sscan(p, &port)
		}
		// URL entries restrict checks to their path prefix: audit the
		// entry URL and probe sensitive paths beneath it, never the
		// host root.
		base := u.Scheme + "://" + u.Host
		if p := strings.TrimRight(u.EscapedPath(), "/"); p != "" {
			base += p
		}
		if isTLS {
			if !e.acquire(ctx, limiter) {
				break
			}
			all = append(all, TLSAudit(t.host, port, e.dialer(ctx), e.cfg.Mode.DialTimeout)...)
		}
		all = append(all, HeaderAudit(base, do)...)
		all = append(all, ExposureAudit(base, do)...)
		delete(webPorts, port)
	}
	for port, isTLS := range webPorts {
		if !open[port] {
			continue
		}
		if isTLS {
			if !e.acquire(ctx, limiter) {
				break
			}
			all = append(all, TLSAudit(t.host, port, e.dialer(ctx), e.cfg.Mode.DialTimeout)...)
		}
		base := httpBase(port, isTLS)
		all = append(all, HeaderAudit(base, do)...)
	}
	out <- all
	return true
}

// dialer hands checks a DialFunc that only ever dials pinned addresses.
func (e *Engine) dialer(ctx context.Context) DialFunc {
	return func(network, addr string, timeout time.Duration) (net.Conn, error) {
		return e.dialPinned(ctx, network, addr)
	}
}

// resolve pins each host to the addresses it resolved to when first used
// this run. A hostname entry authorizes whatever the name resolves to at
// that moment; every later connection reuses those pinned addresses, so a
// mid-run DNS change cannot move the assessment somewhere else.
func (e *Engine) resolve(ctx context.Context, host string) ([]net.IP, error) {
	e.pinMu.Lock()
	defer e.pinMu.Unlock()
	if ips, ok := e.pins[host]; ok {
		return ips, nil
	}
	if ip := net.ParseIP(host); ip != nil {
		e.pins[host] = []net.IP{ip}
		return e.pins[host], nil
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("cannot resolve %s: %v", host, err)
	}
	e.pins[host] = ips
	return ips, nil
}

// dialPinned connects to one of the host's pinned addresses.
func (e *Engine) dialPinned(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := e.resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	var last error
	for _, ip := range ips {
		d := net.Dialer{Timeout: e.cfg.Mode.DialTimeout}
		c, err := d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return c, nil
		}
		last = err
	}
	return nil, last
}

// httpClient pins redirects to the scope: a redirect to anything outside
// the allowlist is refused and recorded, never followed.
func (e *Engine) httpClient() *http.Client {
	return &http.Client{
		Timeout:   e.cfg.Mode.HTTPTimeout,
		Transport: &http.Transport{DialContext: e.dialPinned},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("too many redirects")
			}
			if !e.sc.AllowsURL(req.URL) {
				return fmt.Errorf("redirect to %s refused: outside allowlist", req.URL.Host)
			}
			return nil
		},
	}
}

// watchRSS samples our own memory and eases off past the mode's soft cap.
func (e *Engine) watchRSS(ctx context.Context) {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			mb := selfRSSMB()
			if mb > e.peakRSS.Load() {
				e.peakRSS.Store(mb)
			}
			e.throttle.Store(e.cfg.Mode.SoftRSSMB > 0 && mb > e.cfg.Mode.SoftRSSMB)
		}
	}
}

func selfRSSMB() uint64 {
	b, err := os.ReadFile("/proc/self/stat")
	if err == nil {
		f := strings.Fields(string(b))
		if len(f) > 23 {
			if pages, perr := strconv.ParseUint(f[23], 10, 64); perr == nil {
				return pages * uint64(os.Getpagesize()) / (1024 * 1024)
			}
		}
	}
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.Sys / (1024 * 1024)
}
