package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSessionSaveLoadAndReset(t *testing.T) {
	dir := t.TempDir()
	s := NewSession("low", []string{"ip 127.0.0.1"})
	s.mark("scope", stageDone, "1 allowlist entries")
	s.mark("recon", stageRunning, "")
	if err := s.Save(dir); err != nil {
		t.Fatal(err)
	}
	back, err := LoadSession(dir)
	if err != nil {
		t.Fatal(err)
	}
	if back.ID != s.ID || back.Mode != "low" {
		t.Fatalf("session identity lost: %+v", back)
	}
	if back.Stages["scope"].Status != stageDone {
		t.Fatal("done stage should survive the round trip")
	}
	if back.Stages["recon"].Status != stagePending {
		t.Fatalf("interrupted stage should reset to pending, got %s", back.Stages["recon"].Status)
	}
	if !back.needsRun("recon") || back.needsRun("scope") {
		t.Fatal("needsRun disagrees with stage states")
	}
}

func TestSameScope(t *testing.T) {
	if !sameScope([]string{"ip 127.0.0.1"}, []string{"ip 127.0.0.1"}) {
		t.Fatal("identical scopes should match")
	}
	if sameScope([]string{"ip 127.0.0.1"}, []string{"ip 127.0.0.2"}) {
		t.Fatal("different scopes must not match")
	}
}

func TestBuildTasksRulesAndDedup(t *testing.T) {
	findings := []Finding{
		{Target: "h:6379", Check: "ports", Severity: "medium", Title: "port 6379 open: Redis"},
		{Target: "h:6379", Check: "ports", Severity: "medium", Title: "port 6379 open: Redis"}, // dup
		{Target: "h:80", Check: "ports", Severity: "info", Title: "port 80 open"},
		{Target: "http://h/.env", Check: "exposure", Severity: "high", Title: "environment file exposed"},
		{Target: "http://h/", Check: "headers", Severity: "low", Title: "missing header X-Frame-Options"},
		{Target: "h:443", Check: "tls", Severity: "high", Title: "certificate expired"},
		{Target: "http://h/", Check: "fingerprint", Severity: "high", Title: "Apache httpd 2.4.49 path traversal and RCE"},
	}
	tasks := buildTasks(findings)
	kinds := map[string]string{}
	for _, task := range tasks {
		kinds[task.Kind+"|"+task.Target] = task.ID
	}
	if len(tasks) != 4 {
		t.Fatalf("expected 4 deduped tasks, got %d: %+v", len(tasks), tasks)
	}
	for _, want := range []string{"confirm-port|h:6379", "confirm-exposure|http://h/.env", "review|h:443", "review|http://h/"} {
		if kinds[want] == "" {
			t.Fatalf("missing task %s in %+v", want, tasks)
		}
	}
	if open := openTasks(tasks); len(open) != 4 {
		t.Fatalf("all tasks should start open, got %d", len(open))
	}
}

func TestFingerprintMatching(t *testing.T) {
	cases := []struct {
		banner  string
		wantID  string
		wantSev string
	}{
		{"SSH-2.0-OpenSSH_7.4p1 Debian", "CVE-2018-15473", "medium"},
		{"SSH-2.0-OpenSSH_8.9p1 Ubuntu", "", ""},
		{"Apache/2.4.49 (Unix)", "CVE-2021-41773", "high"},
		{"Apache/2.4.50 (Unix)", "CVE-2021-42013", "high"},
		{"Apache/2.4.62 (Unix)", "", ""},
		{"vsftpd 2.3.4", "CVE-2011-2523", "high"},
		{"220 ProFTPD 1.3.5 Server ready", "CVE-2015-3306", "high"},
		{"Microsoft-IIS/6.0", "CVE-2017-7269", "high"},
		{"220 mail Exim 4.90_1", "CVE-2019-10149", "high"},
		{"220 mail Exim 4.96", "", ""},
		{"X-Powered-By: PHP/5.6.40", "EOL-PHP5", "low"},
		{"nginx/1.25.4", "", ""},
	}
	for _, c := range cases {
		got := matchFingerprints(c.banner)
		if c.wantID == "" {
			if len(got) != 0 {
				t.Fatalf("%q: expected no match, got %+v", c.banner, got)
			}
			continue
		}
		if len(got) != 1 || got[0].id != c.wantID || got[0].severity != c.wantSev {
			t.Fatalf("%q: want %s/%s, got %+v", c.banner, c.wantID, c.wantSev, got)
		}
	}
}

func TestAnalyseFindingsAugments(t *testing.T) {
	in := []Finding{
		{Target: "http://h/", Check: "headers", Severity: "info", Title: "server banner disclosed", Evidence: "Apache/2.4.49 (Unix)"},
		{Target: "h:22", Check: "ports", Severity: "info", Title: "port 22 open", Evidence: "SSH-2.0-OpenSSH_7.4"},
	}
	out := analyseFindings(in)
	if len(out) != 4 {
		t.Fatalf("expected 2 original + 2 hints, got %d", len(out))
	}
	var apacheOK, sshOK bool
	for _, f := range out[2:] {
		if f.Check != "fingerprint" {
			t.Fatalf("hint has wrong check %q", f.Check)
		}
		if f.Fix == "" {
			t.Fatal("hint must carry its fix")
		}
		if strings.Contains(f.Evidence, "CVE-2021-41773") {
			apacheOK = true
		}
		if strings.Contains(f.Evidence, "CVE-2018-15473") {
			sshOK = true
		}
	}
	if !apacheOK || !sshOK {
		t.Fatalf("missing expected hints: %+v", out[2:])
	}
	// Same banner on the same target must not double-report.
	out2 := analyseFindings([]Finding{
		{Target: "http://h/", Check: "headers", Severity: "info", Evidence: "Apache/2.4.49"},
		{Target: "http://h/", Check: "exposure", Severity: "info", Evidence: "Apache/2.4.49"},
	})
	if len(out2) != 3 {
		t.Fatalf("expected one deduped hint, got %d findings", len(out2))
	}
}

func TestRemediationKnownFindings(t *testing.T) {
	f := Finding{Check: "headers", Title: "missing header Content-Security-Policy"}
	if fix := remediation(f); !strings.Contains(fix, "Content-Security-Policy") {
		t.Fatalf("expected header fix, got %q", fix)
	}
	info := Finding{Check: "ports", Severity: "info", Title: "port 80 open"}
	if remediation(info) != "" {
		t.Fatal("info port finding should carry no fix")
	}
}

func TestConfirmPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	sc, err := Parse([]string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	mode := Table()[0]
	p := NewPipeline(Config{Mode: mode, Ports: []int{1}, MaxRuntime: time.Minute}, sc, Spec{CPUs: 2, TotalMemMB: 4096}, t.TempDir())
	limiter := time.NewTicker(time.Millisecond)
	defer limiter.Stop()
	if !p.confirmPort(context.Background(), ln.Addr().String(), limiter) {
		t.Fatal("open listener should confirm")
	}
	ln.Close()
	if p.confirmPort(context.Background(), ln.Addr().String(), limiter) {
		t.Fatal("closed listener should not confirm")
	}
}

func TestConfirmExposure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.git/HEAD" {
			fmt.Fprint(w, "ref: refs/heads/main")
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()
	if !confirmExposure(srv.URL+"/.git/HEAD", http.DefaultClient.Do) {
		t.Fatal("real git metadata should confirm")
	}
	if confirmExposure(srv.URL+"/.env", http.DefaultClient.Do) {
		t.Fatal("404 should not confirm")
	}
}

func TestPipelineEndToEndAndResume(t *testing.T) {
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.4.49 (Unix)")
		if r.URL.Path == "/.git/HEAD" {
			fmt.Fprint(w, "ref: refs/heads/main")
			return
		}
		w.WriteHeader(200)
	}))
	defer web.Close()
	_, portStr, _ := net.SplitHostPort(strings.TrimPrefix(web.URL, "http://"))
	var webPort int
	fmt.Sscan(portStr, &webPort)

	sc, err := Parse([]string{web.URL})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cfg := Config{Mode: Table()[0], ModeReason: "test", Ports: []int{webPort}, MaxRuntime: time.Minute}
	p := NewPipeline(cfg, sc, Spec{CPUs: 2, TotalMemMB: 4096}, dir)
	s, err := p.Run(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range stageOrder {
		if s.Stages[name].Status != stageDone {
			t.Fatalf("stage %s not done: %+v", name, s.Stages[name])
		}
	}
	// The httptest server banner must produce the Apache fingerprint hint.
	var hint bool
	for _, f := range s.Run.Findings {
		if f.Check == "fingerprint" && strings.Contains(f.Evidence, "CVE-2021-41773") {
			hint = true
		}
	}
	if !hint {
		t.Fatal("fingerprint stage did not catch the Apache banner")
	}
	if len(s.Tasks) == 0 {
		t.Fatal("expected tasks from the risky findings")
	}
	md, err := readFile(dir, "report.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"## Tasks", "## Pipeline", "Coverage and limitations", "Fix:"} {
		if !strings.Contains(md, want) {
			t.Fatalf("report.md missing %q", want)
		}
	}
	if _, err := readFile(dir, "session.json"); err != nil {
		t.Fatal("session.json should exist")
	}

	// Resume: everything already done, so findings and tasks stay identical.
	before := len(s.Run.Findings)
	s2, err := NewPipeline(cfg, sc, Spec{CPUs: 2, TotalMemMB: 4096}, dir).Run(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	if len(s2.Run.Findings) != before {
		t.Fatalf("resume changed findings: %d -> %d", before, len(s2.Run.Findings))
	}

	// Resume against a different scope must be refused.
	sc2, _ := Parse([]string{"localhost"})
	if _, err := NewPipeline(cfg, sc2, Spec{}, dir).Run(context.Background(), true); err == nil {
		t.Fatal("resume with a different scope must fail")
	}
}

func readFile(dir, name string) (string, error) {
	b, err := os.ReadFile(filepath.Join(dir, name))
	return string(b), err
}
