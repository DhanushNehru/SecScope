package main

import (
	"strings"
	"testing"
	"time"

)

func TestMarkdownAndCounts(t *testing.T) {
	r := &Run{
		StartedAt: time.Now(), FinishedAt: time.Now().Add(time.Minute),
		Mode: "low", ModeReason: "test", Scope: []string{"host example.com"},
		Findings: []Finding{
			{Target: "example.com:23", Check: "ports", Severity: "medium", Title: "port 23 open"},
			{Target: "example.com", Check: "headers", Severity: "info", Title: "server banner disclosed"},
		},
	}
	c := r.Counts()
	if c["medium"] != 1 || c["info"] != 1 {
		t.Fatalf("counts wrong: %+v", c)
	}
	if r.MaxSeverity() != "medium" {
		t.Fatalf("max severity = %q", r.MaxSeverity())
	}
	md := r.Markdown()
	if !strings.Contains(md, "medium 1") || !strings.Contains(md, "port 23 open") {
		t.Fatal("markdown missing findings")
	}
	j, err := r.JSON()
	if err != nil || !strings.Contains(string(j), "\"mode\": \"low\"") {
		t.Fatal("json render broken")
	}
}
