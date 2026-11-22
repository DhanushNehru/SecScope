// Package tasks turns findings into a small task graph.
//
// The graph is what makes a run autonomous without a model: plain rules
// decide what still needs confirming or reviewing, and the verify stage
// works the graph. Everything here is deterministic and inspectable.
package main

import (
	"fmt"
	"strings"
)

// Task is one unit of follow-up work derived from findings.
type Task struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"` // confirm-port, confirm-exposure, review
	Target string `json:"target"`
	Status string `json:"status"` // open, confirmed, ruled-out, noted
	Detail string `json:"detail"`
}

const (
	taskOpen      = "open"
	taskConfirmed = "confirmed"
	taskRuledOut  = "ruled-out"
	taskNoted     = "noted"
)

// buildTasks applies the follow-up rules to a finding set. One task per
// (kind, target) pair, stable order by first appearance.
func buildTasks(findings []Finding) []Task {
	var tasks []Task
	seen := map[string]bool{}
	add := func(kind, target, detail string) {
		key := kind + "|" + target
		if seen[key] {
			return
		}
		seen[key] = true
		tasks = append(tasks, Task{
			ID:     fmt.Sprintf("T%d", len(tasks)+1),
			Kind:   kind,
			Target: target,
			Status: taskOpen,
			Detail: detail,
		})
	}
	for _, f := range findings {
		switch {
		case f.Check == "ports" && rank[f.Severity] >= rank["medium"]:
			add("confirm-port", f.Target, f.Title)
		case f.Check == "exposure" && rank[f.Severity] >= rank["medium"]:
			add("confirm-exposure", f.Target, f.Title)
		case f.Check == "fingerprint" && rank[f.Severity] >= rank["medium"]:
			add("review", f.Target, f.Title)
		case f.Check == "tls" && f.Severity == "high":
			add("review", f.Target, f.Title)
		}
	}
	return tasks
}

// openTasks returns the tasks the verify stage still owes work on.
func openTasks(tasks []Task) []Task {
	var out []Task
	for _, t := range tasks {
		if t.Status == taskOpen {
			out = append(out, t)
		}
	}
	return out
}

// taskCounts tallies tasks per status for the report.
func taskCounts(tasks []Task) map[string]int {
	c := map[string]int{taskOpen: 0, taskConfirmed: 0, taskRuledOut: 0, taskNoted: 0}
	for _, t := range tasks {
		c[t.Status]++
	}
	return c
}

// remediation returns a concrete next step for a finding, or "" when the
// finding is informational only. Local knowledge base, no lookups.
func remediation(f Finding) string {
	switch f.Check {
	case "ports":
		if rank[f.Severity] >= rank["medium"] {
			return "Close the port or restrict it to trusted networks with a firewall rule; if the service must stay reachable, put it behind TLS and authentication."
		}
	case "headers":
		if strings.HasPrefix(f.Title, "missing header ") {
			h := strings.TrimPrefix(f.Title, "missing header ")
			return "Set the " + h + " response header at the web server or application layer."
		}
		if f.Title == "server banner disclosed" {
			return "Suppress or shorten the Server header; the version string helps an attacker pick known exploits."
		}
	case "cookies":
		switch {
		case strings.Contains(f.Title, "HttpOnly"):
			return "Set HttpOnly on the cookie so client-side scripts cannot read it."
		case strings.Contains(f.Title, "Secure"):
			return "Set the Secure flag so the cookie is only sent over HTTPS."
		case strings.Contains(f.Title, "SameSite"):
			return "Set SameSite=Lax or Strict to limit cross-site sending of the cookie."
		}
	case "exposure":
		switch f.Title {
		case "git metadata exposed":
			return "Block web access to .git (or remove it from the document root); deployed source history leaks code and often secrets."
		case "environment file exposed":
			return "Remove the file from the document root and rotate every secret it contains; treat them as compromised."
		case "server status page exposed":
			return "Restrict the status page to localhost or an admin network."
		}
	case "tls":
		if f.Title == "certificate expired" {
			return "Renew the certificate; expired certs train users to click through warnings."
		}
		if strings.HasPrefix(f.Title, "TLS version below 1.2") {
			return "Disable TLS 1.0 and 1.1 in the server configuration and retest."
		}
		if strings.HasPrefix(f.Title, "certificate expires in") {
			return "Renew the certificate before it lapses; automate renewal if possible."
		}
	case "fingerprint":
		return f.Fix
	}
	return ""
}
