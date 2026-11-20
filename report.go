// Package report renders run results as JSON and Markdown.
package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

)

// Run captures one assessment from start to finish.
type Run struct {
	StartedAt   time.Time        `json:"started_at"`
	FinishedAt  time.Time        `json:"finished_at"`
	Mode        string           `json:"mode"`
	ModeReason  string           `json:"mode_reason"`
	CPUs        int              `json:"cpus"`
	MemoryMB    uint64           `json:"memory_mb"`
	Scope       []string         `json:"scope"`
	Findings    []Finding `json:"findings"`
	Probes      int              `json:"probes_sent"`
	PeakRSSMB   uint64           `json:"peak_rss_mb"`
	TargetsDone int              `json:"targets_done"`
	TargetsSkip int              `json:"targets_skipped"`
}

// limitations always ship in the report; they are part of the result.
var limitations = []string{
	"Read-only checks only: TCP connects, TLS handshakes, banner reads and HTTP GET/HEAD requests. Nothing was written, changed or exploited.",
	"An open port or missing header is a lead to review, not proof of a vulnerability.",
	"No authenticated testing, no crawling beyond the listed paths, no exploit verification, no brute force of any kind.",
	"Results are point-in-time and only cover the allowlisted scope; anything outside the file was not looked at.",
}

var rank = map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3}

// Counts tallies findings per severity.
func (r *Run) Counts() map[string]int {
	c := map[string]int{"info": 0, "low": 0, "medium": 0, "high": 0}
	for _, f := range r.Findings {
		c[f.Severity]++
	}
	return c
}

// MaxSeverity returns the highest severity present, or "" for none.
func (r *Run) MaxSeverity() string {
	best := ""
	for _, f := range r.Findings {
		if rank[f.Severity] > rank[best] {
			best = f.Severity
		}
	}
	return best
}

// JSON renders the machine-readable report.
func (r *Run) JSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// Markdown renders the human-readable report.
func (r *Run) Markdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# scantling report\n\n")
	fmt.Fprintf(&b, "Started %s, finished %s (%s).\n\n",
		r.StartedAt.Format("2006-01-02 15:04:05 MST"), r.FinishedAt.Format("15:04:05 MST"),
		r.FinishedAt.Sub(r.StartedAt).Round(time.Second))
	fmt.Fprintf(&b, "Mode **%s** (%s) on %d CPUs / %d MiB RAM. %d probes sent, peak RSS %d MiB. %d targets done, %d skipped.\n\n",
		r.Mode, r.ModeReason, r.CPUs, r.MemoryMB, r.Probes, r.PeakRSSMB, r.TargetsDone, r.TargetsSkip)
	fmt.Fprintf(&b, "## Scope\n\n")
	for _, s := range r.Scope {
		fmt.Fprintf(&b, "- %s\n", s)
	}
	fmt.Fprintf(&b, "\n## Findings\n\n")
	c := r.Counts()
	fmt.Fprintf(&b, "high %d · medium %d · low %d · info %d\n\n", c["high"], c["medium"], c["low"], c["info"])
	fs := append([]Finding(nil), r.Findings...)
	sort.SliceStable(fs, func(i, j int) bool { return rank[fs[i].Severity] > rank[fs[j].Severity] })
	for _, f := range fs {
		fmt.Fprintf(&b, "- **[%s]** %s — `%s`", f.Severity, f.Title, f.Target)
		if f.Evidence != "" {
			ev := f.Evidence
			if len(ev) > 120 {
				ev = ev[:120] + "…"
			}
			fmt.Fprintf(&b, " (%s)", ev)
		}
		b.WriteString("\n")
	}
	if len(fs) == 0 {
		b.WriteString("No findings.\n")
	}
	fmt.Fprintf(&b, "\n## Coverage and limitations\n\n")
	for _, l := range limitations {
		fmt.Fprintf(&b, "- %s\n", l)
	}
	return b.String()
}
