// Package report renders report v2: the session's findings, remediation,
// task graph and stage history in one document.
package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// reportV2 is the machine-readable v2 document.
type reportV2 struct {
	Version   int                    `json:"version"`
	SessionID string                 `json:"session_id"`
	CreatedAt time.Time              `json:"created_at"`
	Mode      string                 `json:"mode"`
	Scope     []string               `json:"scope"`
	Stages    map[string]*StageState `json:"stages"`
	Tasks     []Task                 `json:"tasks"`
	Run       *Run                   `json:"run"`
}

// JSONV2 renders the session as the machine-readable report.
func (s *Session) JSONV2() ([]byte, error) {
	doc := reportV2{
		Version:   2,
		SessionID: s.ID,
		CreatedAt: s.CreatedAt,
		Mode:      s.Mode,
		Scope:     s.Scope,
		Stages:    s.Stages,
		Tasks:     s.Tasks,
		Run:       s.Run,
	}
	return json.MarshalIndent(doc, "", "  ")
}

// maxSeverityOf returns the highest severity in a finding set.
func maxSeverityOf(fs []Finding) string {
	best := ""
	for _, f := range fs {
		if rank[f.Severity] > rank[best] {
			best = f.Severity
		}
	}
	return best
}

// MarkdownV2 renders the human-readable v2 report: prioritized findings
// with their fixes, the task graph outcome, and the pipeline history.
func (s *Session) MarkdownV2() string {
	r := s.Run
	var b strings.Builder
	fmt.Fprintf(&b, "# secscope report\n\n")
	fmt.Fprintf(&b, "Session %s, started %s", s.ID, s.CreatedAt.Format("2006-01-02 15:04:05 MST"))
	if r != nil {
		fmt.Fprintf(&b, ", recon finished %s (%s)",
			r.FinishedAt.Format("15:04:05 MST"), r.FinishedAt.Sub(r.StartedAt).Round(time.Second))
	}
	b.WriteString(".\n\n")
	if r != nil {
		fmt.Fprintf(&b, "Mode **%s** (%s) on %d CPUs / %d MiB RAM. %d probes sent, peak RSS %d MiB. %d targets done, %d skipped.\n\n",
			r.Mode, r.ModeReason, r.CPUs, r.MemoryMB, r.Probes, r.PeakRSSMB, r.TargetsDone, r.TargetsSkip)
	}
	fmt.Fprintf(&b, "## Scope\n\n")
	for _, sc := range s.Scope {
		fmt.Fprintf(&b, "- %s\n", sc)
	}

	fmt.Fprintf(&b, "\n## Findings\n\n")
	var findings []Finding
	if r != nil {
		findings = r.Findings
	}
	c := map[string]int{"info": 0, "low": 0, "medium": 0, "high": 0}
	for _, f := range findings {
		c[f.Severity]++
	}
	fmt.Fprintf(&b, "high %d | medium %d | low %d | info %d\n\n", c["high"], c["medium"], c["low"], c["info"])
	fs := append([]Finding(nil), findings...)
	sort.SliceStable(fs, func(i, j int) bool { return rank[fs[i].Severity] > rank[fs[j].Severity] })
	if len(fs) == 0 {
		b.WriteString("No findings.\n")
	}
	for _, f := range fs {
		fmt.Fprintf(&b, "- **[%s]** %s - `%s`", f.Severity, f.Title, f.Target)
		if f.Evidence != "" {
			fmt.Fprintf(&b, " (%s)", truncate(f.Evidence, 120))
		}
		b.WriteString("\n")
		if f.Fix != "" {
			fmt.Fprintf(&b, "  Fix: %s\n", f.Fix)
		}
	}

	fmt.Fprintf(&b, "\n## Tasks\n\n")
	if len(s.Tasks) == 0 {
		b.WriteString("No follow-up tasks.\n")
	} else {
		tc := taskCounts(s.Tasks)
		fmt.Fprintf(&b, "%d confirmed | %d ruled out | %d noted for review | %d still open\n\n",
			tc[taskConfirmed], tc[taskRuledOut], tc[taskNoted], tc[taskOpen])
		for _, t := range s.Tasks {
			fmt.Fprintf(&b, "- %s (%s) %s `%s`: %s\n", t.ID, t.Status, t.Kind, t.Target, t.Detail)
		}
	}

	fmt.Fprintf(&b, "\n## Pipeline\n\n")
	for _, name := range stageOrder {
		st := s.Stages[name]
		if st == nil {
			continue
		}
		fmt.Fprintf(&b, "- %s: %s", name, st.Status)
		if st.Note != "" {
			fmt.Fprintf(&b, " (%s)", st.Note)
		}
		b.WriteString("\n")
	}

	fmt.Fprintf(&b, "\n## Coverage and limitations\n\n")
	for _, l := range limitations {
		fmt.Fprintf(&b, "- %s\n", l)
	}
	return b.String()
}
