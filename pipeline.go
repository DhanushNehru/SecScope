// Package pipeline runs the assessment as a sequence of stages over a
// session: scope, recon, analyse, verify, report.
//
// Each stage saves the session when it finishes. Re-running with --resume
// picks up at the first stage that is not done, so a crashed or
// interrupted run never has to start from zero.
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

// Pipeline carries one run through its stages.
type Pipeline struct {
	cfg    Config
	sc     *Scope
	spec   Spec
	outDir string
	eng    *Engine
}

// NewPipeline builds a pipeline and the engine its probe stages share, so
// DNS pins from recon are reused by verify.
func NewPipeline(cfg Config, sc *Scope, spec Spec, outDir string) *Pipeline {
	return &Pipeline{cfg: cfg, sc: sc, spec: spec, outDir: outDir, eng: New(cfg, sc, spec)}
}

// loadOrNew returns the saved session when resume is requested and the
// allowlist still matches, a fresh session otherwise.
func (p *Pipeline) loadOrNew(resume bool) (*Session, error) {
	if resume {
		s, err := LoadSession(p.outDir)
		if err == nil {
			if !sameScope(s.Scope, p.sc.Describe()) {
				return nil, fmt.Errorf("saved session covers a different scope; start a new run or choose another --out directory")
			}
			return s, nil
		}
		if !os.IsNotExist(err) {
			return nil, err
		}
		// No session yet: --resume on a first run simply starts fresh.
	}
	return NewSession(p.cfg.Mode.Name, p.sc.Describe()), nil
}

// save marks the stage and persists the session in one step.
func (p *Pipeline) save(s *Session, stage, status, note string) error {
	s.mark(stage, status, note)
	return s.Save(p.outDir)
}

// Run walks every stage that still needs running and returns the session.
func (p *Pipeline) Run(ctx context.Context, resume bool) (*Session, error) {
	if err := os.MkdirAll(p.outDir, 0o755); err != nil {
		return nil, err
	}
	s, err := p.loadOrNew(resume)
	if err != nil {
		return nil, err
	}

	if s.needsRun("scope") {
		// The allowlist was parsed before the pipeline started; reaching
		// this stage at all means the scope is valid. Recording it is what
		// this stage is for.
		if err := p.save(s, "scope", stageDone, fmt.Sprintf("%d allowlist entries", len(s.Scope))); err != nil {
			return s, err
		}
	}

	if s.needsRun("recon") {
		s.mark("recon", stageRunning, "")
		_ = s.Save(p.outDir)
		run, err := p.eng.Run(ctx)
		if err != nil {
			_ = p.save(s, "recon", stageFailed, err.Error())
			return s, err
		}
		s.Run = run
		if err := p.save(s, "recon", stageDone, fmt.Sprintf("%d findings, %d probes", len(run.Findings), run.Probes)); err != nil {
			return s, err
		}
	}

	if s.needsRun("analyse") {
		if s.Run == nil {
			return s, fmt.Errorf("cannot analyse: recon produced no run state")
		}
		augmented := analyseFindings(s.Run.Findings)
		for i := range augmented {
			if augmented[i].Fix == "" {
				augmented[i].Fix = remediation(augmented[i])
			}
		}
		s.Run.Findings = augmented
		s.Tasks = buildTasks(augmented)
		if err := p.save(s, "analyse", stageDone, fmt.Sprintf("%d findings after fingerprint hints, %d tasks", len(augmented), len(s.Tasks))); err != nil {
			return s, err
		}
	}

	if s.needsRun("verify") {
		s.mark("verify", stageRunning, "")
		_ = s.Save(p.outDir)
		note := p.verify(ctx, s)
		s.Run.Probes = int(p.eng.probes.Load()) // include verify probes
		if err := p.save(s, "verify", stageDone, note); err != nil {
			return s, err
		}
	}

	if s.needsRun("report") {
		// Mark done before rendering so the report shows its own final
		// pipeline state; a write failure flips the stage back to failed.
		s.mark("report", stageDone, "report.md and report.json written")
		if err := p.writeReports(s); err != nil {
			_ = p.save(s, "report", stageFailed, err.Error())
			return s, err
		}
		if err := s.Save(p.outDir); err != nil {
			return s, err
		}
	}
	return s, nil
}

// writeReports renders report v2 in both formats.
func (p *Pipeline) writeReports(s *Session) error {
	j, err := s.JSONV2()
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(p.outDir, "report.json"), j, 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(p.outDir, "report.md"), []byte(s.MarkdownV2()), 0o644)
}
