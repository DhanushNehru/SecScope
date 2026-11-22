// Package session holds the durable state of one assessment.
//
// A session is a single JSON document on disk. Each pipeline stage writes
// it after finishing, so an interrupted run can resume where it stopped
// instead of starting over.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// stageOrder is the fixed pipeline order.
var stageOrder = []string{"scope", "recon", "analyse", "verify", "report"}

const (
	stagePending = "pending"
	stageRunning = "running"
	stageDone    = "done"
	stageFailed  = "failed"
)

// StageState records where one stage stands.
type StageState struct {
	Status     string `json:"status"`
	FinishedAt string `json:"finished_at,omitempty"`
	Note       string `json:"note,omitempty"`
}

// Session is one assessment from first probe to final report.
type Session struct {
	Version   int                    `json:"version"`
	ID        string                 `json:"id"`
	CreatedAt time.Time              `json:"created_at"`
	UpdatedAt time.Time              `json:"updated_at"`
	Mode      string                 `json:"mode"`
	Scope     []string               `json:"scope"`
	Stages    map[string]*StageState `json:"stages"`
	Tasks     []Task                 `json:"tasks"`
	Run       *Run                   `json:"run,omitempty"`
}

// NewSession starts a fresh session for one scope and mode.
func NewSession(mode string, scope []string) *Session {
	now := time.Now()
	s := &Session{
		Version:   1,
		ID:        now.Format("20060102-150405"),
		CreatedAt: now,
		UpdatedAt: now,
		Mode:      mode,
		Scope:     scope,
		Stages:    map[string]*StageState{},
	}
	for _, name := range stageOrder {
		s.Stages[name] = &StageState{Status: stagePending}
	}
	return s
}

// needsRun reports whether a stage still has to run: never started, left
// running by an interrupted process, or failed last time.
func (s *Session) needsRun(name string) bool {
	st, ok := s.Stages[name]
	if !ok {
		return true
	}
	return st.Status != stageDone
}

func (s *Session) mark(name, status, note string) {
	s.Stages[name] = &StageState{Status: status, Note: note}
	if status == stageDone {
		s.Stages[name].FinishedAt = time.Now().Format(time.RFC3339)
	}
	s.UpdatedAt = time.Now()
}

// sessionFile is the file name inside the output directory.
const sessionFile = "session.json"

// Save writes the session atomically enough for a CLI: temp file, rename.
func (s *Session) Save(dir string) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, ".session.tmp")
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, sessionFile))
}

// LoadSession reads a saved session. A stage left "running" belongs to a
// process that died, so it is reset to pending for the resume.
func LoadSession(dir string) (*Session, error) {
	b, err := os.ReadFile(filepath.Join(dir, sessionFile))
	if err != nil {
		return nil, err
	}
	var s Session
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("session file is corrupt: %w", err)
	}
	if s.Stages == nil {
		s.Stages = map[string]*StageState{}
	}
	for _, name := range stageOrder {
		st, ok := s.Stages[name]
		if !ok {
			s.Stages[name] = &StageState{Status: stagePending}
			continue
		}
		if st.Status == stageRunning {
			st.Status = stagePending
			st.Note = "reset after interruption"
		}
	}
	return &s, nil
}

// sameScope reports whether two scope descriptions match, used to refuse
// resuming a session against a different allowlist.
func sameScope(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
