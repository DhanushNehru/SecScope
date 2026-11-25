// Package verify works the open tasks a run produced.
//
// Confirmation probes are the same read-only primitives recon uses: one
// TCP connect, one HTTP GET. They run through the shared engine, so they
// respect the mode's rate limit, the memory throttle and the pinned DNS
// answers, and they are counted as probes like any other.
package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// verify processes every open task and returns a summary note.
func (p *Pipeline) verify(ctx context.Context, s *Session) string {
	open := openTasks(s.Tasks)
	if len(open) == 0 {
		return "no tasks to verify"
	}
	limiter := time.NewTicker(time.Second / time.Duration(p.cfg.Mode.GlobalRate))
	defer limiter.Stop()
	client := p.eng.httpClient()
	do := func(req *http.Request) (*http.Response, error) {
		if !p.eng.acquire(ctx, limiter) {
			return nil, context.DeadlineExceeded
		}
		return client.Do(req)
	}

	byID := map[string]*Task{}
	for i := range s.Tasks {
		byID[s.Tasks[i].ID] = &s.Tasks[i]
	}
	var confirmed, ruledOut, noted int
	for _, t := range open {
		stored := byID[t.ID]
		switch t.Kind {
		case "confirm-port":
			if p.confirmPort(ctx, t.Target, limiter) {
				stored.Status = taskConfirmed
				stored.Detail += " | verified: port still open"
				confirmed++
			} else {
				stored.Status = taskRuledOut
				stored.Detail += " | verified: port closed or unreachable at verify time"
				ruledOut++
			}
		case "confirm-exposure":
			if confirmExposure(t.Target, do) {
				stored.Status = taskConfirmed
				stored.Detail += " | verified: still served"
				confirmed++
			} else {
				stored.Status = taskRuledOut
				stored.Detail += " | verified: no longer served"
				ruledOut++
			}
		default: // review tasks need a human, not a probe
			stored.Status = taskNoted
			noted++
		}
	}
	return fmt.Sprintf("%d confirmed, %d ruled out, %d noted for review", confirmed, ruledOut, noted)
}

// confirmPort dials host:port once. Open means the finding stands.
func (p *Pipeline) confirmPort(ctx context.Context, target string, limiter *time.Ticker) bool {
	if !p.eng.acquire(ctx, limiter) {
		return false
	}
	c, err := p.eng.dialer(ctx)("tcp", target, p.cfg.Mode.DialTimeout)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// confirmExposure re-GETs an exposed URL once. A 200 with real-looking
// content means the exposure stands.
func confirmExposure(target string, do HTTPDoer) bool {
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return false
	}
	resp, err := do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != 200 {
		return false
	}
	// Reuse the same loose content check recon applied.
	for _, ep := range ExposedPaths {
		if strings.HasSuffix(target, ep.path) {
			return looksReal(ep.path, body)
		}
	}
	return len(body) > 0
}
