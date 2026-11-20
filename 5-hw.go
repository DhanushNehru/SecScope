// Package hw detects machine specifications and maps them to run modes.
package main

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Spec describes the machine scantling is running on.
type Spec struct {
	CPUs       int
	TotalMemMB uint64
}

// Detect reads the current machine's CPU count and total memory.
func Detect() Spec {
	return Spec{CPUs: runtime.NumCPU(), TotalMemMB: totalMemMB()}
}

func totalMemMB() uint64 {
	b, err := os.ReadFile("/proc/meminfo")
	if err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "MemTotal:") {
				f := strings.Fields(line)
				if len(f) >= 2 {
					if kb, perr := strconv.ParseUint(f[1], 10, 64); perr == nil {
						return kb / 1024
					}
				}
			}
		}
	}
	return 4096 // conservative fallback when memory size cannot be read
}

// Mode holds the operating parameters for one resource tier.
type Mode struct {
	Name        string
	Workers     int           // concurrent host assessments
	GlobalRate  int           // probes per second across all targets
	DialTimeout time.Duration // per-connection timeout
	HTTPTimeout time.Duration // per-request timeout
	SoftRSSMB   uint64        // memory level where scantling eases off
}

// Table lists the available modes, lowest footprint first.
func Table() []Mode {
	return []Mode{
		{Name: "low", Workers: 2, GlobalRate: 20, DialTimeout: 5 * time.Second, HTTPTimeout: 12 * time.Second, SoftRSSMB: 128},
		{Name: "balanced", Workers: 8, GlobalRate: 100, DialTimeout: 4 * time.Second, HTTPTimeout: 10 * time.Second, SoftRSSMB: 256},
		{Name: "high", Workers: 32, GlobalRate: 400, DialTimeout: 3 * time.Second, HTTPTimeout: 8 * time.Second, SoftRSSMB: 512},
	}
}

// Choose maps a machine spec to a mode and explains the choice.
func Choose(s Spec) (Mode, string) {
	t := Table()
	switch {
	case s.CPUs <= 2 || s.TotalMemMB <= 2048:
		return t[0], "limited hardware (2 CPUs or less, or 2 GiB RAM or less)"
	case s.CPUs >= 8 && s.TotalMemMB >= 16384:
		return t[2], "plenty of headroom (8+ CPUs and 16+ GiB RAM)"
	default:
		return t[1], "mid-range hardware"
	}
}

// Resolve turns a --mode value into a Mode. "auto" (the default) inspects
// the machine.
func Resolve(name string, s Spec) (Mode, string, error) {
	if name == "" || name == "auto" {
		m, why := Choose(s)
		return m, "auto: " + why, nil
	}
	for _, m := range Table() {
		if m.Name == name {
			return m, "forced with --mode", nil
		}
	}
	return Mode{}, "", fmt.Errorf("unknown mode %q (want auto, low, balanced or high)", name)
}
