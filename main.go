// secscope is an authorized security surface assessment CLI that adapts
// its footprint to the machine it runs on.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

)

const usage = `secscope - authorized security surface assessment, sized to your machine

Usage:
  secscope run --allow targets.txt [flags]   run an assessment
  secscope session --dir secscope-report     show the state of a saved session
  secscope modes                             show this machine's specs and the mode table
  secscope scope --allow targets.txt         print the parsed scope and exit

A run moves through five stages (scope, recon, analyse, verify, report)
and saves its session after each one. Re-run with --resume to continue an
interrupted session from its last finished stage.

Only hosts, addresses, ranges and URLs written in the allowlist file are
ever contacted. All checks are read-only.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var code int
	switch os.Args[1] {
	case "run":
		code = cmdRun(os.Args[2:])
	case "session":
		code = cmdSession(os.Args[2:])
	case "modes":
		code = cmdModes()
	case "scope":
		code = cmdScope(os.Args[2:])
	default:
		fmt.Fprint(os.Stderr, usage)
		code = 2
	}
	os.Exit(code)
}

func cmdRun(args []string) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	allow := fs.String("allow", "", "allowlist file with authorized targets (required)")
	modeName := fs.String("mode", "auto", "auto, low, balanced or high")
	ports := fs.String("ports", "", "comma-separated ports (default: curated common set)")
	out := fs.String("out", "secscope-report", "output directory for the report")
	maxRuntime := fs.Duration("max-runtime", 30*time.Minute, "stop the whole run after this long")
	failOn := fs.String("fail-on", "medium", "exit 1 when a finding of this severity or worse exists (info, low, medium, high, never)")
	resume := fs.Bool("resume", false, "resume the session saved in --out instead of starting over")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *allow == "" {
		fmt.Fprintln(os.Stderr, "secscope: --allow is required; secscope only runs against an explicit allowlist of systems you are authorized to test")
		return 2
	}
	sc, err := ParseFile(*allow)
	if err != nil {
		fmt.Fprintln(os.Stderr, "secscope:", err)
		return 2
	}
	spec := Detect()
	mode, reason, err := Resolve(*modeName, spec)
	if err != nil {
		fmt.Fprintln(os.Stderr, "secscope:", err)
		return 2
	}
	var portList []int
	if *ports != "" {
		for _, p := range strings.Split(*ports, ",") {
			var n int
			if _, err := fmt.Sscan(strings.TrimSpace(p), &n); err != nil || n < 1 || n > 65535 {
				fmt.Fprintf(os.Stderr, "secscope: bad port %q\n", p)
				return 2
			}
			portList = append(portList, n)
		}
	}

	fmt.Printf("secscope: mode %s (%s); %d CPUs, %d MiB RAM\n", mode.Name, reason, spec.CPUs, spec.TotalMemMB)
	fmt.Printf("secscope: scope is %s; nothing outside it will be contacted\n", strings.Join(sc.Describe(), ", "))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	pipe := NewPipeline(Config{Mode: mode, ModeReason: reason, Ports: portList, MaxRuntime: *maxRuntime}, sc, spec, *out)
	session, err := pipe.Run(ctx, *resume)
	if err != nil {
		fmt.Fprintln(os.Stderr, "secscope:", err)
		return 2
	}
	run := session.Run
	c := map[string]int{"info": 0, "low": 0, "medium": 0, "high": 0}
	for _, f := range run.Findings {
		c[f.Severity]++
	}
	fmt.Printf("secscope: done in %s - high %d, medium %d, low %d, info %d; report in %s/\n",
		run.FinishedAt.Sub(run.StartedAt).Round(time.Second), c["high"], c["medium"], c["low"], c["info"], *out)

	order := map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "never": 99}
	thr, ok := order[*failOn]
	if !ok {
		fmt.Fprintln(os.Stderr, "secscope: bad --fail-on value")
		return 2
	}
	max := maxSeverityOf(run.Findings)
	if *failOn != "never" && max != "" && order[max] >= thr {
		return 1
	}
	return 0
}

func cmdSession(args []string) int {
	fs := flag.NewFlagSet("session", flag.ContinueOnError)
	dir := fs.String("dir", "secscope-report", "output directory holding the session")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	s, err := LoadSession(*dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "secscope:", err)
		return 2
	}
	fmt.Printf("session %s, created %s, mode %s\n", s.ID, s.CreatedAt.Format("2006-01-02 15:04:05 MST"), s.Mode)
	for _, name := range stageOrder {
		st := s.Stages[name]
		line := name + ": " + st.Status
		if st.Note != "" {
			line += " (" + st.Note + ")"
		}
		fmt.Println(line)
	}
	if len(s.Tasks) > 0 {
		tc := taskCounts(s.Tasks)
		fmt.Printf("tasks: %d confirmed, %d ruled out, %d noted, %d open\n",
			tc[taskConfirmed], tc[taskRuledOut], tc[taskNoted], tc[taskOpen])
	}
	if s.Run != nil {
		c := s.Run.Counts()
		fmt.Printf("findings: high %d, medium %d, low %d, info %d\n", c["high"], c["medium"], c["low"], c["info"])
	}
	return 0
}

func cmdModes() int {
	spec := Detect()
	fmt.Printf("this machine: %d CPUs, %d MiB RAM\n\n", spec.CPUs, spec.TotalMemMB)
	chosen, why := Choose(spec)
	for _, m := range Table() {
		mark := "  "
		if m.Name == chosen.Name {
			mark = "* "
		}
		fmt.Printf("%s%-9s workers %-3d rate %-4d dial %-5s http %-6s soft cap %d MiB RSS\n",
			mark, m.Name, m.Workers, m.GlobalRate, m.DialTimeout, m.HTTPTimeout, m.SoftRSSMB)
	}
	fmt.Printf("\n* = auto would pick %s here: %s\n", chosen.Name, why)
	fmt.Println("force one with: secscope run --mode low|balanced|high")
	return 0
}

func cmdScope(args []string) int {
	fs := flag.NewFlagSet("scope", flag.ContinueOnError)
	allow := fs.String("allow", "", "allowlist file (required)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *allow == "" {
		fmt.Fprintln(os.Stderr, "secscope: --allow is required")
		return 2
	}
	sc, err := ParseFile(*allow)
	if err != nil {
		fmt.Fprintln(os.Stderr, "secscope:", err)
		return 2
	}
	for _, line := range sc.Describe() {
		fmt.Println(line)
	}
	return 0
}
