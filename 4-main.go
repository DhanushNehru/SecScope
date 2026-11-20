// scantling is an authorized security surface assessment CLI that adapts
// its footprint to the machine it runs on.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

)

const usage = `scantling - authorized security surface assessment, sized to your machine

Usage:
  scantling run --allow targets.txt [flags]   run an assessment
  scantling modes                             show this machine's specs and the mode table
  scantling scope --allow targets.txt         print the parsed scope and exit

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
	out := fs.String("out", "scantling-report", "output directory for the report")
	maxRuntime := fs.Duration("max-runtime", 30*time.Minute, "stop the whole run after this long")
	failOn := fs.String("fail-on", "medium", "exit 1 when a finding of this severity or worse exists (info, low, medium, high, never)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *allow == "" {
		fmt.Fprintln(os.Stderr, "scantling: --allow is required; scantling only runs against an explicit allowlist of systems you are authorized to test")
		return 2
	}
	sc, err := ParseFile(*allow)
	if err != nil {
		fmt.Fprintln(os.Stderr, "scantling:", err)
		return 2
	}
	spec := Detect()
	mode, reason, err := Resolve(*modeName, spec)
	if err != nil {
		fmt.Fprintln(os.Stderr, "scantling:", err)
		return 2
	}
	var portList []int
	if *ports != "" {
		for _, p := range strings.Split(*ports, ",") {
			var n int
			if _, err := fmt.Sscan(strings.TrimSpace(p), &n); err != nil || n < 1 || n > 65535 {
				fmt.Fprintf(os.Stderr, "scantling: bad port %q\n", p)
				return 2
			}
			portList = append(portList, n)
		}
	}

	fmt.Printf("scantling: mode %s (%s); %d CPUs, %d MiB RAM\n", mode.Name, reason, spec.CPUs, spec.TotalMemMB)
	fmt.Printf("scantling: scope is %s; nothing outside it will be contacted\n", strings.Join(sc.Describe(), ", "))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	eng := New(Config{Mode: mode, ModeReason: reason, Ports: portList, MaxRuntime: *maxRuntime}, sc, spec)
	run, err := eng.Run(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "scantling:", err)
		return 2
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "scantling:", err)
		return 2
	}
	j, _ := run.JSON()
	if err := os.WriteFile(filepath.Join(*out, "report.json"), j, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "scantling:", err)
		return 2
	}
	if err := os.WriteFile(filepath.Join(*out, "report.md"), []byte(run.Markdown()), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "scantling:", err)
		return 2
	}
	c := run.Counts()
	fmt.Printf("scantling: done in %s - high %d, medium %d, low %d, info %d; report in %s/\n",
		run.FinishedAt.Sub(run.StartedAt).Round(time.Second), c["high"], c["medium"], c["low"], c["info"], *out)

	order := map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "never": 99}
	thr, ok := order[*failOn]
	if !ok {
		fmt.Fprintln(os.Stderr, "scantling: bad --fail-on value")
		return 2
	}
	if *failOn != "never" && order[run.MaxSeverity()] >= thr && run.MaxSeverity() != "" {
		return 1
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
	fmt.Println("force one with: scantling run --mode low|balanced|high")
	return 0
}

func cmdScope(args []string) int {
	fs := flag.NewFlagSet("scope", flag.ContinueOnError)
	allow := fs.String("allow", "", "allowlist file (required)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *allow == "" {
		fmt.Fprintln(os.Stderr, "scantling: --allow is required")
		return 2
	}
	sc, err := ParseFile(*allow)
	if err != nil {
		fmt.Fprintln(os.Stderr, "scantling:", err)
		return 2
	}
	for _, line := range sc.Describe() {
		fmt.Println(line)
	}
	return 0
}
