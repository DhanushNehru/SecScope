// Package fingerprints maps service banners to known-vulnerability hints.
//
// The table is small, curated and embedded in the binary: matching is a
// few regex tests against banners we already captured, so the whole stage
// costs microseconds and no network. A hint says "this version is known
// vulnerable", never "this target is exploited".
package main

import (
	"fmt"
	"regexp"
)

// fingerprintRow is one curated banner rule.
type fingerprintRow struct {
	id       string // stable identifier, usually the CVE
	pattern  string // matched case-sensitively against banner text
	severity string
	title    string
	fix      string
}

// fingerprintTable holds only entries we can state with confidence. Each
// pattern is pinned to exact affected versions; when in doubt, leave it
// out rather than hint at the wrong version.
var fingerprintTable = []fingerprintRow{
	{
		id: "CVE-2021-41773", pattern: `Apache/2\.4\.49\b`, severity: "high",
		title: "Apache httpd 2.4.49 path traversal and RCE",
		fix:   "Upgrade Apache httpd to 2.4.51 or later; 2.4.50 is still vulnerable (see CVE-2021-42013).",
	},
	{
		id: "CVE-2021-42013", pattern: `Apache/2\.4\.50\b`, severity: "high",
		title: "Apache httpd 2.4.50 path traversal and RCE",
		fix:   "Upgrade Apache httpd to 2.4.51 or later.",
	},
	{
		id: "CVE-2011-2523", pattern: `vsftpd 2\.3\.4\b`, severity: "high",
		title: "vsftpd 2.3.4 backdoor command execution",
		fix:   "Rebuild or replace vsftpd from a trusted source; the 2.3.4 release tarball was backdoored.",
	},
	{
		id: "CVE-2015-3306", pattern: `ProFTPD 1\.3\.5\b`, severity: "high",
		title: "ProFTPD 1.3.5 mod_copy arbitrary file copy",
		fix:   "Upgrade ProFTPD past 1.3.5a or disable mod_copy.",
	},
	{
		id: "CVE-2017-7269", pattern: `Microsoft-IIS/6\.0\b`, severity: "high",
		title: "IIS 6.0 WebDAV buffer overflow (and end of life)",
		fix:   "Move off Windows Server 2003/IIS 6.0 entirely; if WebDAV is enabled, disable it until migration.",
	},
	{
		id: "CVE-2018-15473", pattern: `OpenSSH_(7\.[0-6]|[0-6]\.)`, severity: "medium",
		title: "OpenSSH before 7.7 username enumeration",
		fix:   "Upgrade OpenSSH to 7.7 or later through the OS package manager.",
	},
	{
		id: "CVE-2019-10149", pattern: `Exim 4\.(8[7-9]|9[01])(\D|$)`, severity: "high",
		title: "Exim 4.87 to 4.91 remote command execution",
		fix:   "Upgrade Exim to 4.92 or later.",
	},
	{
		id: "EOL-PHP5", pattern: `PHP/5\.`, severity: "low",
		title: "PHP 5 is end of life",
		fix:   "Plan a move to a supported PHP branch; PHP 5 has had no security fixes since 2018.",
	},
	{
		id: "EOL-APACHE22", pattern: `Apache/2\.2\.`, severity: "low",
		title: "Apache httpd 2.2 is end of life",
		fix:   "Upgrade to a maintained httpd release; 2.2 stopped receiving fixes in 2017.",
	},
}

type compiledFingerprint struct {
	re       *regexp.Regexp
	severity string
	title    string
	fix      string
	id       string
}

var fingerprints []compiledFingerprint

func init() {
	for _, row := range fingerprintTable {
		fingerprints = append(fingerprints, compiledFingerprint{
			id:       row.id,
			re:       regexp.MustCompile(row.pattern),
			severity: row.severity,
			title:    row.title,
			fix:      row.fix,
		})
	}
}

// matchFingerprints returns every hint a banner string triggers.
func matchFingerprints(banner string) []compiledFingerprint {
	var out []compiledFingerprint
	for _, fp := range fingerprints {
		if fp.re.MatchString(banner) {
			out = append(out, fp)
		}
	}
	return out
}

// analyseFindings scans the evidence of every finding for known banners
// and appends one hint finding per (fingerprint, target). The original
// finding set is returned unchanged when nothing matches.
func analyseFindings(in []Finding) []Finding {
	out := append([]Finding(nil), in...)
	seen := map[string]bool{}
	for _, f := range in {
		if f.Evidence == "" {
			continue
		}
		for _, fp := range matchFingerprints(f.Evidence) {
			key := fp.id + "|" + f.Target
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, Finding{
				Target:   f.Target,
				Check:    "fingerprint",
				Severity: fp.severity,
				Title:    fp.title,
				Evidence: fmt.Sprintf("%s (banner: %s)", fp.id, truncate(f.Evidence, 80)),
				Fix:      fp.fix,
			})
		}
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
