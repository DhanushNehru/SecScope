# scantling

An authorized security surface assessment CLI that sizes itself to the machine it runs on.

scantling takes a written list of systems you are allowed to test, picks an operating mode from your CPU and memory, and checks each target with read-only probes: open ports, TLS certificates, HTTP security headers and a handful of commonly exposed files. It prints what it found, what it did not check, and how much it cost to run.

It is not an exploit framework. It will not attack anything, and it will not touch anything that is not in your allowlist file.

## Install

```sh
go install github.com/DhanushNehru/scantling@latest
```

or build from source:

```sh
git clone https://github.com/DhanushNehru/scantling
cd scantling
go build -o scantling .
```

Go 1.23+, no dependencies outside the standard library.

## Quickstart

Write the targets you are authorized to test, one per line:

```
# targets.txt
192.0.2.10
203.0.113.0/29
staging.example.com
https://example.com/app/
```

Then run:

```sh
scantling run --allow targets.txt
```

Reports land in `scantling-report/` as `report.md` and `report.json`. `scantling` exits 1 when a finding at or above `--fail-on` (default `medium`) exists, so it slots into CI.

Other entry points:

```sh
scantling modes                    # show this machine's specs and the mode table
scantling scope --allow targets.txt  # print the parsed scope, touch nothing
```

## Modes

`scantling run` defaults to `--mode auto`, which reads the machine and picks a tier:

| mode     | picked when                          | workers | probes/sec | soft memory cap |
|----------|--------------------------------------|---------|------------|-----------------|
| low      | 2 CPUs or less, or 2 GiB RAM or less | 2       | 20         | 128 MiB         |
| balanced | mid-range hardware                   | 8       | 100        | 256 MiB         |
| high     | 8+ CPUs and 16+ GiB RAM              | 32      | 400        | 512 MiB         |

Force one with `--mode low|balanced|high`. While running, scantling samples its own memory every two seconds; past the mode's soft cap it eases off until usage drops. The cap is soft: scantling slows down rather than stopping. `scantling modes` shows what auto would pick and why.

A real run on a 2-core VM with 2 GiB RAM:

```
$ scantling run --allow targets.txt --ports 8899,22
scantling: mode low (auto: limited hardware ...); 2 CPUs, 1982 MiB RAM
scantling: scope is ip 127.0.0.1; nothing outside it will be contacted
scantling: done in 2s - high 0, medium 0, low 0, info 2; report in scantling-report/
```

Peak RSS for that run: 6 MiB.

## What gets checked

- **Ports** — a small curated set of common ports (override with `--ports`). Open database/remote-admin services (Redis, MongoDB, RDP, the unencrypted Docker API, Telnet, ...) are flagged for review.
- **TLS** — on 443/8443 and allowlisted `https://` URLs: negotiated version below 1.2, expired or expiring certificates.
- **Headers and cookies** — on common web ports and allowlisted URLs: missing Content-Security-Policy, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy; cookies missing HttpOnly, Secure or SameSite.
- **Exposed files** — plain GETs for `/.git/HEAD`, `/.env`, `/server-status`, and a note when `/.well-known/security.txt` is absent.

Every check is a TCP connect, a TLS handshake, a banner read, or an HTTP GET/HEAD. Nothing is written, no credentials are tried, no payloads are sent.

## The allowlist is the boundary

- scantling refuses to run without `--allow`.
- Hostname entries allow every port and path on that host. IP and CIDR entries work the same way for their ranges.
- URL entries (`https://example.com/app/`) restrict checks to that host and path prefix.
- HTTP redirects to anything outside the allowlist are refused, not followed.
- Hostname entries authorize whatever the name resolves to when the run first uses it; scantling pins those addresses for the whole run, so a mid-run DNS change cannot move the assessment somewhere else.
- CIDR entries are not enumerated (that would be a network scan); they authorize the URLs and hosts you list.

Only run scantling against systems you own or have written permission to test.

## What the report says and does not say

Reports end with a coverage and limitations section, because a clean result here is narrow on purpose: no authenticated testing, no crawling, no exploit verification, no brute force. An open port or a missing header is a lead to review, not proof of a vulnerability. Results are point-in-time and cover only the allowlisted scope.

## Development

```sh
go test ./...
```

Tests run entirely against local fixtures: loopback listeners and `httptest` servers, including one that proves a redirect out of scope is refused.

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE).
