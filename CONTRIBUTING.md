# Contributing

Thanks for helping out. A few ground rules keep this project useful and safe.

## The safety rules are not negotiable

secscope exists to check systems the operator is explicitly authorized to
test. Contributions that keep that boundary tight are welcome; contributions
that weaken it are not.

- All checks stay read-only: TCP connects, TLS handshakes, banner reads,
  HTTP GET/HEAD. No payloads, no credential attempts, no writes, no exploits.
- The allowlist is a hard boundary. Code that reaches past it — following
  out-of-scope redirects, enumerating unlisted hosts — is a bug; please
  report it.
- Reports must stay honest about what was not checked.

## How to contribute

1. Fork the repository and create a branch from `main`.
2. Make your change. Add or update tests; everything runs on local fixtures
   (`go test ./...`), no network access needed.
3. Run `go vet ./...` and `gofmt` before committing.
4. Open a pull request and describe what you changed and why.

Good first contributions are tagged [`good first issue`](../../issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) in the issue tracker.

## Reporting problems

Open an issue with what you ran, what you expected, and what happened.
Redact real target names if they are private.
