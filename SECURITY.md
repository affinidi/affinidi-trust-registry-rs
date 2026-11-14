# Security Policy

## Supported versions

Security fixes are made for the newest two GA releases (N and N-1), as the
[support policy in RELEASES.md](./RELEASES.md#support) defines. The
[release schedule](./RELEASES.md#schedule) lists each release line and whether
it is supported or end of life; releases are cut weekly, so check it for the
version you run.

| Version | Supported |
|---------|-----------|
| Newest GA minor (N) | Yes |
| Previous GA minor (N-1) | Yes |
| Older minors, release candidates, `main` / nightly builds | No |

A fix lands on `main` first and is backported to each supported release
branch, then shipped as a patch release (`0.N.x`) of the affected lines. It is
not backported to an end-of-life line: upgrade to a supported release.

## Reporting a vulnerability

Please do not open a public issue, pull request or discussion for a security
problem.

Report it privately by email to <security@affinidi.com>.

Include a description of the issue, the steps to reproduce it, the affected
versions, and, if known, mitigations. Our vulnerability management team will
respond within 5 working days. If the issue is confirmed as a vulnerability, we
will publish a GitHub Security Advisory with the fixed versions. This project
follows a 120 day disclosure timeline.
