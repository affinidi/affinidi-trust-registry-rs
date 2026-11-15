# Security Policy

## Supported versions

**The newest two GA minor releases, N and N-1, receive security fixes —
however short-lived.** That is the
[support policy in RELEASES.md](./RELEASES.md#support). The
[release schedule](./RELEASES.md#schedule), generated from the release tags,
lists each release line and whether it is supported or end of life.

| Version | Supported |
|---------|-----------|
| Newest GA minor (N) | Yes |
| Previous GA minor (N-1) | Yes, until the next GA |
| Older minors, release candidates, `main` / nightly builds | No |

"Supported" means a security fix (or a fix for a defect that breaks a
deployment) is shipped for that line as a patch release. Nothing else is
backported to it.

Releases go GA about weekly, so a release is N-1 — and supported — for as
little as a few days after the next one ships. **Track the latest GA
release.** Treat N-1 as the time to upgrade in, not a line to stay on.

### How fixes are delivered

A fix lands on `main` first. The merged PR is labelled
`backport release/<major.minor>` for each supported line it affects; the
backport is merged onto that release branch and a patch release (`0.N.x`) is
prepared, tagged and published to crates.io, as
[RELEASES.md](./RELEASES.md#what-goes-on-a-release-branch) describes. The
advisory names the fixed versions. A fix is not backported to an end-of-life
line: upgrade to a supported release.

## Reporting a vulnerability

Please do not open a public issue, pull request or discussion for a security
problem.

Report it privately by email to <security@affinidi.com>.

Include a description of the issue, the steps to reproduce it, the affected
versions, and, if known, mitigations. Our vulnerability management team will
respond within 5 working days. If the issue is confirmed as a vulnerability, we
will publish a GitHub Security Advisory with the fixed versions. This project
follows a 120 day disclosure timeline.
