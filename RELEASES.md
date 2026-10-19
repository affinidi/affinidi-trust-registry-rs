# Releases

What operators deploy is a **release**, named by its `major.minor` version
(`0.27`, `0.28`, …). It is cut from `nightly`, stabilised and patched on its own
branch for as long as it is supported, and published from there as crates on
crates.io (`trust-registry`, `trqp`, `trql-client`) and a tag. Patches
(`0.27.1`, `0.27.2`, …) only ever happen on the release branch.

This follows the branching model of `affinidi-messaging-mediator` (and, before
it, `affinidi-webvh-service` and verifiable-trust-infrastructure). Every crate
in the workspace carries the release's version (lockstep).

## Branches

```
feature/*  ──PR──▶  main  ──(nightly.yml: last fully green commit)──▶  nightly
                                                                          │
                          release/0.27 ◀── cut ───────────────────────────┤
                          release/0.28 ◀── cut ───────────────────────────┘
```

| Branch | What it is | Written by |
|---|---|---|
| `main` | Active development. Every PR lands here first. Carries the *next* release's version (`0.28.0` once `release/0.27` is cut) and publishes nothing. | PRs |
| `nightly` | The newest `main` commit on which **every** `checks.yaml` job passed. Fast-forward only. Releases are cut from here, never from `main`'s tip. | `nightly.yml`, daily at 02:00 UTC |
| `release/<major.minor>` | One release, from its cut to its end of life. Takes backported fixes only. | Backport and prep PRs |
| `feature/*`, `fix/*` | Short-lived work. | Anyone |

## Versions and tags

The workspace is versioned in lockstep: `[workspace.package] version` in the
root `Cargo.toml` is the version of every crate (`version.workspace = true`),
and every internal dependency requires exactly that version
(`{ path = "…", version = "0.27.0" }`). Nobody edits either by hand;
`scripts/release_lib.py` moves them together, and the `release guards` job in
`checks.yaml` fails a tree where they disagree.

On a release branch the current version is its `RELEASE` file; the tag is `v`
+ that. `RELEASE` exists on release branches only.

| Step | `RELEASE` | Tag | Crates (crates.io) |
|---|---|---|---|
| **Cut** `release/0.27` from `nightly` | `0.27.0-rc.0` | `v0.27.0-rc.0` (prerelease) | set to `0.27.0`, not published |
| **Stabilise** — backport fixes; each prep is another candidate | `0.27.0-rc.1`, … | `v0.27.0-rc.1`, … (prerelease) | — |
| **GA** | `0.27.0` | `v0.27.0` | publish `0.27.0` |
| **Patch** as fixes are backported | `0.27.1`, `0.27.2`, … | `v0.27.1`, … | publish `0.27.N` |
| **EOL** — marked in the table below; the branch stays, read-only | — | — | — |

`main` never publishes and never edits the version: the cut moves it to the
next minor. A patch never changes a public API in a breaking way — the
`semver (patch-compatible)` job runs `cargo semver-checks --release-type patch`
on every PR into a release branch — and a fix that needs a break stays on
`main` for the next release.

Up to `0.26.0`, every merge to `main` published from `main` through
`affinidi/pipeline-rust`'s release workflow, tagged `trust-registry-v…`.
`0.27.0` is the first release from a release branch, tagged `v0.27.0`.

## Schedule

| Release | Branch | First RC | GA | Latest | Status |
|---|---|---|---|---|---|
| ≤ 0.26 | — | — | — | `0.26.0` | published from `main` (`trust-registry-v…` tags) |
| 0.27 | — | TBD | TBD | — | in development on `main` |

## Support

The newest two GA releases (N and N-1) are supported. When a release goes GA,
the release before N-1 reaches end of life. "Supported" means fixes for
security problems and for defects that break a deployment are backported and
released. Features never are.

## What goes on a release branch

**Fix on `main` first, then backport.** Label the merged PR
`backport release/<major.minor>` (one label per target branch); `backport.yml`
opens the cherry-pick as a PR on that branch, as a draft carrying the conflict
if it does not apply cleanly. A conflict in `CHANGELOG.md` is expected — main's
`## Unreleased` is not on a GA'd branch — drop that hunk: a patch's changelog is
generated from the commit subjects it ships.

Only fix on the release branch directly when the code there no longer exists on
`main`: a maintainer adds the `release-direct` label to that PR, and its
description says why.

The `branch rules` check (`scripts/check-branch-rules.py`) holds all of this: a
PR into `release/**` is a bot backport, a prep PR or labelled `release-direct`;
only the release tooling changes the version or `RELEASE`, on any branch.

## Changelog

Every PR with a user-visible change adds its entry under `## Unreleased` at the
top of `CHANGELOG.md` on `main`. The tooling owns the headings: the cut and the
GA prep turn `## Unreleased` into `## 0.27.0 (date)`.

## Procedures

### Cut

```sh
python3 scripts/cut-release.py 0.27 --dry-run   # builds both commits, pushes nothing
python3 scripts/cut-release.py 0.27
```

From a clean checkout with push access, Python ≥ 3.11, cargo, and `gh`
authenticated. It pushes `release/0.27` (workspace at `0.27.0`, `RELEASE` =
`0.27.0-rc.0`, which `release-tag.yml` tags), creates the
`backport release/0.27` label, and opens the `release-cut/0.27` PR that moves
`main` to `0.28.0` and closes `main`'s `## Unreleased` changelog section under
`## 0.27.0`. Merge it, then update the schedule table above.

`--from <rev>` cuts from something other than `origin/nightly` — the first cut,
before `nightly` exists, is `--from origin/main`.

### Release candidate, GA, patch

Actions → **Prepare a release** → choose the release branch as the ref and
`rc`, `ga` or `patch`. It moves `RELEASE`, writes the changelog (GA: the
`## Unreleased` section becomes `## 0.27.0 (date)`; patch: a new section listing
the commits since the last tag), moves the whole workspace for a patch, and
opens a `chore(release): v…` PR from `release-prep/<major.minor>/<version>`.

**Merging it is the release.** On that push to the release branch:

- `release-tag.yml` tags `v<RELEASE>` and opens the GitHub Release (notes =
  that version's changelog section; an rc is a prerelease).
- `release.yaml` publishes the crates for a GA or patch (below).

### Publish (crates.io)

Automatic, by `release.yaml`, on every push to `release/**`. It publishes only
when `RELEASE` is a GA/patch version equal to the workspace version, and only
the crates whose version is not on crates.io yet — so it is a no-op on every
other push, and re-running it after a failure resumes from the first missing
crate. Order is dependency order from `cargo metadata`:

```sh
python3 .github/scripts/publish-crates.py plan
```

It authenticates with **crates.io Trusted Publishing only** — no registry token
is stored anywhere. Each crate is verify-built first (`cargo package`), then a
fresh 30-minute token is minted for its upload alone; a failed upload is
retried with a new token.

The workflow keeps the filename `release.yaml` because that is what each
crate's Trusted Publisher on crates.io names. Renaming it breaks publishing.

**A new crate** cannot be published this way: Trusted Publishing can only
publish to a crate that already exists and names this workflow as a trusted
publisher. `release.yaml` stops with an explanation. To add a crate:

1. An owner publishes its first version by hand:
   `git switch --detach v<version> && cargo publish -p <crate>`.
2. On crates.io → the crate → Settings → Trusted Publishing, add GitHub
   repository `affinidi/affinidi-trust-registry-rs`, workflow `release.yaml`,
   environment `release`.
3. Re-run `release.yaml` on the release branch for anything that waited on it.

### End of life

Set the status in the table. Nothing is deleted: the branch, its tags and its
crates stay.

## Repository settings this relies on

Settings, not files:

- **Environment `release`** — `release.yaml` runs in it. Its deployment branch
  policy must allow `release/*` (it allowed only `main` while `main`
  published). Each crate's Trusted Publisher on crates.io names this
  repository, `release.yaml` and this environment.
- **Release-bot GitHub App** (`RELEASE_BOT_APP_ID`, `RELEASE_BOT_PRIVATE_KEY`
  secrets in the `release` environment, as `pipeline-rust` already uses — so
  `release-tag.yml`, `release-prep.yml` and `backport.yml` run their jobs in
  that environment) — `release-tag.yml` creates tags
  with it (the `tags_managed` ruleset lets only that app and admins create
  tags), and `release-prep.yml` and `backport.yml` push branches and open PRs
  with it (the enterprise does not allow `GITHUB_TOKEN` to open PRs, and a PR
  it opened would run no CI). The app needs contents and pull-requests write
  on this repository.
- **Ruleset on `release/**`:** require a PR, require the `checks` jobs and
  `branch rules`, block force pushes and deletion.
- **Ruleset on `main`** (`Default_branch_managed`): add `branch rules` as a
  required check.
- **Ruleset on `nightly`:** block force pushes and deletion; only the
  workflow's identity (`github-actions`) may update it.
