#!/usr/bin/env python3
# Fallback for release-cut.yml. Delete this script and release_lib.py once a
# release has been cut with release-cut.yml (RELEASES.md, "Cut").
"""Cut a release: create `release/<major.minor>` and move main to the next one.

    python3 scripts/cut-release.py 0.27 [--from origin/nightly] [--dry-run]

Run by the release manager from a clean checkout with push access and `gh`
authenticated. It:

  1. creates the `backport release/<name>` label backport.yml reads;
  2. resolves the source commit — `origin/nightly` by default, the newest main
     commit the full CI suite passed (RELEASES.md) — and refuses one main
     doesn't have, since only main is reviewed;
  3. builds `release/<name>` = source commit + one commit that moves the
     workspace (lockstep: `[workspace.package] version` and every internal
     requirement) to `<name>.0` and writes `RELEASE` = `<name>.0-rc.0`, and
     `release-cut/<name>` = main + one commit that moves the workspace to the
     next minor (`0.28.0` after `0.27`) and closes main's `## Unreleased`
     changelog section under `## <name>.0 (<today, UTC>)`, with a fresh
     `## Unreleased` above it;
  4. pushes both branches in one `git push --atomic`: either both exist
     afterwards or neither does. `release-tag.yml` then tags
     `v<name>.0-rc.0` (a prerelease; crates are not published);
  5. opens the `release-cut/<name>` PR to main.

Each step is skipped when it is already done, so after a failure the same
command resumes where it stopped: an existing `release/<name>` is accepted if
its tip is this script's cut commit on top of a main commit (that commit is
then the source, whatever `--from` says), an existing `release-cut/<name>` is
reused, and an open PR from it is left alone (a closed, unmerged one is
replaced). Once `release/<name>` exists and its cut PR is merged, a rerun does
nothing, even if the `release-cut/<name>` branch was deleted. A
`release/<name>` that is not a cut stops the script.

The CHANGELOG split is only automatic when main's `## Unreleased` section is
the one the source commit has (nothing changelogged landed after nightly). If
it differs, main's CHANGELOG is left alone and the script says so: move the
entries that shipped in the release under its heading by hand, in the PR.
"""

import argparse
import datetime
import json
import pathlib
import sys
import tempfile

from release_lib import RELEASE_NAME, git, run, set_version, unreleased_split


def worktree(rev, tmp, name):
    path = pathlib.Path(tmp) / name
    git("worktree", "add", "--detach", str(path), rev)
    return path


def remote_head(branch):
    """The SHA of `origin/<branch>` on the remote, or None if it does not exist."""
    out = git("ls-remote", "--exit-code", "--heads", "origin", branch, check=False)
    if out.returncode:
        return None
    return out.stdout.split()[0]


def cut_pull_requests(cut_head):
    """Every PR from `cut_head` into main, whatever its state: [{state, url}]."""
    out = run(
        "gh", "pr", "list", "--head", cut_head, "--base", "main", "--state", "all",
        "--json", "state,url",
    ).stdout
    return json.loads(out or "[]")


def cut_subject(branch, version):
    return f"chore(release): cut {branch} at {version}-rc.0"


def existing_cut_source(branch, version, tip, main_sha):
    """The source commit of an existing `release/<name>`, or exit if it is not our cut."""
    git("fetch", "origin", f"refs/heads/{branch}")
    subject = git("log", "-1", "--format=%s", tip).stdout.strip()
    parent = git("rev-parse", "--verify", f"{tip}^1").stdout.strip()
    if subject != cut_subject(branch, version):
        sys.exit(f"{branch} exists and its tip {tip[:12]} is not a cut commit ({subject!r}); resolve by hand")
    if git("merge-base", "--is-ancestor", parent, main_sha, check=False).returncode:
        sys.exit(f"{branch} exists but its cut is not on top of a main commit; resolve by hand")
    return parent


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("name", help="major.minor, e.g. 0.27")
    ap.add_argument("--from", dest="source", default="origin/nightly")
    ap.add_argument("--dry-run", action="store_true", help="build both commits, push nothing")
    args = ap.parse_args()

    m = RELEASE_NAME.fullmatch(args.name)
    if not m:
        sys.exit(f"release name {args.name!r} is not major.minor")
    major, minor = map(int, m.groups())
    branch = f"release/{args.name}"
    cut_head = f"release-cut/{args.name}"
    version = f"{args.name}.0"
    next_version = f"{major}.{minor + 1}.0"
    today = datetime.datetime.now(datetime.timezone.utc).date().isoformat()

    git("fetch", "origin", "--tags", "--prune")
    main_sha = git("rev-parse", "--verify", "origin/main^{commit}").stdout.strip()

    release_tip = remote_head(branch)
    # Done already: the branch exists and the cut PR merged. The branch may
    # have moved on (rc and GA preps) and the cut branch may be deleted.
    merged = [pr for pr in cut_pull_requests(cut_head) if pr["state"] == "MERGED"]
    if release_tip and merged:
        print(f"{branch} exists and its cut PR is merged ({merged[0]['url']}): nothing to do")
        return 0
    if release_tip:
        source = existing_cut_source(branch, version, release_tip, main_sha)
        print(f"{branch} already exists at {release_tip[:12]} (cut from {source[:12]}); resuming")
    else:
        source = git("rev-parse", "--verify", f"{args.source}^{{commit}}").stdout.strip()
        if git("merge-base", "--is-ancestor", source, main_sha, check=False).returncode:
            sys.exit(f"{args.source} ({source[:12]}) is not on main: a release is cut from a reviewed main commit")
        print(f"cutting {branch} from {args.source} ({source[:12]}); main is {main_sha[:12]}")
    cut_tip = remote_head(cut_head)
    if cut_tip:
        print(f"{cut_head} already exists at {cut_tip[:12]}; reusing it")

    # The label first: it is idempotent (`--force`), and backports need it as
    # soon as the branch exists.
    if not args.dry_run:
        run(
            "gh", "label", "create", f"backport {branch}", "--force",
            "--color", "5319e7", "--description", f"Cherry-pick onto {branch} once merged",
        )

    split = True
    # Prune after the temporary directory is gone: pruned inside it, the
    # worktrees still exist and their records are left behind.
    try:
        with tempfile.TemporaryDirectory() as tmp:
            refspecs = []
            if not release_tip:
                rel = worktree(source, tmp, "release")
                set_version(rel, version)
                (rel / "RELEASE").write_text(f"{version}-rc.0\n")
                git("add", "-A", cwd=rel)
                git("commit", "-s", "-m", cut_subject(branch, version), cwd=rel)
                print(git("show", "--stat", "HEAD", cwd=rel).stdout)
                rel_sha = git("rev-parse", "HEAD", cwd=rel).stdout.strip()
                refspecs.append(f"{rel_sha}:refs/heads/{branch}")

            if not cut_tip:
                mn = worktree(main_sha, tmp, "main")
                set_version(mn, next_version)
                split = False
                main_changelog = mn / "CHANGELOG.md"
                if main_changelog.exists():
                    source_log = git("show", f"{source}:CHANGELOG.md", check=False).stdout
                    src, cur = unreleased_split(source_log), unreleased_split(main_changelog.read_text())
                    split = bool(src and cur and src[1] == cur[1])
                    if split:
                        before, body, after = cur
                        main_changelog.write_text(
                            f"{before}## Unreleased\n\n## {version} ({today})\n{body}{after}"
                        )
                git("add", "-A", cwd=mn)
                git(
                    "commit", "-s", "-m",
                    f"chore(release): cut {branch}; main moves to {next_version}",
                    cwd=mn,
                )
                print(git("show", "--stat", "HEAD", cwd=mn).stdout)
                mn_sha = git("rev-parse", "HEAD", cwd=mn).stdout.strip()
                refspecs.append(f"{mn_sha}:refs/heads/{cut_head}")

            if not split:
                print(
                    "WARNING: main's `## Unreleased` differs from the cut's (or CHANGELOG.md is "
                    "missing); CHANGELOG.md on main was not split. Move the shipped entries under "
                    f"`## {version} ({today})` by hand in the release-cut PR.",
                    file=sys.stderr,
                )
            if args.dry_run:
                print("dry run: nothing pushed")
                return 0

            if refspecs:
                # Both branches or neither: a half-pushed cut is what makes a
                # rerun necessary in the first place.
                git("push", "--atomic", "origin", *refspecs)
    finally:
        git("worktree", "prune")

    # An open PR is reused; a closed, unmerged one does not count as done.
    open_prs = [pr for pr in cut_pull_requests(cut_head) if pr["state"] == "OPEN"]
    if open_prs:
        print(f"the {cut_head} PR already exists: {open_prs[0]['url']}")
    else:
        run(
            "gh", "pr", "create", "--base", "main", "--head", cut_head,
            "--title", f"chore(release): cut {branch}; main moves to {next_version}",
            "--body",
            f"Cuts `{branch}` from `{source[:12]}`. `main` moves to `{next_version}`."
            + ("" if split else "\n\n**CHANGELOG.md needs splitting by hand** — see the cut output."),
        )
    print(f"{branch} and the {cut_head} PR are in place. Update the table in RELEASES.md.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
