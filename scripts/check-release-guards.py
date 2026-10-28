#!/usr/bin/env python3
"""Build-free guards that keep the release tooling's assumptions true.

    python3 scripts/check-release-guards.py [--base-sha SHA]

Run by the `release guards` job in checks.yaml on every PR and push. Each guard is
a fact the release scripts (RELEASES.md) rely on and would otherwise discover
at the worst moment — mid-cut, or mid-publish:

  1. toolchain sync — every `toolchain: X` pin in .github/workflows/* names
     the same toolchain (there is no rust-toolchain.toml; the CI pin is the
     source of truth), and the workspace `rust-version` does not exceed it.
     The release workflows build with the toolchain CI tested.
  2. lockstep — every member inherits `version.workspace = true`, and every
     internal dependency requires exactly the workspace version
     (`{ version = "0.27.0", path = ... }`). The release tooling moves them
     together; a hand-edited one drifts, and a published crate then requires a
     sibling version that is never published.
  3. changelog — CHANGELOG.md exists at the root. On main it has an
     `## Unreleased` section (the cut and the GA prep rename it). On a
     release branch at a GA or patch version it has that version's section,
     which release-tag.yml turns into the GitHub Release notes.
  4. RELEASE ↔ version — on a release branch, RELEASE's `major.minor.patch` is
     the workspace version, and a PR (with --base-sha) never moves RELEASE
     backwards. release.yaml refuses to publish when these disagree; this says
     so at review time instead.

Exit 1 with every problem listed; 0 when all hold.
"""

import argparse
import pathlib
import re
import subprocess
import sys
import tomllib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from release_lib import ROOT, lockstep_problems, parse_release, workspace_version  # noqa: E402

def vtuple(v):
    return tuple(int(x) for x in v.split("."))


def toolchain_problems():
    problems = []
    pin = re.compile(r"""^\s*toolchain:\s*["']?([^"'\s#]+)""", re.M)
    pins = {}
    for wf in sorted((ROOT / ".github" / "workflows").glob("*.y*ml")):
        for lineno, line in enumerate(wf.read_text().splitlines(), 1):
            m = pin.match(line)
            if m:
                pins.setdefault(m.group(1), []).append(f"{wf.relative_to(ROOT)}:{lineno}")
    if not pins:
        return ["no `toolchain:` pin found in .github/workflows"]
    if len(pins) > 1:
        detail = "; ".join(f"{v} at {', '.join(where)}" for v, where in sorted(pins.items()))
        problems.append(f"workflows pin different toolchains: {detail}")
    channel = max(pins, key=lambda v: (len(pins[v]), v))
    print(f"toolchain: workflows pin {channel}")
    rv = tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"].get("package", {}).get("rust-version")
    if rv and re.fullmatch(r"\d+\.\d+(\.\d+)?", rv) and re.fullmatch(r"\d+\.\d+(\.\d+)?", channel):
        if vtuple(rv) > vtuple(channel):
            problems.append(f"Cargo.toml rust-version {rv} is above the CI toolchain {channel}")
    return problems


def git_show(rev, path):
    out = subprocess.run(["git", "show", f"{rev}:{path}"], capture_output=True, text=True, cwd=ROOT)
    return out.stdout if out.returncode == 0 else None


def release_problems(base_sha):
    problems = []
    version = workspace_version(ROOT)
    release_file = ROOT / "RELEASE"
    changelog = ROOT / "CHANGELOG.md"
    if not changelog.exists():
        return ["CHANGELOG.md is missing at the repository root (the release tooling writes to it)"]
    text = changelog.read_text()

    if not release_file.exists():
        # main (or a feature branch off it).
        if not re.search(r"^## Unreleased", text, re.M):
            problems.append("CHANGELOG.md has no `## Unreleased` section (main always carries one)")
        return problems

    current = release_file.read_text().strip()
    major, minor, patch, rc = parse_release(current)
    if f"{major}.{minor}.{patch}" != version:
        problems.append(f"RELEASE is {current} but the workspace version is {version}")
    if rc is None and not re.search(rf"^## \[?{re.escape(current)}(\]| |$)", text, re.M):
        problems.append(f"CHANGELOG.md has no `## {current}` section for the GA/patch RELEASE names")

    if base_sha:
        before = git_show(base_sha, "RELEASE")
        if before and before.strip() != current:
            b = parse_release(before)
            key = lambda t: (t[0], t[1], t[2], float("inf") if t[3] is None else t[3])  # noqa: E731
            if key((major, minor, patch, rc)) <= key(b):
                problems.append(f"RELEASE moves backwards: {before.strip()} -> {current}")
    return problems


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base-sha", help="the PR's base commit, to check RELEASE only moves forward")
    args = ap.parse_args()

    sections = [
        ("toolchain sync", toolchain_problems()),
        ("lockstep versions", lockstep_problems(ROOT)),
        ("changelog and RELEASE", release_problems(args.base_sha)),
    ]
    failed = False
    for name, problems in sections:
        if problems:
            failed = True
            print(f"FAIL  {name}:")
            for p in problems:
                print(f"        - {p}")
        else:
            print(f"ok    {name}")
    if failed:
        print("\nSee RELEASES.md. Versions are only ever moved by the release tooling.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
