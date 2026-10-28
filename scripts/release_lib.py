"""Lockstep helpers for the release guards (RELEASES.md).

A release is named `major.minor` (`0.27`) and lives on `release/<major.minor>`.
The workspace is versioned in **lockstep**: `[workspace.package] version` in
the root Cargo.toml is the one version every crate carries
(`version.workspace = true`), and every internal dependency on a workspace
member requires exactly that version (`{ version = "0.27.0", path = ... }`).
`main` carries the next release's `major.minor.0` and publishes nothing.

The release branch's current version is the `RELEASE` file at its root:
`0.27.0-rc.0`, `0.27.0-rc.1`, `0.27.0`, `0.27.1`, … The tag is `v` + that. An
rc never changes the crates' version (they are already `0.27.0`); only GA and
patches publish.
"""

import pathlib
import re
import tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent

RELEASE_VERSION = re.compile(r"(\d+)\.(\d+)\.(\d+)(?:-rc\.(\d+))?")

# Dependency tables a manifest may name a workspace member in.
DEP_TABLES = ("dependencies", "dev-dependencies", "build-dependencies")


def root_manifest(root):
    return tomllib.loads((root / "Cargo.toml").read_text())


def members(root):
    """Manifest paths of every workspace member (no globs are used here)."""
    data = root_manifest(root)
    return [root / m / "Cargo.toml" for m in data["workspace"]["members"]]


def member_names(root):
    return [tomllib.loads(m.read_text())["package"]["name"] for m in members(root)]


def workspace_version(root):
    return root_manifest(root)["workspace"]["package"]["version"]


def _dep_tables(data):
    """Yield every dependency table in a parsed manifest, target-specific ones included."""
    for t in DEP_TABLES:
        if t in data:
            yield data[t]
    for target in data.get("target", {}).values():
        for t in DEP_TABLES:
            if t in target:
                yield target[t]


def internal_requirements(root):
    """[(manifest, dep name, requirement or None)] for every dep on a workspace member."""
    names = set(member_names(root))
    out = []
    for manifest in [root / "Cargo.toml", *members(root)]:
        data = tomllib.loads(manifest.read_text())
        tables = list(_dep_tables(data))
        if manifest == root / "Cargo.toml":
            ws_deps = data.get("workspace", {}).get("dependencies")
            if ws_deps:
                tables.append(ws_deps)
        for table in tables:
            for key, spec in table.items():
                name = spec.get("package", key) if isinstance(spec, dict) else key
                if name not in names:
                    continue
                req = spec if isinstance(spec, str) else spec.get("version")
                if isinstance(spec, dict) and spec.get("workspace"):
                    continue  # inherits from [workspace.dependencies], checked there
                out.append((manifest, name, req))
    return out


def lockstep_problems(root):
    """Every way the tree breaks the lockstep invariant (empty list = holds)."""
    problems = []
    version = workspace_version(root)
    for manifest in members(root):
        pkg = tomllib.loads(manifest.read_text())["package"]
        v = pkg.get("version")
        if not (isinstance(v, dict) and v.get("workspace")):
            problems.append(
                f"{manifest.relative_to(root)}: [package] version must be "
                f"`version.workspace = true` (found {v!r})"
            )
    for manifest, name, req in internal_requirements(root):
        if req != version:
            problems.append(
                f"{manifest.relative_to(root)}: `{name}` requires {req!r}; lockstep requires "
                f'`version = "{version}"` on every internal dependency'
            )
    return problems


def parse_release(text):
    m = RELEASE_VERSION.fullmatch(text.strip())
    if not m:
        raise SystemExit(f"RELEASE holds {text.strip()!r}, not major.minor.patch[-rc.N]")
    major, minor, patch, rc = m.groups()
    return int(major), int(minor), int(patch), (None if rc is None else int(rc))
