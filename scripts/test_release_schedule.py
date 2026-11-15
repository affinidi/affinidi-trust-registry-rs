"""Tests for release_schedule.py: python3 -m unittest discover -s scripts -p 'test_*.py'"""

import contextlib
import datetime
import io
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import release_schedule as rs

D = datetime.date


def tags(**named: str) -> dict:
    """`tags(v0_30_0="2026-10-29")` → {Version(0, 30, 0, None): date}."""
    out = {}
    for key, day in named.items():
        version = rs.parse_tag(key.replace("_rc", "-rc.").replace("_", "."))
        assert version is not None, key
        out[version] = D.fromisoformat(day)
    return out


def body_rows(table: str) -> list[str]:
    return table.splitlines()[3:]


class ParseTag(unittest.TestCase):
    def test_ga_rc_and_others(self):
        self.assertEqual(rs.parse_tag("v0.31.2"), rs.Version(0, 31, 2, None))
        self.assertEqual(rs.parse_tag("v0.31.0-rc.3"), rs.Version(0, 31, 0, 3))
        for other in ("trust-registry-v0.4.0", "v0.31", "0.31.0", "v0.31.0-beta.1", "v0.31.0-rc"):
            self.assertIsNone(rs.parse_tag(other), other)

    def test_rc_sorts_before_its_ga_and_patches_after(self):
        order = ["v0.31.0-rc.0", "v0.31.0-rc.10", "v0.31.0", "v0.31.1", "v0.32.0-rc.0"]
        parsed = [rs.parse_tag(t) for t in order]
        self.assertEqual(
            sorted([parsed[i] for i in (3, 0, 4, 2, 1)], key=rs.Version.sort_key), parsed
        )


class Render(unittest.TestCase):
    def test_n_and_n_minus_1_supported_older_end_of_life_on_the_ga_two_above(self):
        table = rs.render(
            {
                **tags(v0_27_0="2026-10-19"),
                **tags(v0_28_0_rc0="2026-10-26", v0_28_0="2026-10-26"),
                **tags(v0_29_0_rc0="2026-10-28", v0_29_0="2026-10-28"),
                **tags(v0_30_0_rc0="2026-10-29", v0_30_0="2026-10-29"),
            }
        )
        self.assertTrue(table.startswith(rs.HEADER))
        self.assertEqual(
            body_rows(table),
            [
                # No rc tag: First RC falls back to the GA date.
                "| 0.27 | `release/0.27` | 2026-10-19 | 2026-10-19 | `0.27.0` | end of life (2026-10-28) |",
                "| 0.28 | `release/0.28` | 2026-10-26 | 2026-10-26 | `0.28.0` | end of life (2026-10-29) |",
                "| 0.29 | `release/0.29` | 2026-10-28 | 2026-10-28 | `0.29.0` | supported (N-1) |",
                "| 0.30 | `release/0.30` | 2026-10-29 | 2026-10-29 | `0.30.0` | supported (N) |",
            ],
        )

    def test_a_cut_not_yet_ga_is_a_release_candidate_and_ends_no_support(self):
        table = rs.render(
            {
                **tags(v0_30_0="2026-10-29", v0_31_0="2026-11-05"),
                **tags(v0_32_0_rc0="2026-11-12", v0_32_0_rc1="2026-11-13"),
            }
        )
        self.assertEqual(
            body_rows(table),
            [
                "| 0.30 | `release/0.30` | 2026-10-29 | 2026-10-29 | `0.30.0` | supported (N-1) |",
                "| 0.31 | `release/0.31` | 2026-11-05 | 2026-11-05 | `0.31.0` | supported (N) |",
                "| 0.32 | `release/0.32` | 2026-11-12 | — | `0.32.0-rc.1` | release candidate |",
            ],
        )

    def test_latest_is_the_highest_patch_and_first_rc_the_earliest_rc(self):
        table = rs.render(
            tags(
                v0_31_0_rc1="2026-11-04",
                v0_31_0_rc0="2026-11-03",
                v0_31_0="2026-11-05",
                v0_31_2="2026-11-09",
                v0_31_10="2026-11-20",
            )
        )
        self.assertEqual(
            body_rows(table),
            ["| 0.31 | `release/0.31` | 2026-11-03 | 2026-11-05 | `0.31.10` | supported (N) |"],
        )

    def test_an_rc_of_a_patch_is_not_latest(self):
        rows = body_rows(
            rs.render(tags(v0_31_0="2026-11-05", v0_31_1="2026-11-06", v0_31_2_rc0="2026-11-07"))
        )
        self.assertIn("| `0.31.1` |", rows[0])

    def test_a_cut_that_never_went_ga_is_superseded_once_a_newer_line_is(self):
        rows = body_rows(
            rs.render(tags(v0_30_0="2026-10-29", v0_31_0_rc0="2026-11-01", v0_32_0="2026-11-05"))
        )
        self.assertEqual(
            rows[1], "| 0.31 | `release/0.31` | 2026-11-01 | — | `0.31.0-rc.0` | superseded |"
        )
        self.assertTrue(rows[0].endswith("| supported (N-1) |"))

    def test_status_follows_version_order_across_majors(self):
        rows = body_rows(
            rs.render(tags(v0_99_0="2026-01-01", v1_0_0="2026-02-01", v1_1_0="2026-03-01"))
        )
        self.assertTrue(rows[0].endswith("| end of life (2026-03-01) |"))
        self.assertTrue(rows[1].endswith("| supported (N-1) |"))
        self.assertTrue(rows[2].endswith("| supported (N) |"))


class Splice(unittest.TestCase):
    DOC = f"# R\n\n{rs.BEGIN}\nold table\n{rs.END}\n\n## Support\n"

    def test_replaces_only_between_the_markers(self):
        self.assertEqual(
            rs.splice(self.DOC, "new\n"),
            f"# R\n\n{rs.BEGIN}\nnew\n{rs.END}\n\n## Support\n",
        )

    def test_is_idempotent(self):
        once = rs.splice(self.DOC, "new\n")
        self.assertEqual(rs.splice(once, "new\n"), once)

    def test_missing_or_repeated_markers_stop(self):
        with self.assertRaises(SystemExit):
            rs.splice("# R\nno markers\n", "new\n")
        with self.assertRaises(SystemExit):
            rs.splice(self.DOC + self.DOC, "new\n")


class AgainstGit(unittest.TestCase):
    """End to end on a throwaway repository: tag dates, check and --write."""

    def git(self, *args, date=None):
        env = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
        if date:
            env.update(GIT_COMMITTER_DATE=date, GIT_AUTHOR_DATE=date)
        subprocess.run(["git", *args], cwd=self.dir, env=env, check=True, capture_output=True)

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = pathlib.Path(tmp.name)
        self.git("init", "-q")
        self.git("config", "user.email", "ci@example.invalid")
        self.git("config", "user.name", "ci")
        self.md = self.dir / "RELEASES.md"
        self.md.write_text(f"# R\n{rs.BEGIN}\n{rs.END}\n", encoding="utf-8")

    def main(self, *args):
        with contextlib.redirect_stdout(io.StringIO()):
            return rs.main([*args, "--file", str(self.md)])

    def commit_and_tag(self, tag, date):
        self.git("commit", "-q", "--allow-empty", "-m", tag, date=date)
        self.git("tag", tag)

    def test_no_tags_is_an_error_not_an_empty_table(self):
        self.git("commit", "-q", "--allow-empty", "-m", "init")
        with self.assertRaises(SystemExit):
            self.main()

    def test_check_fails_then_write_then_check_passes(self):
        # 23:30 at +08:00 is 15:30 UTC the same day; 06:00 at +08:00 is the
        # previous day in UTC: dates are UTC.
        self.commit_and_tag("v0.40.0-rc.0", "2026-12-01T06:00:00+08:00")
        self.commit_and_tag("v0.40.0", "2026-12-01T23:30:00+08:00")
        self.commit_and_tag("trust-registry-v0.4.0", "2026-12-02T00:00:00+00:00")
        self.assertEqual(self.main(), 1)
        self.assertEqual(self.main("--write"), 0)
        self.assertEqual(self.main(), 0)
        self.assertIn(
            "| 0.40 | `release/0.40` | 2026-11-30 | 2026-12-01 | `0.40.0` | supported (N) |",
            self.md.read_text(encoding="utf-8"),
        )


if __name__ == "__main__":
    unittest.main()
