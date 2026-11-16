"""Tests for release_lib.py's changelog helpers: python3 -m unittest discover -s scripts -p 'test_*.py'"""

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import release_lib as rl  # noqa: E402

MAIN = """# Changelog

Intro.

## Unreleased

### Fixed

- a fix

## 0.31.0 (2026-11-05)

- older
"""


class CloseUnreleased(unittest.TestCase):
    def test_pending_heading_matches_pipeline_rust(self):
        # pipeline-rust's release-cut writes this placeholder and its GA prep
        # dates any `## <version> …` heading; the local fallback must match.
        self.assertEqual(rl.pending_heading("0.42.0"), "## 0.42.0 (unreleased)")

    def test_cut_closes_unreleased_under_the_pending_heading(self):
        self.assertEqual(
            rl.close_unreleased(MAIN, "0.32.0"),
            """# Changelog

Intro.

## Unreleased

## 0.32.0 (unreleased)

### Fixed

- a fix

## 0.31.0 (2026-11-05)

- older
""",
        )

    def test_older_sections_are_untouched(self):
        closed = rl.close_unreleased(MAIN, "0.32.0")
        self.assertTrue(closed.endswith("## 0.31.0 (2026-11-05)\n\n- older\n"))
        self.assertEqual(closed.count("## Unreleased"), 1)

    def test_no_unreleased_section(self):
        self.assertIsNone(rl.close_unreleased("# Changelog\n\n## 0.31.0 (2026-11-05)\n", "0.32.0"))

    def test_unreleased_last_in_the_file(self):
        self.assertEqual(
            rl.close_unreleased("## Unreleased\n\n- x\n", "0.32.0"),
            "## Unreleased\n\n## 0.32.0 (unreleased)\n\n- x\n",
        )


if __name__ == "__main__":
    unittest.main()
