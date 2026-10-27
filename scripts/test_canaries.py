"""Every canary runs a type checker or eslint: python3 -m unittest discover -s scripts

A canary catches breakage from the newest, unlocked releases of its
dependencies, so it runs every static analysis tool its repository's CI runs
(ruff and prettier excepted; see README.md, "What a canary runs"). This test
fails a canary whose test script calls no type checker (mypy, pyright, tsc) or
eslint in any of its effective jobs, unless the file sets
`static-analysis-exempt` to a reason string.

It is a tripwire against forgetting, not a proof: it only looks for a checker
in the test script -- not that it runs over the right files, or at all.
"""

import glob
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

CANARIES = os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "canaries")
PLAN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "plan.py")

# A type checker (mypy, pyright, tsc) or an eslint call. `pnpm lint`,
# `pnpm compile-tests` and `yarn typecheck` wrap eslint or tsc.
CHECKER = re.compile(
    r"\b(?:mypy|pyright|tsc|eslint)\b|\bpnpm\s+lint\b|\bpnpm\s+compile-tests\b|\byarn\s+typecheck\b"
)


def load(path):
    # yq is preinstalled on GitHub's Ubuntu runners, so CI needs no packages.
    if shutil.which("yq"):
        return json.loads(subprocess.check_output(["yq", "-o=json", ".", path]))
    try:
        import yaml
    except ImportError:
        raise unittest.SkipTest("needs yq or PyYAML to read the canary")
    with open(path) as f:
        return yaml.safe_load(f)


def plan(entries):
    """Run scripts/plan.py over `entries` (one JSON object per line) and return the
    completed process. plan.py validates every entry at import, before it selects
    any, so a clean environment (no ONLY, SCHEDULE or CHANGED_FILES) selects them
    all; a rejected entry exits non-zero with its message on stderr."""
    env = {k: v for k, v in os.environ.items() if k not in {"ONLY", "SCHEDULE", "CHANGED_FILES"}}
    with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
        f.write("\n".join(json.dumps(e) for e in entries))
        path = f.name
    try:
        return subprocess.run([sys.executable, PLAN, path], capture_output=True, text=True, env=env)
    finally:
        os.unlink(path)


def scrubbed(text):
    """`text` with shell comments and `::group::` log labels dropped, so a
    checker named only in a label (`echo "::group::pyright"`) doesn't count. A
    `#` that begins a word (the start of a line or after whitespace) starts a
    comment, so `pytest # pyright` loses `pyright` while `a#b` keeps its `#`."""
    text = re.sub(r'"::group::[^"]*"', "", text)
    return "\n".join(re.sub(r"(^|\s)#.*", "", line) for line in text.splitlines())


def effective_tests(canary):
    """The test script of each effective job: the canary merged with each of its
    variants the way scripts/plan.py's jobs() does, so a variant's keys override
    the top level. Install scripts don't count -- installing a checker (e.g.
    `uv pip install pyright`) isn't running it."""
    return [(canary | variant).get("test", "") for variant in canary.get("variants") or [{}]]


def runs_static_analysis(canary):
    """True if some effective job's test script runs a type checker or eslint, or
    the canary sets a non-empty `static-analysis-exempt` reason."""
    exempt = canary.get("static-analysis-exempt")
    if isinstance(exempt, str) and exempt.strip():
        return True
    return any(CHECKER.search(scrubbed(test)) for test in effective_tests(canary))


class RunsStaticAnalysis(unittest.TestCase):
    def test_no_static_analysis_fails(self):
        self.assertFalse(runs_static_analysis({"test": "uv run --no-sync pytest -ra"}))

    def test_ruff_only_fails(self):
        # ruff is out of scope (style only); it doesn't satisfy the rule.
        self.assertFalse(runs_static_analysis({"test": "uv run --no-sync ruff check .\nuv run --no-sync ruff format --check ."}))

    def test_pyright_passes(self):
        self.assertTrue(runs_static_analysis({"test": "uv run --no-sync pyright"}))

    def test_commented_out_pyright_fails(self):
        self.assertFalse(runs_static_analysis({"test": "# uv run --no-sync pyright\nuv run --no-sync pytest -ra"}))

    def test_checker_in_a_variant_passes(self):
        canary = {
            "install": "uv venv",
            "variants": [
                {"label": "a", "test": "uv run --no-sync pytest -ra"},
                {"label": "b", "test": "uv run --no-sync pyright"},
            ],
        }
        self.assertTrue(runs_static_analysis(canary))

    def test_checker_only_in_install_fails(self):
        # Installing a checker isn't running it; only the test script counts.
        self.assertFalse(runs_static_analysis({"install": "uv pip install pyright", "test": "uv run --no-sync pytest -ra"}))

    def test_inline_comment_fails(self):
        # A `#` after a space starts a comment, so this pyright doesn't count.
        self.assertFalse(runs_static_analysis({"test": "uv run --no-sync pytest -ra # pyright"}))

    def test_group_label_only_fails(self):
        # A checker named only in a `::group::` log label isn't run.
        self.assertFalse(runs_static_analysis({"test": 'echo "::group::pyright"; uv run --no-sync pytest || status=1'}))

    def test_group_label_plus_real_command_passes(self):
        self.assertTrue(
            runs_static_analysis({"test": 'echo "::group::pyright"; uv run --no-sync pyright || status=1; echo "::endgroup::"'})
        )

    def test_top_level_checker_overridden_by_every_variant_fails(self):
        # Every effective job replaces the top-level test, so pyright never runs.
        canary = {
            "test": "uv run --no-sync pyright",
            "variants": [
                {"label": "a", "test": "uv run --no-sync pytest -ra"},
                {"label": "b", "test": "uv run --no-sync pytest -ra -n0 -m network"},
            ],
        }
        self.assertFalse(runs_static_analysis(canary))

    def test_top_level_test_kept_when_variants_override_only_install_passes(self):
        # The variants keep the top-level test, so its pyright runs in each job.
        canary = {
            "test": "uv run --no-sync pyright\nuv run --no-sync pytest -ra",
            "variants": [
                {"label": "a", "install": "uv venv"},
                {"label": "b", "install": "uv pip install -e .[dev]"},
            ],
        }
        self.assertTrue(runs_static_analysis(canary))

    def test_variants_overriding_test_with_a_checker_pass(self):
        canary = {
            "variants": [
                {"label": "a", "test": "uv run --no-sync pyright"},
                {"label": "b", "test": "uv run --no-sync mypy src"},
            ],
        }
        self.assertTrue(runs_static_analysis(canary))

    def test_exempt_with_reason_passes(self):
        self.assertTrue(
            runs_static_analysis({"test": "uv run --no-sync pytest -ra", "static-analysis-exempt": "upstream has no type checker"})
        )

    def test_empty_or_non_string_reason_fails(self):
        self.assertFalse(runs_static_analysis({"test": "uv run --no-sync pytest -ra", "static-analysis-exempt": ""}))
        self.assertFalse(runs_static_analysis({"test": "uv run --no-sync pytest -ra", "static-analysis-exempt": "  "}))
        self.assertFalse(runs_static_analysis({"test": "uv run --no-sync pytest -ra", "static-analysis-exempt": True}))


class TargetRef(unittest.TestCase):
    # A canary must check out `main`, never a target repository's default branch.
    def test_non_main_ref_fails(self):
        result = plan([{"name": "x", "repo": "o/r", "ref": "meridian"}])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ref must be", result.stderr)

    def test_missing_ref_fails(self):
        result = plan([{"name": "x", "repo": "o/r"}])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ref must be", result.stderr)

    def test_main_ref_passes(self):
        result = plan([{"name": "x", "repo": "o/r", "ref": "main"}])
        self.assertEqual(result.returncode, 0, result.stderr)


class InstallGitUrls(unittest.TestCase):
    # Every git+ URL in an install script must pin @main, so a canary can't drift
    # onto a dependency's default branch.
    BASE = {"name": "x", "repo": "o/r", "ref": "main"}

    def test_unpinned_git_url_fails(self):
        result = plan([{**self.BASE, "install": "uv pip install git+https://github.com/o/r.git"}])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("@main", result.stderr)

    def test_git_url_pinned_to_another_ref_fails(self):
        result = plan([{**self.BASE, "install": "uv pip install git+https://github.com/o/r.git@meridian"}])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("@main", result.stderr)

    def test_git_url_pinned_to_main_passes(self):
        result = plan([{**self.BASE, "install": "uv pip install git+https://github.com/o/r.git@main"}])
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_quoted_git_url_pinned_to_main_passes(self):
        result = plan([{**self.BASE, "install": 'uv pip install "git+https://github.com/o/r.git@main"'}])
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_git_url_with_ref_before_fragment_fails(self):
        result = plan([{**self.BASE, "install": "uv pip install git+https://github.com/o/r.git@dev#subdirectory=pkg@main"}])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("@main", result.stderr)

    def test_install_without_a_git_url_passes(self):
        result = plan([{**self.BASE, "install": "uv pip install -e .[dev]"}])
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_unpinned_git_url_in_a_variant_fails(self):
        result = plan([{**self.BASE, "variants": [{"label": "a", "install": "pip install git+https://github.com/o/r.git"}]}])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("@main", result.stderr)

    def test_git_url_followed_by_a_shell_separator_passes(self):
        result = plan([{**self.BASE, "install": "pip install git+https://github.com/o/r.git@main; echo done"}])
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_git_url_followed_by_a_redirect_passes(self):
        result = plan([{**self.BASE, "install": "pip install git+https://github.com/o/r.git@main>/dev/null"}])
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_git_url_pinned_to_a_main_prefixed_ref_fails(self):
        result = plan([{**self.BASE, "install": "pip install git+https://github.com/o/r.git@main-old"}])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("@main", result.stderr)


class RealCanaries(unittest.TestCase):
    def test_every_canary_runs_static_analysis(self):
        paths = sorted(glob.glob(os.path.join(CANARIES, "*.yml")))
        self.assertTrue(paths, "no canaries found")
        for path in paths:
            name = os.path.basename(path)
            with self.subTest(canary=name):
                self.assertTrue(
                    runs_static_analysis(load(path)),
                    f"{name} runs no type checker or eslint and is not static-analysis-exempt",
                )

    def test_every_canary_passes_the_planner(self):
        # Runs plan.py over the real files, so a wrong ref (or an unpinned git+
        # install URL) in any canary fails CI.
        paths = sorted(glob.glob(os.path.join(CANARIES, "*.yml")))
        self.assertTrue(paths, "no canaries found")
        result = plan([load(path) for path in paths])
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
