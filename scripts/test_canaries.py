"""Every canary runs a type checker or eslint: python3 -m unittest discover -s scripts

A canary catches breakage from the newest, unlocked releases of its
dependencies, so it runs every static analysis tool its repository's CI runs
(ruff and prettier excepted; see README.md, "What a canary runs"). This test
fails a canary whose install and test scripts call no type checker (mypy,
pyright, tsc) or eslint, unless the file sets `static-analysis-exempt` to a
reason string.
"""

import glob
import json
import os
import re
import shutil
import subprocess
import unittest

CANARIES = os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "canaries")

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


def scripts_text(canary):
    """The install and test scripts of the canary and its variants, with comment
    lines dropped so a comment that only mentions a checker doesn't count."""
    blocks = [canary.get("install", ""), canary.get("test", "")]
    for variant in canary.get("variants") or []:
        blocks += [variant.get("install", ""), variant.get("test", "")]
    code = (line for block in blocks for line in block.splitlines() if not line.lstrip().startswith("#"))
    return "\n".join(code)


def runs_static_analysis(canary):
    """True if the canary runs a type checker or eslint, or sets a non-empty
    `static-analysis-exempt` reason."""
    exempt = canary.get("static-analysis-exempt")
    if isinstance(exempt, str) and exempt.strip():
        return True
    return bool(CHECKER.search(scripts_text(canary)))


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

    def test_exempt_with_reason_passes(self):
        self.assertTrue(
            runs_static_analysis({"test": "uv run --no-sync pytest -ra", "static-analysis-exempt": "upstream has no type checker"})
        )

    def test_empty_or_non_string_reason_fails(self):
        self.assertFalse(runs_static_analysis({"test": "uv run --no-sync pytest -ra", "static-analysis-exempt": ""}))
        self.assertFalse(runs_static_analysis({"test": "uv run --no-sync pytest -ra", "static-analysis-exempt": "  "}))
        self.assertFalse(runs_static_analysis({"test": "uv run --no-sync pytest -ra", "static-analysis-exempt": True}))


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


if __name__ == "__main__":
    unittest.main()
