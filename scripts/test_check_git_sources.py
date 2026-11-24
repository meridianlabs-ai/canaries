"""Tests for check_git_sources.py: python3 -m unittest discover -s scripts"""

import os
import subprocess
import sys
import tempfile
import tomllib
import unittest

from check_git_sources import git_packages

SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "check_git_sources.py")

# (case, pyproject.toml text, the packages it takes from git)
CASES = [
    ("no sources", '[project]\nname = "a"\ndependencies = ["inspect-ai>=0.3"]\n', []),
    (
        "git table source",
        '[tool.uv.sources]\ninspect-ai = { git = "https://github.com/UKGovernmentBEIS/inspect_ai", branch = "main" }\n',
        ["inspect-ai"],
    ),
    (
        "git in list form",
        "[tool.uv.sources]\ninspect-ai = [\n"
        '  { git = "https://github.com/UKGovernmentBEIS/inspect_ai", marker = "sys_platform == \'linux\'" },\n'
        '  { index = "pypi", marker = "sys_platform != \'linux\'" },\n'
        "]\n",
        ["inspect-ai"],
    ),
    (
        "git+ URL dependency",
        '[project]\nname = "a"\ndependencies = ["inspect-ai @ git+https://github.com/UKGovernmentBEIS/inspect_ai@main"]\n',
        ["inspect-ai"],
    ),
    (
        "git+ URL with extras in an optional dependency",
        '[project]\nname = "a"\n[project.optional-dependencies]\ndev = ["inspect-ai[dev] @ git+https://github.com/x/y"]\n',
        ["inspect-ai"],
    ),
    (
        "git+ URL in a dependency group",
        '[dependency-groups]\ndev = [{ include-group = "test" }, "b @ git+ssh://git@github.com/x/b"]\ntest = ["c"]\n',
        ["b"],
    ),
    (
        "path and workspace sources pass",
        '[tool.uv.sources]\nlocal-eval = { path = "tests/local_eval", editable = true }\nmember = { workspace = true }\n',
        [],
    ),
    ("a file URL passes", '[project]\nname = "a"\ndependencies = ["b @ file:///tmp/b"]\n', []),
]


def write(directory, text):
    os.makedirs(directory, exist_ok=True)
    with open(os.path.join(directory, "pyproject.toml"), "w") as f:
        f.write(text)


def run(project_dir):
    # The script the way the canary step runs it.
    return subprocess.run([sys.executable, "-I", SCRIPT, project_dir], capture_output=True, text=True)


class GitPackages(unittest.TestCase):
    def test_cases(self):
        for case, text, expected in CASES:
            with self.subTest(case):
                self.assertEqual(git_packages(tomllib.loads(text)), expected)


class Script(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.project = self.dir.name

    def test_a_git_source_fails_and_names_the_file_package_and_rule(self):
        write(self.project, CASES[1][1])
        result = run(self.project)
        self.assertEqual(result.returncode, 1)
        path = os.path.join(self.project, "pyproject.toml")
        self.assertIn(f"::error::{path}: inspect-ai comes from git", result.stdout)
        self.assertIn("canaries test PyPI releases; remove the git source", result.stdout)

    def test_no_git_source_passes(self):
        write(self.project, CASES[0][1])
        result = run(self.project)
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_no_pyproject_passes(self):
        self.assertEqual(run(self.project).returncode, 0)

    def test_a_workspace_member_with_a_git_source_fails(self):
        write(self.project, '[tool.uv.workspace]\nmembers = ["packages/*"]\nexclude = ["packages/skipped"]\n')
        write(os.path.join(self.project, "packages", "member"), CASES[3][1])
        result = run(self.project)
        self.assertEqual(result.returncode, 1)
        self.assertIn(os.path.join(self.project, "packages", "member", "pyproject.toml"), result.stdout)

    def test_an_excluded_workspace_member_is_not_read(self):
        write(self.project, '[tool.uv.workspace]\nmembers = ["packages/*"]\nexclude = ["packages/skipped"]\n')
        write(os.path.join(self.project, "packages", "skipped"), CASES[3][1])
        self.assertEqual(run(self.project).returncode, 0)


if __name__ == "__main__":
    unittest.main()
