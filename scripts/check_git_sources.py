"""Fail when a tested repository takes a package from git.

    python3 -I scripts/check_git_sources.py <project-dir>

Canaries test PyPI releases. uv applies the tested repository's
`[tool.uv.sources]` in a canary (so its path and workspace sources install as in
its own CI), so a git source there would install a git branch in place of the
newest release, and the canary would test the wrong code without saying so.

This fails on a `[tool.uv.sources]` entry with a `git` key, as a table or in a
list of tables, and on a dependency that is a direct `git+` URL
(`name @ git+https://...`) in `[project]` dependencies, optional dependencies
or `[dependency-groups]`. It reads the pyproject.toml in <project-dir> and
those of its uv workspace members. A project dir with no pyproject.toml has
nothing to check. Standard library only.
"""

import glob
import os
import re
import sys
import tomllib

RULE = "canaries test PyPI releases; remove the git source"
# `name @ git+...`, with optional extras before the `@`.
DIRECT_GIT = re.compile(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)[^@]*@\s*git\+")


def load(path):
    with open(path, "rb") as f:
        return tomllib.load(f)


def git_packages(pyproject):
    """The packages that a parsed pyproject.toml takes from git, sorted."""
    sources = pyproject.get("tool", {}).get("uv", {}).get("sources", {})
    from_sources = {
        name for name, source in sources.items() if any("git" in s for s in (source if isinstance(source, list) else [source]))
    }
    project = pyproject.get("project", {})
    requirements = [
        *project.get("dependencies", []),
        *(r for group in project.get("optional-dependencies", {}).values() for r in group),
        # A group entry may also be a table, such as {include-group = "test"}.
        *(r for group in pyproject.get("dependency-groups", {}).values() for r in group if isinstance(r, str)),
    ]
    direct = {m.group(1) for m in map(DIRECT_GIT.match, requirements) if m}
    return sorted(from_sources | direct)


def pyprojects(project_dir):
    """The pyproject.toml of `project_dir`, then those of its uv workspace
    members (`[tool.uv.workspace]` members globs, minus exclude globs)."""
    root = os.path.join(project_dir, "pyproject.toml")
    if not os.path.isfile(root):
        return []
    workspace = load(root).get("tool", {}).get("uv", {}).get("workspace", {})

    def matches(key):
        return {os.path.normpath(p) for pattern in workspace.get(key, []) for p in glob.glob(os.path.join(project_dir, pattern))}

    members = sorted(matches("members") - matches("exclude") - {os.path.normpath(project_dir)})
    return [root, *(path for m in members if os.path.isfile(path := os.path.join(m, "pyproject.toml")))]


def main():
    project_dir = sys.argv[1]
    found = [(path, name) for path in pyprojects(project_dir) for name in git_packages(load(path))]
    for path, name in found:
        print(f"::error::{path}: {name} comes from git ({RULE}).")
    if not found:
        print(f"No git sources in {project_dir}.")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
