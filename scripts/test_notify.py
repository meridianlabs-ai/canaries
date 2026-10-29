"""Tests for notify.py: python3 -m unittest discover -s scripts"""

import contextlib
import http.server
import io
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import threading
import unittest
from datetime import datetime, timedelta
from urllib.parse import parse_qs, urlsplit
from unittest import mock

import notify

ESC = chr(27)
SHA = "0123456789abcdef0123456789abcdef01234567"
OLD_SHA = "fedcba9876543210fedcba9876543210fedcba98"


def job(name, conclusion, id=1, run_id=10, steps=None):
    return {"name": name, "conclusion": conclusion, "id": id, "run_id": run_id, "steps": steps or []}


def step(name, conclusion, start, end, number):
    return {"name": name, "number": number, "conclusion": conclusion, "started_at": f"2026-10-23T02:{start}Z", "completed_at": f"2026-10-23T02:{end}Z"}


def line(time, text):
    return f"2026-10-23T02:{time}.1234567Z {text}"


def canary_log(sha=SHA, versions=(("anyio", "4.11.0"), ("inspect-ai", "0.3.290")), test_output=(), install_output=()):
    """A job log shaped like GitHub's, with steps at fixed times."""
    lines = [
        line("00:00", "##[group]Run echo \"canary-tested: UKGovernmentBEIS/inspect_ai@$(git rev-parse HEAD)\""),
        line("00:00", f"{ESC}[36;1mecho \"canary-tested: UKGovernmentBEIS/inspect_ai@$(git rev-parse HEAD)\"{ESC}[0m"),
        line("00:00", "##[endgroup]"),
        line("00:00", f"canary-tested: UKGovernmentBEIS/inspect_ai@{sha}"),
        line("00:00", "##[group]Run uv venv"),
        line("00:00", "##[endgroup]"),
        line("00:05", "Installed 300 packages"),
        *[line("00:09", text) for text in install_output],
        line("00:09", "##[group]Run uv pip list --format freeze | sed -e 's/==/ /' -e 's/^/canary-installed: /'"),
        line("00:09", f"{ESC}[36;1muv pip list --format freeze | sed -e 's/==/ /' -e 's/^/canary-installed: /'{ESC}[0m"),
        line("00:09", "##[endgroup]"),
    ]
    lines += [line("00:09", f"canary-installed: {name} {version}") for name, version in versions]
    lines += [
        line("00:09", "##[group]Run uv run --no-sync pytest -ra"),
        line("00:09", "##[endgroup]"),
    ]
    lines += [line("05:00", text) for text in test_output]
    lines += [line("06:31", "##[error]Process completed with exit code 1.")]
    lines += [line("06:31", "Post job cleanup.")]
    return "\n".join(lines)


def details(job, log, green, green_log, green_url):
    """The reply for a canary that is one red job."""
    return notify.details_text([(job, "https://x/job", log, green, green_log, green_url)])


CANARY_STEPS = [
    step("Set up job", "success", "00:00", "00:00", 1),
    step("Record what we tested", "success", "00:00", "00:00", 2),
    step("Install the newest releases", "success", "00:00", "00:09", 3),
    step("Installed versions", "success", "00:09", "00:09", 4),
]


class State(unittest.TestCase):
    def test_conclusions(self):
        self.assertEqual(notify.state("failure"), "red")
        self.assertEqual(notify.state("timed_out"), "red")
        self.assertEqual(notify.state("success"), "green")
        for conclusion in ("cancelled", "skipped", "neutral", None):
            self.assertIsNone(notify.state(conclusion))

    def test_previous_job_skips_runs_without_a_result(self):
        history = [
            [job("plan", "success"), job("nightly", "skipped")],  # a 2h run
            [job("inspect_ai", "cancelled")],
            [job("inspect_ai", "failure", id=3), job("nightly", "success", id=4)],
            [job("inspect_ai", "success", id=5)],
        ]
        self.assertEqual(notify.previous_job("inspect_ai", history)["id"], 3)
        self.assertEqual(notify.previous_job("nightly", history)["id"], 4)
        self.assertEqual(notify.previous_job("inspect_ai", history, want=("green",))["id"], 5)
        self.assertIsNone(notify.previous_job("new", history))

    def test_previous_run_returns_the_jobs_that_ran_the_canary(self):
        history = [
            [job("plan", "success"), job("b", "success")],
            [job("a (x)", "cancelled"), job("a (y)", "skipped")],
            [job("a (x)", "success", id=7), job("a (y)", "failure", id=8)],
            [job("a (x)", "success"), job("a (y)", "success")],
        ]
        self.assertEqual([j["id"] for j in notify.previous_run("a", history)], [7, 8])
        self.assertIsNone(notify.previous_run("new", history))


class Grouping(unittest.TestCase):
    def test_canary_and_part(self):
        self.assertEqual(notify.canary_and_part("inspect_ai (asyncio)"), ("inspect_ai", "asyncio"))
        self.assertEqual(notify.canary_and_part("inspect_ai"), ("inspect_ai", None))
        self.assertEqual(notify.canary_and_part("inspect_vscode-proxy-routes"), ("inspect_vscode-proxy-routes", None))

    def test_only_names_the_planner_generates_parse(self):
        """The review's Q1: the parser is as strict as the planner."""
        for name in ("x ()", "a (b) (c)", "a (b (c))", "a (x)\n", "a\n", "a  (x)", "a(x)", "a (x y)", "a (x", " a", "plan", "notify", "plan (fake)", "notify (x)", "", "${{ matrix.name }}"):
            self.assertIsNone(notify.canary_and_part(name), name)

    def test_names_that_dont_parse_are_ignored(self):
        jobs = [job("victim (safe)", "success"), job("victim (b) (c)", "failure"), job("victim ()", "failure"), job("plan (fake)", "failure")]
        self.assertEqual(list(notify.by_canary(jobs)), ["victim"])
        self.assertEqual(notify.canary_state(notify.by_canary(jobs)["victim"]), "green")

    def test_jobs_group_by_canary_in_order(self):
        jobs = [job("plan", "success"), job("a (x)", "success"), job("b", "failure"), job("a (y)", "failure"), job("notify", None)]
        groups = notify.by_canary(jobs)
        self.assertEqual(list(groups), ["a", "b"])
        self.assertEqual([j["name"] for j in groups["a"]], ["a (x)", "a (y)"])

    def test_canary_state_from_its_parts(self):
        def canary(*conclusions):
            return notify.canary_state([job(f"a ({i})", c) for i, c in enumerate(conclusions)])

        self.assertEqual(canary("success", "failure", "success"), "red")
        self.assertEqual(canary("success", "timed_out"), "red")
        self.assertEqual(canary("failure", "cancelled"), "red")
        self.assertEqual(canary("success", "success"), "green")
        self.assertEqual(canary("success", "cancelled", "skipped"), "green")  # parts that didn't run don't count
        self.assertIsNone(canary("cancelled", "skipped"))
        self.assertIsNone(canary())

    def test_previous_state_skips_runs_that_did_not_run_the_canary(self):
        history = [
            [job("plan", "success"), job("b", "success")],
            [job("a (x)", "cancelled"), job("a (y)", "skipped")],
            [job("a (x)", "success"), job("a (y)", "failure")],
            [job("a (x)", "success"), job("a (y)", "success")],
        ]
        self.assertEqual(notify.previous_state("a", history), "red")
        self.assertEqual(notify.previous_state("b", history), "green")
        self.assertIsNone(notify.previous_state("new", history))


class Escaping(unittest.TestCase):
    def test_markup_is_escaped(self):
        text = "<!channel> <@U123> <https://evil.example|click> a & b ```done```"
        escaped = notify.slack_escape(text)
        self.assertNotIn("<", escaped)
        self.assertNotIn(">", escaped)
        self.assertNotIn("`", escaped)
        self.assertEqual(notify.slack_escape("a & <b>"), "a &amp; &lt;b&gt;")

    def test_ampersand_first(self):
        self.assertEqual(notify.slack_escape("&lt;"), "&amp;lt;")

    def test_clean_strips_timestamp_colors_and_controls(self):
        raw = f"2026-10-23T02:00:00.1234567Z {ESC}[31mFAILED{ESC}[0m x{chr(7)}{chr(0)}\ty"
        self.assertEqual(notify.clean(raw), "FAILED x\ty")

    def test_tested_commit_reports_the_first_marker(self):
        log = canary_log() + "\n" + line("05:00", f"canary-tested: evil/repo@{OLD_SHA}")
        self.assertEqual(notify.tested_commit(log), ("UKGovernmentBEIS/inspect_ai", SHA))

    def test_tested_commit_rejects_odd_values(self):
        self.assertIsNone(notify.tested_commit(line("00:00", "canary-tested: <!channel>@abc")))
        self.assertIsNone(notify.tested_commit(line("00:00", "nothing here")))


class Truncation(unittest.TestCase):
    def test_long_lines_are_cut(self):
        cleaned = notify.clean("x" * 1000)
        self.assertEqual(len(cleaned), notify.LINE_CHARS)
        self.assertTrue(cleaned.endswith("…"))

    def test_fit_keeps_head_or_tail(self):
        lines = [f"line {i}" for i in range(100)]
        head = notify.fit(lines, 50)
        self.assertTrue(head.startswith("line 0\n"))
        self.assertTrue(head.endswith("more lines"))
        tail = notify.fit(lines, 50, keep="tail")
        self.assertTrue(tail.startswith("… "))
        self.assertTrue(tail.endswith("line 99"))
        self.assertLessEqual(len(tail), 50 + len("… 100 more lines\n"))

    def test_fit_without_truncation(self):
        self.assertEqual(notify.fit(["a", "b"], 100), "a\nb")
        self.assertEqual(notify.fit(["a", "b"], 100, keep="tail"), "a\nb")

    def test_details_are_bounded(self):
        output = [f"FAILED tests/test_{i}.py::test_{'x' * 50} - boom" for i in range(500)]
        output += ["y" * 2000] * 200
        log = canary_log(test_output=output)
        failing = job("inspect_ai", "failure", steps=CANARY_STEPS + [step("Test", "failure", "00:09", "06:31", 5)])
        green = job("inspect_ai", "success", id=2, steps=CANARY_STEPS + [step("Test", "success", "00:09", "06:31", 5)])
        text = details(failing, log, green, canary_log(), "https://x/run")
        budget = notify.TESTS_CHARS + notify.LOG_CHARS + notify.VERSIONS_CHARS
        self.assertLess(len(text), budget + 1000)
        self.assertIn("*Failed tests* (100+)", text)
        self.assertIn("(0):", text.split("Versions")[1])
        self.assertIn("more lines", text)


class Parts(unittest.TestCase):
    def test_failing_parts_share_the_bounds_of_one_job(self):
        output = [f"FAILED tests/test_{i}.py::test_{'x' * 50} - boom" for i in range(500)] + ["y" * 2000] * 200
        versions = tuple((f"package-{i}", "2.0") for i in range(200))
        green_log = canary_log(versions=tuple((f"package-{i}", "1.0") for i in range(200)))
        failing = []
        for i in range(4):
            j = job(f"inspect_ai (part{i})", "failure", id=i, steps=CANARY_STEPS + [step("Test", "failure", "00:09", "06:31", 5)])
            green = job(f"inspect_ai (part{i})", "success", id=10 + i)
            failing.append((j, f"https://x/job/{i}", canary_log(versions=versions, test_output=output), green, green_log, "https://x/green"))
        text = notify.details_text(failing, ran=5)
        one_job = notify.details_text(failing[:1])
        budget = notify.TESTS_CHARS + notify.LOG_CHARS + notify.VERSIONS_CHARS
        self.assertLess(len(text), budget + 1500)
        self.assertLess(len(one_job), budget + 1000)
        self.assertIn("*Failing parts* (4 of 5): `part0`, `part1`, `part2`, `part3`", text)
        for i in range(4):
            self.assertIn(f"*Part* `part{i}` (<https://x/job/{i}|Run log>)", text)
        self.assertEqual(text.count("*Failed tests* (100+)"), 4)
        self.assertEqual(text.count("*Versions changed since"), 4)

    def test_many_long_labelled_parts_stay_within_one_reply(self):
        """The review's R1: 128 failing parts with long labels and escaped log text."""
        noisy = [f"FAILED tests/t.py::test_{i} - <&>" + "&<>" * 90 for i in range(120)] + ["<!channel> & " * 25] * 60
        failing = []
        for i in range(128):
            j = job(f"a (part{i:03}-{'a' * 60})", "failure", id=i, run_id=7, steps=CANARY_STEPS + [step("Test", "failure", "00:09", "06:31", 5)])
            failing.append((j, f"https://github.com/o/r/actions/runs/7/job/{i}", canary_log(test_output=noisy), None, "", ""))
        text = notify.details_text(failing, ran=130, run_url="https://github.com/o/r/actions/runs/7")
        self.assertLessEqual(len(text), notify.REPLY_CHARS)
        self.assertIn("*Failing parts* (128 of 130): ", text)
        self.assertIn("and 122 more", text)
        self.assertEqual(text.count("*Part* "), notify.MAX_PARTS)
        self.assertIn("_122 more failing parts not shown: see <https://github.com/o/r/actions/runs/7|the run>._", text)
        self.assertNotIn("part006", text)
        self.assertNotIn("<!channel>", text)
        self.assertEqual(text.count("```") % 2, 0)  # every code block closed
        # Labels are cut to LABEL_CHARS.
        self.assertIn(f"`part000-{'a' * (notify.LABEL_CHARS - 9)}…`", text)
        # Each shown part still shows its log tail, cut and escaped.
        for section in text.split("*Part* ")[1:]:
            self.assertIn("&lt;!channel&gt; &amp;", section.split("*Last lines of the job*")[1])

    def test_the_final_bound_drops_whole_sections(self):
        sections = ["head"] + [f"section {i}\n```\n{'x' * 100}\n```" for i in range(10)]
        text = notify.within(sections, 500, "_cut_")
        self.assertLessEqual(len(text), 500)
        self.assertTrue(text.endswith("\n\n_cut_"))
        self.assertEqual(text.count("```") % 2, 0)
        self.assertEqual(notify.within(["a", "b"], 100, "_cut_"), "a\n\nb")

    def test_code_blocks_are_bounded_after_escaping(self):
        block = notify.code_block(["&" * 200] * 50, 1000)
        self.assertLessEqual(len(block), 1000 + len("```\n\n```") + len("… 50 more lines\n"))
        self.assertIn("&amp;", block)

    def test_plain_does_not_end_in_half_an_escape(self):
        self.assertEqual(notify.plain("ab&cd", limit=4), "`ab…`")
        self.assertEqual(notify.plain("a" * 50, limit=10), f"`{'a' * 9}…`")

    def test_one_job_has_no_part_headings(self):
        text = notify.details_text([(job("inspect_ai", "failure"), "https://x/job", canary_log(), None, "", "")])
        self.assertNotIn("Part", text)
        self.assertIn("*Last lines of the job*", text)


class Logs(unittest.TestCase):
    def test_output_lines_stop_at_the_post_job_cleanup(self):
        lines = notify.output_lines(canary_log(test_output=["##[group]Run nested", "inside", "##[endgroup]"]))
        self.assertEqual(lines[-3:], ["Run nested", "inside", "Process completed with exit code 1."])
        self.assertNotIn("Post job cleanup.", lines)
        self.assertFalse(any(text.startswith("##[") for text in lines))

    def test_failed_tests(self):
        lines = [
            "tests/test_a.py::test_one PASSED",
            "FAILED tests/test_a.py::test_two - AssertionError: no",
            "ERROR tests/test_b.py::test_three - fixture",
            "FAILED tests/test_a.py::test_two - AssertionError: no",
        ]
        self.assertEqual(notify.failed_tests(lines), (["tests/test_a.py::test_two", "tests/test_b.py::test_three"], False))

    def test_failed_tests_are_bounded(self):
        lines = [f"FAILED tests/t.py::test_{i}" for i in range(150)]
        tests, more = notify.failed_tests(lines)
        self.assertEqual(len(tests), notify.MAX_TESTS)
        self.assertTrue(more)
        self.assertEqual(notify.failed_tests(lines[:3], limit=3), (["tests/t.py::test_0", "tests/t.py::test_1", "tests/t.py::test_2"], False))

    def test_version_diff(self):
        old = notify.parse_versions(
            ["canary-installed: anyio 4.10.0", "canary-installed: Pydantic_Core 2.41.0", "canary-installed: gone 1.0", "canary-installed: same 1.0"]
        )
        new = notify.parse_versions(
            ["canary-installed: anyio 4.11.0", "canary-installed: pydantic-core 2.41.0", "canary-installed: added 2.0", "canary-installed: same 1.0"]
        )
        self.assertEqual(old["pydantic-core"], "2.41.0")
        self.assertEqual(notify.version_diff(old, new), ["+ added 2.0", "  anyio 4.10.0 → 4.11.0", "- gone 1.0"])

    def test_parse_versions_reads_only_marker_lines(self):
        lines = ["Package Version", "------- -------", "anyio 4.11.0", "Run uv pip list", "canary-installed: a 1", "canary-installed: odd line here", "x canary-installed: b 2"]
        self.assertEqual(notify.parse_versions(lines), {"a": "1"})

    def test_details(self):
        output = [
            "tests/test_a.py::test_one PASSED",
            "FAILED tests/test_a.py::test_two - <!channel> & `x`",
            "SKIPPED [1] tests/test_a.py:3: need --runslow option to run",
            "= 1 failed, 1 passed, 1 skipped =",
        ]
        log = canary_log(versions=(("anyio", "4.11.0"), ("inspect-ai", "0.3.290")), test_output=output)
        green_log = canary_log(sha=OLD_SHA, versions=(("anyio", "4.10.0"), ("inspect-ai", "0.3.290")))
        failing = job("inspect_ai", "failure", steps=CANARY_STEPS + [step("Test", "failure", "00:09", "06:31", 5)])
        green = job("inspect_ai", "success", id=2, steps=CANARY_STEPS + [step("Test", "success", "00:09", "06:31", 5)])
        text = details(failing, log, green, green_log, "https://github.com/o/r/actions/runs/9/job/2")
        self.assertTrue(text.startswith(f"_{notify.UNTRUSTED}_"))
        self.assertIn("```\ntests/test_a.py::test_two\n```", text)
        self.assertIn("*Last lines of the job* (failed step `Test`):", text)
        self.assertIn("FAILED tests/test_a.py::test_two - &lt;!channel&gt; &amp; 'x'", text)
        self.assertIn("Process completed with exit code 1.", text)
        self.assertNotIn("Post job cleanup.", text)
        self.assertNotIn("need --runslow", text)
        self.assertNotIn("<!channel>", text)
        self.assertNotIn("canary-installed: inspect-ai", text)  # the version list stays out of the tail
        self.assertIn("anyio 4.10.0 → 4.11.0", text)
        self.assertIn("(1):", text)

    def test_details_without_a_passing_run(self):
        failing = job("c", "failure", steps=[step("Install the newest releases", "failure", "00:00", "00:09", 3)])
        log = canary_log(versions=(), install_output=["error: No solution found", "##[error]Process completed with exit code 1."])
        text = details(failing, log, None, "", "")
        self.assertIn("(failed step `Install the newest releases`)", text)
        self.assertIn("error: No solution found", text)
        self.assertIn("no earlier passing run", text)
        self.assertNotIn("Failed tests", text)

    def test_install_failure_against_a_passing_run(self):
        failing = job("c", "failure", steps=[step("Install the newest releases", "failure", "00:00", "00:09", 3)])
        log = canary_log(versions=(), install_output=["error: No solution found", "##[error]Process completed with exit code 1."])
        text = details(failing, log, job("c", "success", id=2), canary_log(), "https://x/run")
        self.assertIn("this run didn't get as far as installing", text)

    def test_details_for_a_timeout(self):
        failing = job("c", "failure", steps=CANARY_STEPS + [step("Test", "cancelled", "00:09", "06:31", 5)])
        text = details(failing, canary_log(test_output=["still running"]), None, "", "")
        self.assertIn("(failed step `Test`)", text)
        self.assertIn("still running", text)


class NestedGroups(unittest.TestCase):
    """Output can open groups titled `Run …`; the log is read whole, so they can't hide anything."""

    def test_nested_run_group_in_the_failing_step(self):
        output = ["start tests", "##[group]Run nested test suite", "FAILED tests/real.py::test_x - boom", "##[endgroup]", "= 1 failed ="]
        failing = job("c", "failure", steps=CANARY_STEPS + [step("Test", "failure", "00:09", "06:31", 5)])
        text = details(failing, canary_log(test_output=output), None, "", "")
        self.assertIn("```\ntests/real.py::test_x\n```", text)
        self.assertIn("Run nested test suite", text)
        self.assertIn("Process completed with exit code 1.", text)

    def test_preceding_steps_nested_group_in_the_same_second(self):
        """The delta review's R1: Install opens a `Run …` group in the second that
        Installed versions and Test both start; versions must still compare."""
        steps = [
            step("Install the newest releases", "success", "00:00", "00:09", 1),
            step("Installed versions", "success", "00:09", "00:09", 2),
            step("Test", "failure", "00:09", "00:20", 3),
        ]

        def log(version, nested):
            return "\n".join(
                [
                    line("00:00", "##[group]Run install"),
                    line("00:00", "##[endgroup]"),
                    line("00:09", "##[group]Run nested build" if nested else "build output"),
                    line("00:09", "build finished"),
                    line("00:09", "##[endgroup]"),
                    line("00:09", "##[group]Run uv pip list --format freeze | sed -e 's/==/ /' -e 's/^/canary-installed: /'"),
                    line("00:09", "##[endgroup]"),
                    line("00:09", f"canary-installed: anyio {version}"),
                    line("00:09", "##[group]Run pytest"),
                    line("00:09", "##[endgroup]"),
                    line("00:20", "FAILED tests/a.py::test_x - boom"),
                    line("00:20", "##[error]Process completed with exit code 1."),
                ]
            )

        green_steps = [{**s, "conclusion": "success"} for s in steps]
        text = details(
            job("c", "failure", steps=steps), log("4.11.0", True), job("c", "success", id=2, steps=green_steps), log("4.10.0", False), "https://x/run"
        )
        self.assertIn("anyio 4.10.0 → 4.11.0", text)
        self.assertNotIn("didn't get as far as installing", text)
        self.assertIn("tests/a.py::test_x", text)
        self.assertNotIn("canary-installed: anyio", text)


class Names(unittest.TestCase):
    def test_plain_names(self):
        self.assertEqual(notify.plain("inspect_ai"), "`inspect_ai`")
        self.assertEqual(notify.plain("a*b*~c~\n<!here> & `x`"), "`abc &lt;!here&gt; &amp; 'x'`")
        long = notify.plain("n" * 500)
        self.assertEqual(len(long), notify.NAME_CHARS + 2)
        self.assertTrue(long.endswith("…`"))

    def test_names_in_messages_are_plain(self):
        url = "https://github.com/o/r/actions/runs/1/job/2"
        text = notify.alert_text("*bold*\n<!channel>", True, url, None)
        self.assertIn("Canary `bold &lt;!channel&gt;` is failing", text)
        failing = job("c", "failure", steps=CANARY_STEPS + [step("_Test_ *now*", "failure", "00:09", "06:31", 5)])
        self.assertIn("(failed step `_Test_ now`)", details(failing, canary_log(), None, "", ""))


class BoundedRead(unittest.TestCase):
    def test_small_logs_are_read_whole(self):
        data = b"line 1\nline 2\n"
        self.assertEqual(notify.read_bounded(io.BytesIO(data), head=100, tail=100), data)

    def test_large_logs_keep_head_and_tail(self):
        data = b"".join(f"line {i}\n".encode() for i in range(100000))
        kept = notify.read_bounded(io.BytesIO(data), head=1000, tail=2000)
        self.assertLess(len(kept), 3100)
        self.assertTrue(kept.startswith(b"line 0\n"))
        self.assertTrue(kept.endswith(b"line 99999\n"))
        self.assertIn(b"bytes of log left out", kept)
        middle = kept.split(b"left out \xe2\x80\xa6\n", 1)[1]
        self.assertTrue(middle.startswith(b"line "))  # the tail starts on a whole line


class Planner(unittest.TestCase):
    def plan(self, names):
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
            for name in names:
                f.write(json.dumps({"name": name, "repo": f"o/{name}", "ref": "main", "cadence": "2h"}) + "\n")
        try:
            script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "plan.py")
            return subprocess.run([sys.executable, script, f.name], capture_output=True, text=True, env={})
        finally:
            os.unlink(f.name)

    def run_plan(self, entries, **env):
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
            for entry in entries:
                f.write(json.dumps(entry) + "\n")
        try:
            script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "plan.py")
            return subprocess.run([sys.executable, script, f.name], capture_output=True, text=True, env=env)
        finally:
            os.unlink(f.name)

    def matrix(self, entries, **env):
        result = self.run_plan(entries, **env)
        self.assertEqual(result.returncode, 0, result.stderr)
        include = json.loads(result.stdout)["include"]
        self.assertEqual(result.stderr.splitlines()[-1], str(len(include)))
        return include

    VARIANTS = {
        "name": "inspect_ai",
        "repo": "UKGovernmentBEIS/inspect_ai",
        "ref": "main",
        "cadence": "2h",
        "python": "3.11",
        "timeout-minutes": 60,
        "install": "uv venv",
        "test": "pytest",
        "variants": [
            {"label": "asyncio"},
            {"label": "docs", "install": "uv venv .venv-docs", "test": "quarto render docs", "timeout-minutes": 20, "node": "22"},
        ],
    }

    def test_variants_expand_into_parallel_jobs(self):
        plain_entry = {"name": "inspect_swe", "repo": "meridianlabs-ai/inspect_swe", "ref": "main", "cadence": "2h", "test": "pytest"}
        include = self.matrix([self.VARIANTS, plain_entry])
        self.assertEqual([e["name"] for e in include], ["inspect_ai (asyncio)", "inspect_ai (docs)", "inspect_swe"])
        self.assertEqual([e["canary"] for e in include], ["inspect_ai", "inspect_ai", "inspect_swe"])
        asyncio, docs, swe = include
        self.assertNotIn("variants", asyncio)
        self.assertEqual((asyncio["install"], asyncio["test"], asyncio["timeout-minutes"]), ("uv venv", "pytest", 60))
        self.assertNotIn("node", asyncio)
        self.assertEqual((docs["install"], docs["test"], docs["timeout-minutes"], docs["node"]), ("uv venv .venv-docs", "quarto render docs", 20, "22"))
        self.assertEqual((docs["python"], docs["repo"], docs["dir"]), ("3.11", "UKGovernmentBEIS/inspect_ai", "inspect_ai"))
        self.assertEqual(swe["name"], "inspect_swe")

    def test_only_and_pull_requests_run_every_variant(self):
        other = {"name": "inspect_swe", "repo": "meridianlabs-ai/inspect_swe", "ref": "main", "cadence": "nightly"}
        names = lambda include: [e["name"] for e in include]
        self.assertEqual(names(self.matrix([self.VARIANTS, other], ONLY="inspect_ai")), ["inspect_ai (asyncio)", "inspect_ai (docs)"])
        self.assertEqual(names(self.matrix([self.VARIANTS, other], CHANGED_FILES="canaries/inspect_ai.yml")), ["inspect_ai (asyncio)", "inspect_ai (docs)"])
        self.assertEqual(names(self.matrix([self.VARIANTS, other], SCHEDULE="0 */2 * * *")), ["inspect_ai (asyncio)", "inspect_ai (docs)"])

    def test_variant_validation(self):
        def rejected(variants, name="inspect_ai"):
            result = self.run_plan([{**self.VARIANTS, "name": name, "variants": variants}])
            self.assertNotEqual(result.returncode, 0)
            return result.stderr

        self.assertIn("duplicate job names inspect_ai (a)", rejected([{"label": "a"}, {"label": "a"}]))
        for label in (None, "two words", "a(b)", "a\n", "", "-a"):
            variant = {"label": label} if label is not None else {"test": "pytest"}
            self.assertIn("must be a string of letters", rejected([variant]))
        self.assertIn("can only set", rejected([{"label": "a", "repo": "evil/repo"}]))
        self.assertIn("non-empty list", rejected([]))
        self.assertIn("non-empty list", rejected({"label": "a"}))
        self.assertIn("must be a string of letters", rejected(["a"]))
        self.assertIn("must be a string of letters", rejected([{"label": "a"}], name="inspect ai (x)"))

    def test_names_and_labels_must_be_strings(self):
        """The review's R2: `label: 1` and `label: "1"` both rendered as `a (1)`."""
        for label in (1, True, 1.5):
            result = self.run_plan([{**self.VARIANTS, "variants": [{"label": label}, {"label": str(label)}]}])
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(f"variant label {label!r} must be a string", result.stderr)
        for name in (1, True, None):
            result = self.run_plan([{"name": name, "repo": "o/r", "cadence": "2h"}])
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(f"canary name {name!r} must be a string", result.stderr)
        self.assertEqual([e["name"] for e in self.matrix([{**self.VARIANTS, "variants": [{"label": "1"}, {"label": "2"}]}])], ["inspect_ai (1)", "inspect_ai (2)"])

    def test_every_generated_job_name_parses_back(self):
        include = self.matrix([self.VARIANTS, {"name": "a.b-c_1", "repo": "o/r", "ref": "main", "cadence": "2h"}])
        for entry in include:
            self.assertEqual(notify.canary_and_part(entry["name"]), (entry["canary"], entry.get("label")))
        # The same label in two canaries is fine.
        other = {**self.VARIANTS, "name": "other", "repo": "o/other"}
        self.assertEqual(len(self.matrix([self.VARIANTS, other])), 4)

    def test_workflow_job_names_are_reserved(self):
        self.assertEqual(self.plan(["inspect_ai"]).returncode, 0)
        for name in ("plan", "notify"):
            result = self.plan(["inspect_ai", name])
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("job names", result.stderr)


class Messages(unittest.TestCase):
    def test_alert_text(self):
        url = "https://github.com/o/r/actions/runs/1/job/2"
        red = notify.alert_text("inspect_ai", True, url, ("UKGovernmentBEIS/inspect_ai", SHA))
        self.assertIn("Canary `inspect_ai` is failing", red)
        self.assertIn(f"<https://github.com/UKGovernmentBEIS/inspect_ai/commit/{SHA}|UKGovernmentBEIS/inspect_ai@{SHA[:10]}>", red)
        self.assertIn(f"<{url}|Run log>", red)
        green = notify.alert_text("inspect_ai", False, url, None)
        self.assertIn("recovered", green)
        self.assertNotIn("Tested", green)


class FailureSet(unittest.TestCase):
    def test_failed_ids_reads_only_marker_lines(self):
        log = "\n".join(
            [
                line("00:00", "canary-failed: tests/a.py::test_one"),
                line("00:00", f"canary-failed: {ESC}[31mtests/b.py::test_two{ESC}[0m"),
                line("00:00", "canary-failed: tests/a.py::test_one"),  # duplicate, dropped
                line("00:00", "FAILED tests/c.py::test_three"),  # not a marker line
                line("00:00", "canary-failed:   "),  # empty id, dropped
            ]
        )
        self.assertEqual(notify.failed_ids(log), ["tests/a.py::test_one", "tests/b.py::test_two"])

    def test_failure_set_of_red_parts(self):
        parts = [job("a (x)", "failure", id=1), job("a (y)", "failure", id=2), job("a (z)", "success", id=3)]
        logs = {1: "canary-failed: t1\ncanary-failed: t2", 2: "no ids here"}
        self.assertEqual(
            notify.failure_set(parts, lambda j: logs.get(j["id"], "")),
            {("x", "t1"), ("x", "t2"), ("y", notify.NO_TEST_IDS)},
        )

    def test_failure_set_without_parts_uses_an_empty_label(self):
        parts = [job("a", "failure", id=1)]
        self.assertEqual(notify.failure_set(parts, lambda j: "canary-failed: t1"), {("", "t1")})

    def test_failure_set_is_unknown_when_a_red_log_cannot_be_read(self):
        parts = [job("a (x)", "failure", id=1), job("a (y)", "failure", id=2)]
        self.assertIsNone(notify.failure_set(parts, lambda j: None if j["id"] == 2 else "canary-failed: t1"))

    def test_hash_matches_whatever_the_order(self):
        one = notify.set_hash({("x", "t1"), ("y", "t2")})
        two = notify.set_hash({("y", "t2"), ("x", "t1")})
        self.assertEqual(one, two)
        self.assertNotEqual(one, notify.set_hash({("x", "t1")}))
        self.assertEqual(notify.set_hash(None), "-")

    def test_records_parse_only_valid_lines(self):
        H = "a" * 64
        log = "\n".join(
            [
                line("00:00", f"canary-notify: inspect_ai red {H} 3 1700000000.5"),
                line("00:00", "canary-notify: other green - 0 -"),
                line("00:00", "canary-notify: bad red tooshort 0 -"),  # malformed hash, ignored
                line("00:00", "inspect_ai: now red"),  # not a record
            ]
        )
        found = notify.records(log)
        self.assertEqual(found["inspect_ai"], notify.Record("inspect_ai", "red", H, 3, "1700000000.5"))
        self.assertEqual(found["other"], notify.Record("other", "green", "-", 0, "-"))
        self.assertNotIn("bad", found)

    def test_record_line_round_trips(self):
        record = notify.Record("a", "red", "b" * 64, 2, "1.0")
        self.assertEqual(notify.records(notify.record_line(record)), {"a": record})

    def test_repeat_line_counts_and_formats_the_time(self):
        run = {"run_started_at": "2026-10-29T20:01:00Z"}  # 4:01 PM in New York
        self.assertEqual(notify.repeat_line(1, run), "Same failures in 1 more run, last at Oct 29, 4:01 PM ET")
        self.assertEqual(notify.repeat_line(3, run), "Same failures in 3 more runs, last at Oct 29, 4:01 PM ET")
        self.assertEqual(notify.repeat_line(1, {"created_at": "2026-10-29T20:01:00Z"}), notify.repeat_line(1, run))


BASE = datetime(2026, 10, 23, 4)


def created(n):
    """Creation time of the n-th run back from the current one, two hours apart."""
    return (BASE - timedelta(hours=2 * n)).strftime("%Y-%m-%dT%H:%M:%SZ")


class FakeServices:
    """Answers notify.request() for the GitHub and Slack calls main() makes."""

    def __init__(self, runs):
        self.runs = runs  # {run_id: [jobs]}, current run first, then older runs
        self.created = {run_id: created(n) for n, run_id in enumerate(runs)}
        self.logs = {}
        self.posts = []
        self.listings = []
        self.raise_on = None  # a substring of a GET url that should fail

    def __call__(self, url, data=None, headers=None, opener=None, read=None):
        if data is not None:
            body = json.loads(data)
            self.posts.append((url, body))
            return json.dumps({"ok": True, "ts": f"{len(self.posts)}.0"})
        if self.raise_on and self.raise_on in url:
            raise notify.urllib.error.URLError("boom")
        parts = urlsplit(url)
        path, query = parts.path.split("/repos/o/r/", 1)[1], parse_qs(parts.query)
        if path.startswith("actions/runs/") and path.endswith("/jobs"):
            jobs = self.runs[int(path.split("/")[2])]
            return json.dumps({"total_count": len(jobs), "jobs": jobs})
        if path.startswith("actions/runs/"):
            return json.dumps({"id": 100, "workflow_id": 7, "created_at": self.created[100]})
        if path == "actions/workflows/7/runs":
            self.listings.append(query)
            bound = query["created"][0].removeprefix("<=")
            runs = [{"id": i, "created_at": c} for i, c in self.created.items() if c <= bound]
            runs.sort(key=lambda r: r["created_at"], reverse=True)
            return json.dumps({"workflow_runs": runs[: int(query["per_page"][0])]})
        if path.startswith("actions/jobs/"):
            return self.logs.get(int(path.split("/")[2]), "")
        raise AssertionError(url)


def red_record(canary, *items, count=0, ts="-"):
    """A `canary-notify:` line for a red canary. `items` are its (label, id)
    failure-set pairs; with none, the canary has one part with no test ids."""
    items = items or (("", notify.NO_TEST_IDS),)
    return notify.record_line(notify.Record(canary, "red", notify.set_hash(set(items)), count, ts))


def notified(run_id, log, logs, id):
    """A completed notify job for a previous run; stores its `log` under `id`."""
    logs[id] = log
    return job("notify", "success", id=id, run_id=run_id)


ENV = {
    "GITHUB_SERVER_URL": "https://github.com",
    "GITHUB_API_URL": "https://api.github.com",
    "GITHUB_REPOSITORY": "o/r",
    "GITHUB_RUN_ID": "100",
    "GH_TOKEN": "t",
}


class Main(unittest.TestCase):
    def run_main(self, runs, env, logs=None):
        fake = FakeServices(runs)
        fake.logs = logs or {}
        out = io.StringIO()
        with mock.patch.dict(os.environ, {**ENV, **env}, clear=True), mock.patch.object(notify, "request", fake), mock.patch.object(notify.time, "sleep"), contextlib.redirect_stdout(out):
            notify.main()
        self.output = out.getvalue()
        return fake.posts

    def records(self):
        """The `canary-notify:` records main() printed to its log, by canary."""
        return notify.records(self.output)

    def test_turning_red_posts_an_alert_and_a_threaded_reply(self):
        failing_steps = CANARY_STEPS + [step("Test", "failure", "00:09", "06:31", 5)]
        logs = {2: canary_log(test_output=["FAILED tests/t.py::test_x - boom", "canary-failed: tests/t.py::test_x"]), 6: canary_log(sha=OLD_SHA, versions=(("anyio", "4.10.0"),))}
        runs = {
            100: [job("plan", "success", id=1, run_id=100), job("inspect_ai", "failure", id=2, run_id=100, steps=failing_steps), job("other", "failure", id=3, run_id=100), job("notify", None, id=4, run_id=100)],
            # `other` was already red with the same failures last run, so only inspect_ai alerts.
            99: [job("plan", "success", id=5, run_id=99), job("inspect_ai", "success", id=6, run_id=99, steps=CANARY_STEPS), job("other", "failure", id=7, run_id=99), notified(99, red_record("other"), logs, 8)],
        }
        posts = self.run_main(runs, {"SLACK_BOT_TOKEN": "xoxb", "SLACK_CHANNEL_ID": "C1"}, logs)
        self.assertEqual(len(posts), 2)
        (url, alert), (_, reply) = posts
        self.assertEqual(url, "https://slack.com/api/chat.postMessage")
        self.assertEqual(alert["channel"], "C1")
        self.assertIn("Canary `inspect_ai` is failing", alert["text"])
        self.assertIn("https://github.com/o/r/actions/runs/100/job/2", alert["text"])
        self.assertEqual(reply["thread_ts"], "1.0")
        self.assertIn("tests/t.py::test_x", reply["text"])
        self.assertIn("anyio 4.10.0 → 4.11.0", reply["text"])
        self.assertIn("https://github.com/o/r/actions/runs/99/job/6", reply["text"])
        # One record per canary with a result: inspect_ai red (count 0, its ts), other red (same set, count 1).
        self.assertEqual(self.records()["inspect_ai"], notify.Record("inspect_ai", "red", notify.set_hash({("", "tests/t.py::test_x")}), 0, "1.0"))
        self.assertEqual(self.records()["other"], notify.Record("other", "red", notify.set_hash({("", notify.NO_TEST_IDS)}), 1, "-"))

    def test_staying_red_or_green_posts_nothing(self):
        logs = {}
        runs = {
            100: [job("a", "failure", run_id=100), job("b", "success", run_id=100), job("c", "cancelled", run_id=100)],
            99: [job("a", "failure", run_id=99), job("b", "success", run_id=99), job("c", "success", run_id=99), notified(99, red_record("a"), logs, 90)],
        }
        self.assertEqual(self.run_main(runs, {"SLACK_WEBHOOK_URL": "https://hooks.example/x"}, logs), [])
        # a stays red with the same failures (count rises); b stays green; c didn't run, so no record.
        self.assertEqual(self.records()["a"], notify.Record("a", "red", notify.set_hash({("", notify.NO_TEST_IDS)}), 1, "-"))
        self.assertEqual(self.records()["b"], notify.Record("b", "green", "-", 0, "-"))
        self.assertNotIn("c", self.records())

    def test_recovery_through_the_webhook(self):
        runs = {100: [job("a", "success", run_id=100)], 99: [job("a", "skipped", run_id=99)], 98: [job("a", "failure", run_id=98)]}
        posts = self.run_main(runs, {"SLACK_BOT_TOKEN": "xoxb", "SLACK_WEBHOOK_URL": "https://hooks.example/x"})
        self.assertEqual(len(posts), 1)
        url, body = posts[0]
        self.assertEqual(url, "https://hooks.example/x")
        self.assertIn("Canary `a` recovered", body["text"])
        self.assertNotIn("channel", body)

    def test_repost_alerts_an_earlier_runs_red_canaries_without_comparing(self):
        failing_steps = CANARY_STEPS + [step("Test", "failure", "00:09", "06:31", 5)]
        runs = {
            100: [job("notify", None, id=9, run_id=100)],
            99: [job("plan", "success", id=5, run_id=99), job("inspect_ai", "failure", id=6, run_id=99, steps=failing_steps), job("b", "success", id=7, run_id=99)],
            98: [job("inspect_ai", "failure", id=3, run_id=98), job("b", "success", id=4, run_id=98)],
            97: [job("inspect_ai", "success", id=1, run_id=97, steps=CANARY_STEPS)],
        }
        logs = {6: canary_log(test_output=["FAILED tests/t.py::test_x - boom"]), 1: canary_log(sha=OLD_SHA, versions=(("anyio", "4.10.0"),))}
        posts = self.run_main(runs, {"SLACK_BOT_TOKEN": "xoxb", "SLACK_CHANNEL_ID": "C1", "REPOST_RUN": "99"}, logs)
        # Still red since run 98, but a re-post alerts anyway; green canaries are skipped.
        self.assertEqual(len(posts), 2)
        (_, alert), (_, reply) = posts
        self.assertIn("Canary `inspect_ai` is failing", alert["text"])
        self.assertIn("actions/runs/99/job/6", alert["text"])
        self.assertIn("tests/t.py::test_x", reply["text"])

    def test_repost_rejects_anything_but_a_run_id(self):
        posts = self.run_main({100: []}, {"SLACK_WEBHOOK_URL": "https://hooks.example/x", "REPOST_RUN": "99; rm -rf /"})
        self.assertEqual(posts, [])

    def test_planning_failure_posts_one_plain_message(self):
        runs = {
            100: [job("plan", "failure", id=1, run_id=100), job("matrix.name", "skipped", id=2, run_id=100)],
            99: [job("plan", "success", id=3, run_id=99), job("inspect_ai", "success", id=4, run_id=99)],
        }
        posts = self.run_main(runs, {"SLACK_WEBHOOK_URL": "https://hooks.example/x"})
        self.assertEqual(len(posts), 1)
        text = posts[0][1]["text"]
        self.assertIn("Canary planning failed, so no canaries ran.", text)
        self.assertIn("https://github.com/o/r/actions/runs/100/job/1", text)
        self.assertNotIn("`plan`", text)

    def test_planning_recovery_is_not_a_canary_recovery(self):
        runs = {
            100: [job("plan", "success", run_id=100), job("inspect_ai", "success", run_id=100)],
            99: [job("plan", "failure", run_id=99), job("matrix.name", "skipped", run_id=99)],
            98: [job("plan", "success", run_id=98), job("inspect_ai", "success", run_id=98)],
        }
        self.assertEqual(self.run_main(runs, {"SLACK_WEBHOOK_URL": "https://hooks.example/x"}), [])

    def history(self, total, nightly_at, current, other_jobs=True):
        """The current run plus `total` earlier runs; `nightly` ran only in the run
        `nightly_at` back, where it failed and its notify job (id 6000) recorded it."""
        runs = {100: [job("plan", "success", run_id=100), job("nightly", current, id=1, run_id=100)]}
        for n in range(1, total + 1):
            jobs = [job("plan", "success", run_id=1000 + n)]
            if other_jobs:
                jobs.append(job("hourly", "success", run_id=1000 + n))
            if n == nightly_at:
                jobs.append(job("nightly", "failure", id=5000, run_id=1000 + n))
                jobs.append(job("notify", "success", id=6000, run_id=1000 + n))
            runs[1000 + n] = jobs
        return runs

    # The record a nightly's notify job wrote when it failed with no test ids.
    NIGHTLY_RED = {6000: red_record("nightly")}

    def test_history_pages_back_past_100_runs(self):
        # Still red with the same failures: the earlier failure is 130 runs back, beyond the first page.
        fake_posts = self.run_main(self.history(150, 130, "failure"), {"SLACK_WEBHOOK_URL": "https://hooks.example/x"}, self.NIGHTLY_RED)
        self.assertEqual(fake_posts, [])
        # Recovered: the same history, now green, alerts.
        posts = self.run_main(self.history(150, 130, "success"), {"SLACK_WEBHOOK_URL": "https://hooks.example/x"})
        self.assertEqual(len(posts), 1)
        self.assertIn("Canary `nightly` recovered", posts[0][1]["text"])

    def test_history_pages_by_creation_time(self):
        fake = FakeServices(self.history(150, 130, "failure"))
        fake.logs = self.NIGHTLY_RED
        with mock.patch.dict(os.environ, {**ENV, "SLACK_WEBHOOK_URL": "https://hooks.example/x"}, clear=True), mock.patch.object(notify, "request", fake):
            notify.main()
        bounds = [q["created"][0] for q in fake.listings]
        self.assertEqual(bounds[0], f"<={created(0)}")
        # The first page holds the current run and 99 earlier ones; the next starts at the oldest of those.
        self.assertEqual(bounds[1], f"<={created(99)}")
        self.assertTrue(all("page" not in q for q in fake.listings))

    def test_exhausted_history_means_a_new_canary(self):
        posts = self.run_main(self.history(150, None, "failure"), {"SLACK_WEBHOOK_URL": "https://hooks.example/x"})
        self.assertEqual(len(posts), 1)
        self.assertIn("Canary `nightly` is failing", posts[0][1]["text"])
        self.assertEqual(self.run_main(self.history(150, None, "success"), {"SLACK_WEBHOOK_URL": "https://hooks.example/x"}), [])

    def test_no_result_within_the_history_limit_means_a_new_canary(self):
        """The delta review's R2: past the limit, a new canary's first failure still alerts."""
        total = notify.HISTORY_LIMIT + 50
        fake = FakeServices(self.history(total, None, "failure"))
        with mock.patch.dict(os.environ, {**ENV, "SLACK_WEBHOOK_URL": "https://hooks.example/x"}, clear=True), mock.patch.object(notify, "request", fake):
            notify.main()
        self.assertEqual(len(fake.posts), 1)
        self.assertIn("Canary `nightly` is failing", fake.posts[0][1]["text"])
        # Its second failure finds the first, with the same failures, and stays quiet.
        runs = self.history(total, 1, "failure")
        self.assertEqual(self.run_main(runs, {"SLACK_WEBHOOK_URL": "https://hooks.example/x"}, self.NIGHTLY_RED), [])
        # A result beyond the limit isn't searched for: that canary counts as new too.
        self.assertEqual(len(self.run_main(self.history(total, total, "failure"), {"SLACK_WEBHOOK_URL": "https://hooks.example/x"})), 1)
        self.assertEqual(self.run_main(self.history(total, total, "success"), {"SLACK_WEBHOOK_URL": "https://hooks.example/x"}), [])

    BOT = {"SLACK_BOT_TOKEN": "xoxb", "SLACK_CHANNEL_ID": "C1"}
    WEBHOOK = {"SLACK_WEBHOOK_URL": "https://hooks.example/x"}

    def test_parts_alert_once_with_a_section_per_failing_part(self):
        failing_steps = CANARY_STEPS + [step("Test", "failure", "00:09", "06:31", 5)]
        runs = {
            100: [
                job("plan", "success", id=1, run_id=100),
                job("a (x)", "success", id=11, run_id=100),
                job("a (y)", "failure", id=12, run_id=100, steps=failing_steps),
                job("a (z)", "timed_out", id=13, run_id=100, steps=failing_steps),
                job("b", "success", id=14, run_id=100),
            ],
            99: [job("a (x)", "success", id=21, run_id=99), job("a (y)", "success", id=22, run_id=99), job("a (z)", "cancelled", id=23, run_id=99), job("b", "success", id=24, run_id=99)],
            98: [job("a (x)", "success", id=31, run_id=98), job("a (y)", "success", id=32, run_id=98), job("a (z)", "success", id=33, run_id=98)],
        }
        logs = {
            12: canary_log(versions=(("anyio", "4.11.0"),), test_output=["FAILED tests/y.py::test_y - boom"]),
            13: canary_log(versions=(("trio", "0.31.0"),), test_output=["still running"]),
            22: canary_log(sha=OLD_SHA, versions=(("anyio", "4.10.0"),)),
            33: canary_log(sha=OLD_SHA, versions=(("trio", "0.30.0"),)),
        }
        posts = self.run_main(runs, self.BOT, logs)
        self.assertEqual(len(posts), 2)
        (_, alert), (_, reply) = posts
        self.assertIn("Canary `a` is failing on the newest releases (`y`, `z`).", alert["text"])
        self.assertIn(f"UKGovernmentBEIS/inspect_ai@{SHA[:10]}", alert["text"])
        self.assertIn("<https://github.com/o/r/actions/runs/100|Run log>", alert["text"])  # the run, listing every part
        self.assertEqual(reply["thread_ts"], "1.0")
        text = reply["text"]
        self.assertTrue(text.startswith(f"_{notify.UNTRUSTED}_"))
        self.assertIn("*Failing parts* (2 of 3): `y`, `z`", text)
        y, z = text.split("*Part* `y`")[1].split("*Part* `z`")
        self.assertIn("(<https://github.com/o/r/actions/runs/100/job/12|Run log>)", y)
        self.assertIn("tests/y.py::test_y", y)
        self.assertIn("anyio 4.10.0 → 4.11.0", y)
        self.assertIn("actions/runs/99/job/22", y)  # y's last green
        self.assertIn("still running", z)
        self.assertIn("trio 0.30.0 → 0.31.0", z)
        self.assertIn("actions/runs/98/job/33", z)  # z didn't run in 99
        self.assertNotIn("anyio", z)

    def test_parts_through_the_webhook(self):
        runs = {100: [job("a (x)", "success", run_id=100), job("a (y)", "failure", id=2, run_id=100)], 99: [job("a (x)", "success", run_id=99)]}
        posts = self.run_main(runs, self.WEBHOOK)
        self.assertEqual(len(posts), 1)
        self.assertIn("Canary `a` is failing on the newest releases (`y`).", posts[0][1]["text"])

    def test_the_alert_names_at_most_max_parts(self):
        runs = {100: [job(f"a (p{i}-{'x' * 60})", "failure", id=i, run_id=100) for i in range(20)], 99: [job("a (p0)", "success", run_id=99)]}
        posts = self.run_main(runs, self.BOT)
        self.assertEqual(len(posts), 2)
        alert, reply = posts[0][1]["text"], posts[1][1]["text"]
        self.assertIn("and 14 more).", alert)
        self.assertEqual(alert.count("`p"), notify.MAX_PARTS)
        self.assertLess(len(alert), 1000)
        self.assertIn("14 more failing parts not shown: see <https://github.com/o/r/actions/runs/100|the run>", reply)

    def test_a_canary_that_stays_red_with_a_different_failing_part_posts(self):
        # Red both runs, but the failing part changed, so the failure set changed: post.
        logs = {}
        runs = {
            100: [job("a (x)", "success", id=11, run_id=100), job("a (y)", "failure", id=12, run_id=100)],
            99: [job("a (x)", "failure", id=21, run_id=99), job("a (y)", "success", id=22, run_id=99), notified(99, red_record("a", ("x", notify.NO_TEST_IDS)), logs, 29)],
        }
        posts = self.run_main(runs, self.WEBHOOK, logs)
        self.assertEqual(len(posts), 1)
        self.assertIn("Canary `a` is failing on the newest releases (`y`).", posts[0][1]["text"])
        self.assertEqual(self.records()["a"], notify.Record("a", "red", notify.set_hash({("y", notify.NO_TEST_IDS)}), 0, "-"))
        # A part that didn't run leaves the canary green, which stays quiet after green.
        runs = {100: [job("a (x)", "success", run_id=100), job("a (y)", "cancelled", run_id=100)], 99: [job("a (x)", "success", run_id=99), job("a (y)", "success", run_id=99)]}
        self.assertEqual(self.run_main(runs, self.WEBHOOK), [])

    def test_a_part_added_between_runs(self):
        before = [job("plan", "success", run_id=99), job("a (x)", "success", id=21, run_id=99)]
        self.assertEqual(self.run_main({100: [job("a (x)", "success", run_id=100), job("a (new)", "success", run_id=100)], 99: before}, self.WEBHOOK), [])
        runs = {100: [job("a (x)", "success", id=11, run_id=100), job("a (new)", "failure", id=12, run_id=100)], 99: before}
        posts = self.run_main(runs, self.BOT, {12: canary_log(test_output=["FAILED tests/n.py::test_n"])})
        self.assertEqual(len(posts), 2)
        self.assertIn("(`new`)", posts[0][1]["text"])
        reply = posts[1][1]["text"]
        self.assertIn("*Failing parts* (1 of 2): `new`", reply)
        self.assertIn("no earlier passing run found", reply)

    def test_a_part_removed_between_runs(self):
        before = [job("a (x)", "failure", id=21, run_id=99), job("a (y)", "success", id=22, run_id=99)]
        posts = self.run_main({100: [job("a (y)", "success", id=11, run_id=100)], 99: before}, self.WEBHOOK)
        self.assertEqual(len(posts), 1)
        self.assertIn("Canary `a` recovered", posts[0][1]["text"])
        self.assertIn("<https://github.com/o/r/actions/runs/100/job/11|Run log>", posts[0][1]["text"])
        # Both parts failed last run; now only one fails, so the failure set shrank: post.
        logs = {}
        items = (("x", notify.NO_TEST_IDS), ("y", notify.NO_TEST_IDS))
        before = [job("a (x)", "failure", id=31, run_id=99), job("a (y)", "failure", id=32, run_id=99), notified(99, red_record("a", *items), logs, 39)]
        posts = self.run_main({100: [job("a (y)", "failure", run_id=100)], 99: before}, self.WEBHOOK, logs)
        self.assertEqual(len(posts), 1)
        self.assertIn("Canary `a` is failing on the newest releases (`y`).", posts[0][1]["text"])

    def test_a_canary_split_into_parts_keeps_its_name(self):
        now = [job("a (x)", "failure", id=11, run_id=100), job("a (y)", "success", id=12, run_id=100)]
        # The split canary is still grouped under `a`; it was red and stays red, but the
        # failing part's label changed the failure set, so it posts once.
        logs = {}
        posts = self.run_main({100: now, 99: [job("a", "failure", id=20, run_id=99), notified(99, red_record("a"), logs, 29)]}, self.WEBHOOK, logs)
        self.assertEqual(len(posts), 1)
        self.assertIn("Canary `a` is failing on the newest releases (`x`).", posts[0][1]["text"])
        posts = self.run_main({100: now, 99: [job("a", "success", id=21, run_id=99)]}, self.BOT)
        self.assertEqual(len(posts), 2)
        self.assertIn("Canary `a` is failing", posts[0][1]["text"])
        self.assertIn("no earlier passing run found", posts[1][1]["text"])  # versions compare part to part

    def test_test_message_on_both_paths(self):
        posts = self.run_main({}, {"TEST_SLACK": "true", "SLACK_WEBHOOK_URL": "https://hooks.example/x"})
        self.assertEqual([url for url, _ in posts], ["https://hooks.example/x"])
        posts = self.run_main({}, {"TEST_SLACK": "true", "SLACK_BOT_TOKEN": "xoxb", "SLACK_CHANNEL_ID": "C1"})
        self.assertEqual(len(posts), 2)
        self.assertEqual(posts[1][1]["thread_ts"], "1.0")

    def test_no_credentials_posts_nothing(self):
        self.assertEqual(self.run_main({}, {"TEST_SLACK": "true"}), [])

    def test_a_red_nightly_canary_rechecked_every_2_hours(self):
        """Nightly red, then 2-hour re-checks red, red, green: one alert, then one
        recovery. Each run's notify records feed the next, so the repeated reds are quiet."""
        posts = []
        for now in range(len(RECHECK_TIMELINE)):
            runs = timeline_runs(now)
            posts.append([body["text"] for _, body in self.run_main(runs, self.WEBHOOK, timeline_logs(runs))])
        self.assertEqual([len(p) for p in posts], [0, 0, 1, 0, 0, 1, 0, 0])
        self.assertIn("Canary `n` is failing", posts[2][0])
        self.assertIn("Canary `n` recovered", posts[5][0])

    def red_again(self, now_ids, record, env, logs_before=()):
        """A canary red this run with `now_ids`, red last run with `record`;
        returns the posts. `logs_before` are extra current-run log lines."""
        logs = {12: canary_log(test_output=[f"canary-failed: {i}" for i in now_ids] + list(logs_before))}
        runs = {
            100: [job("a", "failure", id=12, run_id=100)],
            99: [job("a", "failure", id=22, run_id=99), notified(99, record, logs, 29)],
        }
        return self.run_main(runs, env, logs)

    def test_the_same_failures_edit_the_last_post_with_a_count(self):
        posts = self.red_again(["t1", "t2"], red_record("a", ("", "t1"), ("", "t2"), count=2, ts="1700000000.5"), self.BOT)
        self.assertEqual(len(posts), 1)  # a single chat.update, no new post
        url, body = posts[0]
        self.assertEqual(url, "https://slack.com/api/chat.update")
        self.assertEqual(body["ts"], "1700000000.5")
        self.assertIn("Canary `a` is failing", body["text"])
        self.assertIn("Same failures in 3 more runs, last at ", body["text"])
        self.assertEqual(self.records()["a"], notify.Record("a", "red", notify.set_hash({("", "t1"), ("", "t2")}), 3, "1700000000.5"))

    def test_an_added_failure_posts_a_new_alert(self):
        posts = self.red_again(["t1", "t2"], red_record("a", ("", "t1"), ts="1.0"), self.BOT)
        self.assertEqual(len(posts), 2)  # a fresh alert and its reply, not an edit
        self.assertEqual(posts[0][0], "https://slack.com/api/chat.postMessage")
        self.assertIn("Canary `a` is failing", posts[0][1]["text"])
        self.assertEqual(self.records()["a"], notify.Record("a", "red", notify.set_hash({("", "t1"), ("", "t2")}), 0, "1.0"))

    def test_a_removed_failure_posts_a_new_alert(self):
        posts = self.red_again(["t1"], red_record("a", ("", "t1"), ("", "t2"), ts="1.0"), self.BOT)
        self.assertEqual(len(posts), 2)
        self.assertEqual(self.records()["a"].count, 0)
        self.assertEqual(self.records()["a"].hash, notify.set_hash({("", "t1")}))

    def test_an_unreadable_record_posts_the_red_results(self):
        # Red last run too, but that run has no completed notify job: post, with a warning.
        runs = {100: [job("a", "failure", id=12, run_id=100)], 99: [job("a", "failure", id=22, run_id=99)]}
        posts = self.run_main(runs, self.WEBHOOK)
        self.assertEqual(len(posts), 1)
        self.assertIn("Canary `a` is failing", posts[0][1]["text"])
        self.assertEqual(self.records()["a"].count, 0)
        self.assertIn("::warning::a: its last run has no completed notify job", self.output)

    def test_a_malformed_record_is_ignored(self):
        logs = {}
        runs = {
            100: [job("a", "failure", id=12, run_id=100)],
            99: [job("a", "failure", id=22, run_id=99), notified(99, "canary-notify: a red not-a-hash 0 -", logs, 29)],
        }
        posts = self.run_main(runs, self.WEBHOOK, logs)
        self.assertEqual(len(posts), 1)  # the line didn't parse, so the record is unknown
        self.assertIn("::warning::a: no record in its last notify log", self.output)

    def test_an_unreadable_history_posts_red_and_stays_quiet_on_green(self):
        for current, want in (("failure", 1), ("success", 0)):
            with self.subTest(current=current):
                fake = FakeServices({100: [job("a", current, id=1, run_id=100)], 99: [job("a", "failure", run_id=99)]})
                fake.raise_on = "workflows/7/runs"
                out = io.StringIO()
                with mock.patch.dict(os.environ, {**ENV, **self.WEBHOOK}, clear=True), mock.patch.object(notify, "request", fake), mock.patch.object(notify.time, "sleep"), contextlib.redirect_stdout(out):
                    notify.main()
                self.assertEqual(len(fake.posts), want)
                self.assertIn("::warning::history for a", out.getvalue())
                self.assertEqual(notify.records(out.getvalue())["a"].state, "red" if current == "failure" else "green")


# Scheduled runs, oldest first: which canaries each ran, and how they ended.
# `n` is nightly, `fast` every 2 hours; while `n` is red, the 2-hour runs
# re-check it.
RECHECK_TIMELINE = [
    ("nightly", {"fast": "success", "n": "success"}),
    ("2h", {"fast": "success"}),
    ("nightly", {"fast": "success", "n": "failure"}),  # breaks
    ("2h", {"fast": "success", "n": "failure"}),  # re-checked: still red
    ("2h", {"fast": "success", "n": "failure"}),
    ("2h", {"fast": "success", "n": "success"}),  # fixed
    ("2h", {"fast": "success"}),  # back to nightly
    ("nightly", {"fast": "success", "n": "success"}),
]


def timeline_runs(now, current=None):
    """FakeServices runs with RECHECK_TIMELINE[now] as the current run (or
    `current` jobs instead), and the earlier ones before it. Each run has a
    notify job (id run_id*10+9) that its own records go under."""
    def jobs(results, run_id):
        return (
            [job("plan", "success", id=run_id * 10, run_id=run_id)]
            + [job(name, conclusion, id=run_id * 10 + i, run_id=run_id) for i, (name, conclusion) in enumerate(results.items(), 1)]
            + [job("notify", "success", id=run_id * 10 + 9, run_id=run_id)]
        )

    runs = {100: jobs(RECHECK_TIMELINE[now][1], 100) if current is None else current}
    for i in reversed(range(now)):
        runs[i + 1] = jobs(RECHECK_TIMELINE[i][1], i + 1)
    return runs


def timeline_logs(runs):
    """The notify log of each earlier run: the records notify wrote for it (no
    test ids, so each red canary's set is just its one no-ids item)."""
    logs = {}
    for run_id, jobs in runs.items():
        if run_id == 100:  # the current run's notify is in progress
            continue
        notify_job = next(j for j in jobs if j["name"] == "notify")
        lines = []
        for name, parts in notify.by_canary(jobs).items():
            state = notify.canary_state(parts)
            if state == "green":
                lines.append(notify.record_line(notify.Record(name, "green", "-", 0, "-")))
            elif state == "red":
                lines.append(red_record(name))
        logs[notify_job["id"]] = "\n".join(lines)
    return logs


@contextlib.contextmanager
def fake_api(fake):
    """`fake` (a FakeServices) as a local GitHub API for the planner, which
    runs in its own process; yields the API URL and the paths requested."""
    paths = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            paths.append(self.path)
            try:
                status, body = 200, fake(f"http://api{self.path}").encode()
            except Exception:
                status, body = 500, b"{}"
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", paths
    finally:
        server.shutdown()
        server.server_close()


class Recheck(unittest.TestCase):
    """On the 2-hour schedule, nightly canaries whose latest result is red run too."""

    run_plan = Planner.run_plan

    TWO_HOURS = "0 */2 * * *"
    NIGHTLY = "30 5 * * *"

    def entry(self, name, cadence, variants=None):
        entry = {"name": name, "repo": f"o/{name}", "ref": "main", "cadence": cadence, "test": "pytest"}
        return entry | ({"variants": [{"label": label} for label in variants]} if variants else {})

    def planned(self, entries, runs, schedule=TWO_HOURS, **env):
        """Job names the planner chooses with `runs` as the history, the
        planner's stderr, and the API paths it requested."""
        with fake_api(FakeServices(runs)) as (api, paths):
            env = {"SCHEDULE": schedule, "GITHUB_API_URL": api, "GITHUB_REPOSITORY": "o/r", "GITHUB_RUN_ID": "100", "GH_TOKEN": "t"} | env
            result = self.run_plan(entries, **env)
        self.assertEqual(result.returncode, 0, result.stderr)
        return [job["name"] for job in json.loads(result.stdout)["include"]], result.stderr, paths

    ENTRIES = [
        ("fast", "2h"),
        ("red", "nightly"),
        ("green", "nightly"),
        ("fixed", "nightly"),
        ("parts", "nightly", ["x", "y"]),
        ("new", "nightly"),
    ]
    RUNS = {
        100: [job("plan", None, run_id=100)],  # this run, planning
        99: [job("fast", "success", run_id=99), job("red", "failure", run_id=99), job("fixed", "success", run_id=99)],  # a 2-hour run that re-checked two
        98: [job("fast", "cancelled", run_id=98), job("parts (x)", "failure", run_id=98)],  # a re-run that only got one part done
        97: [job(name, "failure" if name != "green" else "success", run_id=97) for name in ("fast", "red", "green", "fixed", "parts (x)", "parts (y)")],
    }

    def entries(self):
        return [self.entry(*e) for e in self.ENTRIES]

    def test_red_nightly_canaries_run_on_the_2_hour_schedule(self):
        names, log, _ = self.planned(self.entries(), self.RUNS)
        # `fixed` recovered on its last re-check; `new` has no result yet.
        self.assertEqual(names, ["fast", "red", "parts (x)", "parts (y)"])
        self.assertIn("Re-checking red nightly canaries: parts, red", log)
        self.assertIn("::warning::No result for new in the last 30 scheduled runs", log)
        self.assertEqual(log.splitlines()[-1], "4")

    def test_a_canary_is_red_if_any_part_is(self):
        runs = {100: [], 99: [job("parts (x)", "success", run_id=99), job("parts (y)", "failure", run_id=99)]}
        names, _, _ = self.planned([self.entry("parts", "nightly", ["x", "y"])], runs)
        self.assertEqual(names, ["parts (x)", "parts (y)"])
        runs = {100: [], 99: [job("parts (x)", "success", run_id=99), job("parts (y)", "skipped", run_id=99)]}
        self.assertEqual(self.planned([self.entry("parts", "nightly", ["x", "y"])], runs)[0], [])

    def test_other_selections_are_unchanged_and_read_nothing(self):
        cases = [
            ({"schedule": self.NIGHTLY}, ["fast", "red", "green", "fixed", "parts (x)", "parts (y)", "new"]),
            ({"schedule": "", "ONLY": "green"}, ["green"]),
            ({"schedule": "", "CHANGED_FILES": "canaries/green.yml"}, ["green"]),
            ({"schedule": ""}, ["fast", "red", "green", "fixed", "parts (x)", "parts (y)", "new"]),
        ]
        for env, expected in cases:
            with self.subTest(env=env):
                names, _, paths = self.planned(self.entries(), self.RUNS, **env)
                self.assertEqual(names, expected)
                self.assertEqual(paths, [])

    def test_an_unreadable_history_rechecks_nothing(self):
        fake = FakeServices(self.RUNS)
        fake.runs = {}  # every request for jobs fails
        with fake_api(fake) as (api, _):
            env = {"SCHEDULE": self.TWO_HOURS, "GITHUB_API_URL": api, "GITHUB_REPOSITORY": "o/r", "GITHUB_RUN_ID": "100", "GH_TOKEN": "t"}
            result = self.run_plan(self.entries(), **env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([j["name"] for j in json.loads(result.stdout)["include"]], ["fast"])
        self.assertIn("::warning::Couldn't read red's latest result", result.stderr)
        # No API at all.
        env |= {"GITHUB_API_URL": "http://127.0.0.1:9"}
        result = self.run_plan(self.entries(), **env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([j["name"] for j in json.loads(result.stdout)["include"]], ["fast"])
        self.assertIn("::warning::Couldn't read this run", result.stderr)

    def test_the_history_searched_is_bounded(self):
        runs = {100: []} | {1000 + n: [job("fast", "success", run_id=1000 + n)] for n in range(1, 200)}
        names, log, paths = self.planned([self.entry("fast", "2h"), self.entry("new", "nightly"), self.entry("old", "nightly")], runs)
        self.assertEqual(names, ["fast"])
        jobs = [p for p in paths if p.endswith("/jobs") or "/jobs?" in p]
        listings = [p for p in paths if "/workflows/" in p]
        # Each earlier run's jobs are read once, whichever canaries look at them.
        self.assertEqual(len(jobs), 30)
        self.assertEqual(len(set(jobs)), 30)
        self.assertLessEqual(len(listings), 2)
        self.assertTrue(all("per_page=31" in p for p in listings))
        self.assertIn("No result for old", log)

    def test_the_planner_rechecks_what_the_notifier_calls_red(self):
        """Along RECHECK_TIMELINE, each 2-hour run includes `n` exactly while
        its latest result is red."""
        entries = [self.entry("fast", "2h"), self.entry("n", "nightly")]
        for now, (schedule, results) in enumerate(RECHECK_TIMELINE):
            if schedule != "2h":
                continue
            with self.subTest(run=now):
                names, _, _ = self.planned(entries, timeline_runs(now, current=[]))
                self.assertEqual("n" in names, "n" in results)


if __name__ == "__main__":
    unittest.main()


class SlackFallback(unittest.TestCase):
    def test_a_failing_bot_post_falls_back_to_the_webhook(self):
        calls = []

        def fake_request(url, data=None, headers=None):
            calls.append(url)
            if "chat.postMessage" in url:
                return json.dumps({"ok": False, "error": "missing_scope"}).encode()
            return b"ok"

        slack = notify.Slack("xoxb-test", "C123", "https://hooks.example/abc")
        with mock.patch.object(notify, "request", fake_request), mock.patch.object(notify.time, "sleep"):
            # No ts comes back, so main() posts no thread reply under it.
            self.assertIsNone(slack.post("alert"))
            self.assertIsNone(slack.post("next alert"))
        self.assertEqual(
            calls,
            ["https://slack.com/api/chat.postMessage", "https://hooks.example/abc", "https://hooks.example/abc"],
        )

    def test_a_failing_bot_post_without_a_webhook_raises(self):
        slack = notify.Slack("xoxb-test", "C123", None)
        fake = lambda *a, **k: json.dumps({"ok": False, "error": "missing_scope"}).encode()
        with mock.patch.object(notify, "request", fake):
            with self.assertRaises(RuntimeError):
                slack.post("alert")


class SlackUpdate(unittest.TestCase):
    def test_update_edits_the_message_through_the_bot_token(self):
        calls = []

        def fake_request(url, data=None, headers=None):
            calls.append((url, json.loads(data)))
            return json.dumps({"ok": True}).encode()

        slack = notify.Slack("xoxb-test", "C123", "https://hooks.example/abc")
        with mock.patch.object(notify, "request", fake_request):
            slack.update("1700000000.5", "edited text")
        url, body = calls[0]
        self.assertEqual(url, "https://slack.com/api/chat.update")
        self.assertEqual((body["channel"], body["ts"], body["text"]), ("C123", "1700000000.5", "edited text"))

    def test_update_is_a_no_op_on_the_webhook_path(self):
        calls = []
        slack = notify.Slack(None, None, "https://hooks.example/abc")
        with mock.patch.object(notify, "request", lambda *a, **k: calls.append(a)):
            slack.update("1.0", "edited text")
        self.assertEqual(calls, [])

    def test_a_failing_update_warns_and_returns(self):
        fake = lambda *a, **k: json.dumps({"ok": False, "error": "message_not_found"}).encode()
        slack = notify.Slack("xoxb-test", "C123", None)
        out = io.StringIO()
        with mock.patch.object(notify, "request", fake), contextlib.redirect_stdout(out):
            slack.update("1.0", "edited text")  # does not raise
        self.assertIn("::warning::chat.update failed: message_not_found", out.getvalue())


class FailedTestsStep(unittest.TestCase):
    """The inline `Failed tests` script in canary.yml, run on sample JUnit XML."""

    def script(self):
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, ".github", "workflows", "canary.yml")
        with open(path) as f:
            text = f.read()
        body = text.split("<<'PY'\n", 1)[1].split("\n          PY\n", 1)[0]
        return textwrap.dedent(body)

    def run_script(self, files):
        """Run the script with `files` written to $RUNNER_TEMP/junit (None: no junit dir)."""
        tmp = tempfile.mkdtemp()
        if files is not None:
            junit = os.path.join(tmp, "junit")
            os.makedirs(junit)
            for name, content in files.items():
                with open(os.path.join(junit, name), "w") as f:
                    f.write(content)
        return subprocess.run([sys.executable, "-I", "-"], input=self.script(), text=True, capture_output=True, env={"RUNNER_TEMP": tmp})

    PASS = '<testsuite><testcase classname="tests.test_a" name="test_ok"/></testsuite>'
    FAIL = '<testsuites><testsuite><testcase classname="tests.test_a" name="test_bad"><failure>boom</failure></testcase></testsuite></testsuites>'
    ERROR = '<testsuite><testcase classname="tests.test_b" name="test_err"><error>fixture</error></testcase></testsuite>'
    NO_CLASS = '<testsuite><testcase classname="" name="test_top"><failure>no</failure></testcase></testsuite>'

    def test_reports_failures_errors_counts_and_bad_files(self):
        result = self.run_script(
            {"pytest.xml": self.FAIL, "extra.xml": self.ERROR, "pass.xml": self.PASS, "top.xml": self.NO_CLASS, "broken.xml": "<not closed"}
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = result.stdout.splitlines()
        self.assertIn("canary-junit: pytest.xml 1 1", lines)
        self.assertIn("canary-failed: tests.test_a::test_bad", lines)
        self.assertIn("canary-junit: extra.xml 1 1", lines)
        self.assertIn("canary-failed: tests.test_b::test_err", lines)  # an <error> counts too
        self.assertIn("canary-junit: pass.xml 1 0", lines)  # a pass adds no canary-failed line
        self.assertIn("canary-junit: top.xml 1 1", lines)
        self.assertIn("canary-failed: test_top", lines)  # empty classname -> just the name
        self.assertIn("canary-junit: broken.xml unreadable", lines)  # a bad file never fails the job
        self.assertNotIn("test_ok", result.stdout)
        # Every id the step prints is a line notify.py reads back.
        ids = [notify.clean(line) for line in lines]
        self.assertEqual(set(notify.failed_ids("\n".join(ids))), {"tests.test_a::test_bad", "tests.test_b::test_err", "test_top"})

    def test_no_junit_directory_prints_nothing(self):
        result = self.run_script(None)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")
