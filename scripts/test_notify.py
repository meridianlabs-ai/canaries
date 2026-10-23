"""Tests for notify.py: python3 -m unittest discover -s scripts"""

import io
import json
import os
import subprocess
import sys
import tempfile
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

    def test_only_changes_alert(self):
        red, green = job("c", "failure"), job("c", "success")
        self.assertTrue(notify.changed(red, green))
        self.assertTrue(notify.changed(green, red))
        self.assertFalse(notify.changed(red, red))
        self.assertFalse(notify.changed(green, green))
        self.assertTrue(notify.changed(job("c", "timed_out"), green))
        self.assertFalse(notify.changed(job("c", "timed_out"), red))

    def test_new_canary_counts_as_previously_green(self):
        self.assertTrue(notify.changed(job("c", "failure"), None))
        self.assertFalse(notify.changed(job("c", "success"), None))


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
        text = notify.details_text(failing, log, green, canary_log(), "https://x/run")
        budget = notify.TESTS_CHARS + notify.LOG_CHARS + notify.VERSIONS_CHARS
        self.assertLess(len(text), budget + 1000)
        self.assertIn("*Failed tests* (100+)", text)
        self.assertIn("(0):", text.split("Versions")[1])
        self.assertIn("more lines", text)


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
        text = notify.details_text(failing, log, green, green_log, "https://github.com/o/r/actions/runs/9/job/2")
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
        text = notify.details_text(failing, log, None, "", "")
        self.assertIn("(failed step `Install the newest releases`)", text)
        self.assertIn("error: No solution found", text)
        self.assertIn("no earlier passing run", text)
        self.assertNotIn("Failed tests", text)

    def test_install_failure_against_a_passing_run(self):
        failing = job("c", "failure", steps=[step("Install the newest releases", "failure", "00:00", "00:09", 3)])
        log = canary_log(versions=(), install_output=["error: No solution found", "##[error]Process completed with exit code 1."])
        text = notify.details_text(failing, log, job("c", "success", id=2), canary_log(), "https://x/run")
        self.assertIn("this run didn't get as far as installing", text)

    def test_details_for_a_timeout(self):
        failing = job("c", "failure", steps=CANARY_STEPS + [step("Test", "cancelled", "00:09", "06:31", 5)])
        text = notify.details_text(failing, canary_log(test_output=["still running"]), None, "", "")
        self.assertIn("(failed step `Test`)", text)
        self.assertIn("still running", text)


class NestedGroups(unittest.TestCase):
    """Output can open groups titled `Run …`; the log is read whole, so they can't hide anything."""

    def test_nested_run_group_in_the_failing_step(self):
        output = ["start tests", "##[group]Run nested test suite", "FAILED tests/real.py::test_x - boom", "##[endgroup]", "= 1 failed ="]
        failing = job("c", "failure", steps=CANARY_STEPS + [step("Test", "failure", "00:09", "06:31", 5)])
        text = notify.details_text(failing, canary_log(test_output=output), None, "", "")
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
        text = notify.details_text(
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
        self.assertIn("(failed step `_Test_ now`)", notify.details_text(failing, canary_log(), None, "", ""))


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
                f.write(json.dumps({"name": name, "repo": f"o/{name}", "cadence": "2h"}) + "\n")
        try:
            script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "plan.py")
            return subprocess.run([sys.executable, script, f.name], capture_output=True, text=True, env={})
        finally:
            os.unlink(f.name)

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

    def __call__(self, url, data=None, headers=None, opener=None, read=None):
        if data is not None:
            body = json.loads(data)
            self.posts.append((url, body))
            return json.dumps({"ok": True, "ts": f"{len(self.posts)}.0"})
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
        with mock.patch.dict(os.environ, {**ENV, **env}, clear=True), mock.patch.object(notify, "request", fake), mock.patch.object(notify.time, "sleep"):
            notify.main()
        return fake.posts

    def test_turning_red_posts_an_alert_and_a_threaded_reply(self):
        failing_steps = CANARY_STEPS + [step("Test", "failure", "00:09", "06:31", 5)]
        runs = {
            100: [job("plan", "success", id=1, run_id=100), job("inspect_ai", "failure", id=2, run_id=100, steps=failing_steps), job("other", "failure", id=3, run_id=100), job("notify", None, id=4, run_id=100)],
            99: [job("plan", "success", id=5, run_id=99), job("inspect_ai", "success", id=6, run_id=99, steps=CANARY_STEPS), job("other", "failure", id=7, run_id=99)],
        }
        logs = {2: canary_log(test_output=["FAILED tests/t.py::test_x - boom"]), 6: canary_log(sha=OLD_SHA, versions=(("anyio", "4.10.0"),))}
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

    def test_staying_red_or_green_posts_nothing(self):
        runs = {
            100: [job("a", "failure", run_id=100), job("b", "success", run_id=100), job("c", "cancelled", run_id=100)],
            99: [job("a", "failure", run_id=99), job("b", "success", run_id=99), job("c", "success", run_id=99)],
        }
        self.assertEqual(self.run_main(runs, {"SLACK_WEBHOOK_URL": "https://hooks.example/x"}), [])

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
        """The current run plus `total` earlier runs; `nightly` ran only in the run `nightly_at` back."""
        runs = {100: [job("plan", "success", run_id=100), job("nightly", current, id=1, run_id=100)]}
        for n in range(1, total + 1):
            jobs = [job("plan", "success", run_id=1000 + n)]
            if other_jobs:
                jobs.append(job("hourly", "success", run_id=1000 + n))
            if n == nightly_at:
                jobs.append(job("nightly", "failure", id=5000, run_id=1000 + n))
            runs[1000 + n] = jobs
        return runs

    def test_history_pages_back_past_100_runs(self):
        # Still red: the earlier failure is 130 runs back, beyond the first page.
        fake_posts = self.run_main(self.history(150, 130, "failure"), {"SLACK_WEBHOOK_URL": "https://hooks.example/x"})
        self.assertEqual(fake_posts, [])
        # Recovered: the same history, now green, alerts.
        posts = self.run_main(self.history(150, 130, "success"), {"SLACK_WEBHOOK_URL": "https://hooks.example/x"})
        self.assertEqual(len(posts), 1)
        self.assertIn("Canary `nightly` recovered", posts[0][1]["text"])

    def test_history_pages_by_creation_time(self):
        fake = FakeServices(self.history(150, 130, "failure"))
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
        # Its second failure finds the first and stays quiet.
        runs = self.history(total, 1, "failure")
        self.assertEqual(self.run_main(runs, {"SLACK_WEBHOOK_URL": "https://hooks.example/x"}), [])
        # A result beyond the limit isn't searched for: that canary counts as new too.
        self.assertEqual(len(self.run_main(self.history(total, total, "failure"), {"SLACK_WEBHOOK_URL": "https://hooks.example/x"})), 1)
        self.assertEqual(self.run_main(self.history(total, total, "success"), {"SLACK_WEBHOOK_URL": "https://hooks.example/x"}), [])

    def test_test_message_on_both_paths(self):
        posts = self.run_main({}, {"TEST_SLACK": "true", "SLACK_WEBHOOK_URL": "https://hooks.example/x"})
        self.assertEqual([url for url, _ in posts], ["https://hooks.example/x"])
        posts = self.run_main({}, {"TEST_SLACK": "true", "SLACK_BOT_TOKEN": "xoxb", "SLACK_CHANNEL_ID": "C1"})
        self.assertEqual(len(posts), 2)
        self.assertEqual(posts[1][1]["thread_ts"], "1.0")

    def test_no_credentials_posts_nothing(self):
        self.assertEqual(self.run_main({}, {"TEST_SLACK": "true"}), [])


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
