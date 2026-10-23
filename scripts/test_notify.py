"""Tests for notify.py: python3 -m unittest discover -s scripts"""

import json
import os
import unittest
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


def canary_log(sha=SHA, versions=(("anyio", "4.11.0"), ("inspect-ai", "0.3.290")), test_output=()):
    """A job log shaped like GitHub's, with steps at fixed times."""
    lines = [
        line("00:00", "##[group]Run echo \"canary-tested: UKGovernmentBEIS/inspect_ai@$(git rev-parse HEAD)\""),
        line("00:00", f"{ESC}[36;1mecho \"canary-tested: UKGovernmentBEIS/inspect_ai@$(git rev-parse HEAD)\"{ESC}[0m"),
        line("00:00", "##[endgroup]"),
        line("00:00", f"canary-tested: UKGovernmentBEIS/inspect_ai@{sha}"),
        line("00:00", "##[group]Run uv venv"),
        line("00:00", "##[endgroup]"),
        line("00:05", "Installed 300 packages"),
        line("00:09", "##[group]Run uv pip list"),
        line("00:09", f"{ESC}[36;1muv pip list{ESC}[0m"),
        line("00:09", "##[endgroup]"),
        line("00:09", "Package            Version  Editable project location"),
        line("00:09", "------------------ -------- -------------------------"),
    ]
    lines += [line("00:09", f"{name:<18} {version}") for name, version in versions]
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
        green = job("inspect_ai", "success", id=2, steps=CANARY_STEPS)
        text = notify.details_text(failing, log, green, canary_log(), "https://x/run")
        budget = notify.TESTS_CHARS + notify.LOG_CHARS + notify.VERSIONS_CHARS
        self.assertLess(len(text), budget + 1000)
        self.assertIn("(500)", text)
        self.assertIn("more lines", text)


class Logs(unittest.TestCase):
    def test_step_lines_start_at_the_step_header(self):
        log = canary_log()
        versions = notify.output_lines(notify.step_lines(log, CANARY_STEPS[3], CANARY_STEPS))
        self.assertEqual(versions[0].split()[0], "Package")
        self.assertNotIn("Installed 300 packages", versions)
        self.assertFalse(any(text.startswith("##[") or text.startswith("uv pip list") for text in versions))

    def test_failed_tests(self):
        lines = [
            "tests/test_a.py::test_one PASSED",
            "FAILED tests/test_a.py::test_two - AssertionError: no",
            "ERROR tests/test_b.py::test_three - fixture",
            "FAILED tests/test_a.py::test_two - AssertionError: no",
        ]
        self.assertEqual(notify.failed_tests(lines), ["tests/test_a.py::test_two", "tests/test_b.py::test_three"])

    def test_version_diff(self):
        old = notify.parse_versions(
            ["Package Version", "------- -------", "anyio 4.10.0", "Pydantic_Core 2.41.0", "gone 1.0", "same 1.0"]
        )
        new = notify.parse_versions(
            ["Package Version", "------- -------", "anyio 4.11.0", "pydantic-core 2.41.0", "added 2.0", "same 1.0"]
        )
        self.assertEqual(old["pydantic-core"], "2.41.0")
        self.assertEqual(notify.version_diff(old, new), ["+ added 2.0", "  anyio 4.10.0 → 4.11.0", "- gone 1.0"])

    def test_parse_versions_ignores_lines_before_the_table(self):
        self.assertEqual(notify.parse_versions(["Resolved 3 packages", "--------- -------", "a 1"]), {"a": "1"})
        self.assertEqual(notify.parse_versions(["noise 1.0"]), {})

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
        self.assertIn('*Last lines of "Test":*', text)
        self.assertIn("FAILED tests/test_a.py::test_two - &lt;!channel&gt; &amp; 'x'", text)
        self.assertIn("Process completed with exit code 1.", text)
        self.assertNotIn("Post job cleanup.", text)
        self.assertNotIn("need --runslow", text)
        self.assertNotIn("<!channel>", text)
        self.assertNotIn("Editable project location", text)  # the versions step's output
        self.assertIn("anyio 4.10.0 → 4.11.0", text)
        self.assertIn("(1):", text)

    def test_details_without_a_passing_run(self):
        failing = job("c", "failure", steps=[step("Install the newest releases", "failure", "00:00", "00:09", 3)])
        text = notify.details_text(failing, canary_log(), None, "", "")
        self.assertIn('"Install the newest releases"', text)
        self.assertIn("no earlier passing run", text)
        self.assertNotIn("Failed tests", text)

    def test_details_for_a_timeout(self):
        failing = job("c", "failure", steps=CANARY_STEPS + [step("Test", "cancelled", "00:09", "06:31", 5)])
        text = notify.details_text(failing, canary_log(test_output=["still running"]), None, "", "")
        self.assertIn('"Test"', text)
        self.assertIn("still running", text)


class Messages(unittest.TestCase):
    def test_alert_text(self):
        url = "https://github.com/o/r/actions/runs/1/job/2"
        red = notify.alert_text("inspect_ai", True, url, ("UKGovernmentBEIS/inspect_ai", SHA))
        self.assertIn("*inspect_ai* is failing", red)
        self.assertIn(f"<https://github.com/UKGovernmentBEIS/inspect_ai/commit/{SHA}|UKGovernmentBEIS/inspect_ai@{SHA[:10]}>", red)
        self.assertIn(f"<{url}|Run log>", red)
        green = notify.alert_text("inspect_ai", False, url, None)
        self.assertIn("recovered", green)
        self.assertNotIn("Tested", green)


class FakeServices:
    """Answers notify.request() for the GitHub and Slack calls main() makes."""

    def __init__(self, runs):
        self.runs = runs  # {run_id: [jobs]}, current run first
        self.logs = {}
        self.posts = []

    def __call__(self, url, data=None, headers=None, opener=None):
        if data is not None:
            body = json.loads(data)
            self.posts.append((url, body))
            return json.dumps({"ok": True, "ts": f"{len(self.posts)}.0"})
        path = url.split("/repos/o/r/", 1)[1]
        if path.startswith("actions/runs/") and path.endswith("jobs?per_page=100&page=1"):
            jobs = self.runs[int(path.split("/")[2])]
            return json.dumps({"total_count": len(jobs), "jobs": jobs})
        if path.startswith("actions/runs/"):
            return json.dumps({"id": 100, "workflow_id": 7, "created_at": "2026-10-23T04:00:00Z"})
        if path.startswith("actions/workflows/7/runs"):
            runs = [{"id": i, "created_at": f"2026-10-23T0{4 - n}:00:00Z"} for n, i in enumerate(self.runs)]
            return json.dumps({"workflow_runs": runs})
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
        self.assertIn("*inspect_ai* is failing", alert["text"])
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
        self.assertIn("*a* recovered", body["text"])
        self.assertNotIn("channel", body)

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
