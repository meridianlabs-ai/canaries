"""The canary workflow's security rules: python3 -m unittest discover -s scripts

Canary jobs install and run unreviewed releases, so they must hold no secrets,
get a read-only token, and neither restore nor save the Actions cache. The
Slack secrets are used only by the notify job, through the `slack` environment
(restricted to main in the repository settings), and that job runs only this
repository's own code. These tests fail if a workflow change breaks any of it.

A repository's token cannot list organization secrets. Instead `secrets.yml`
checks the `secrets` context by name each day, on pushes to `main`, and on
pull requests. On Dependabot pull request runs, the context holds Dependabot
secrets in place of Actions secrets. So those runs fail on any Dependabot secret
visible to this repository. Fork pull request runs get only `github_token`, so
they prove nothing. Codespaces and Copilot agent organization secrets are not
covered: they do not reach Actions runs.
"""

import json
import os
import re
import shutil
import subprocess
import unittest

WORKFLOWS = os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, ".github", "workflows")
SECRETS = re.compile(r"(?<![\w.-])secrets(?![\w-])")


def load(name):
    path = os.path.join(WORKFLOWS, name)
    # yq is preinstalled on GitHub's Ubuntu runners, so CI needs no packages.
    if shutil.which("yq"):
        return json.loads(subprocess.check_output(["yq", "-o=json", ".", path]))
    try:
        import yaml
    except ImportError:
        raise unittest.SkipTest("needs yq or PyYAML to read the workflow")
    with open(path) as f:
        return yaml.safe_load(f)


def uses(step):
    return step.get("uses", "").split("@")[0]


def text(value):
    return json.dumps(value)


class CanaryWorkflow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = load("canary.yml")
        cls.jobs = cls.workflow["jobs"]

    def test_the_jobs_are_the_ones_these_rules_cover(self):
        # A new job must be classified here before it can run.
        self.assertEqual(set(self.jobs), {"plan", "canary", "notify"})

    def test_the_default_token_is_read_only(self):
        self.assertEqual(self.workflow["permissions"], {"contents": "read"})

    def test_only_notify_uses_secrets(self):
        self.assertFalse(SECRETS.search(text({k: v for k, v in self.workflow.items() if k != "jobs"})))
        for name in ("plan", "canary"):
            with self.subTest(job=name):
                self.assertFalse(SECRETS.search(text(self.jobs[name])), f"{name} references secrets")
                self.assertNotIn("environment", self.jobs[name])

    def test_planning_and_canary_jobs_get_no_extra_permissions(self):
        # The planner may read Actions history (to re-check red nightly
        # canaries every 2 hours); canary jobs get nothing beyond reading code.
        self.assertIn(
            self.jobs["plan"].get("permissions", {"contents": "read"}),
            ({"contents": "read"}, {}, {"actions": "read", "contents": "read"}),
        )
        self.assertIn(self.jobs["canary"].get("permissions", {"contents": "read"}), ({"contents": "read"}, {}))

    def test_canary_jobs_neither_restore_nor_save_a_cache(self):
        for step in self.jobs["canary"]["steps"]:
            action = uses(step)
            inputs = step.get("with") or {}
            self.assertNotIn(action, {"actions/cache", "actions/cache/restore", "actions/cache/save"})
            if action == "astral-sh/setup-uv":
                self.assertIs(inputs.get("enable-cache"), False)
            if action in {"actions/setup-python", "actions/setup-node"}:
                self.assertNotIn("cache", inputs)
            if action == "actions/setup-node":
                self.assertIs(inputs.get("package-manager-cache"), False)

    def test_canary_jobs_hand_nothing_to_other_jobs(self):
        self.assertNotIn("outputs", self.jobs["canary"])
        for step in self.jobs["canary"]["steps"]:
            self.assertNotIn(uses(step), {"actions/upload-artifact", "actions/cache/save"})

    def test_the_test_step_writes_a_junit_report(self):
        test = next(s for s in self.jobs["canary"]["steps"] if s.get("name") == "Test")
        env = test.get("env") or {}
        self.assertIn("--junitxml=", env.get("PYTEST_ADDOPTS", ""))
        self.assertIn("CANARY_JUNIT_NAME", env)

    def test_the_failed_tests_step_reads_the_reports_safely(self):
        # Right after Test, an inline script with no secrets, no action and no artifact.
        names = [s.get("name") for s in self.jobs["canary"]["steps"]]
        self.assertEqual(names.index("Failed tests"), names.index("Test") + 1)
        failed = next(s for s in self.jobs["canary"]["steps"] if s.get("name") == "Failed tests")
        self.assertEqual(failed["if"], "${{ !cancelled() }}")
        self.assertEqual(uses(failed), "")  # no `uses:`; the script runs inline
        self.assertFalse(SECRETS.search(text(failed)))
        self.assertNotIn("artifact", text(failed))
        self.assertIn("python3 -I", failed["run"])  # isolated: the checkout is untrusted

    def test_checkouts_keep_no_credentials(self):
        for name, job in self.jobs.items():
            for step in job["steps"]:
                if uses(step) == "actions/checkout":
                    with self.subTest(job=name):
                        self.assertIs((step.get("with") or {}).get("persist-credentials"), False)

    def test_runners_are_github_hosted(self):
        for name, job in self.jobs.items():
            with self.subTest(job=name):
                runs_on = str(job["runs-on"])
                self.assertNotIn("self-hosted", runs_on)

    def test_notify_holds_the_secrets_and_runs_only_this_repository(self):
        notify = self.jobs["notify"]
        self.assertEqual(notify["environment"], "slack")
        self.assertEqual(notify["permissions"], {"actions": "read", "contents": "read"})
        # Only on schedules and the explicit manual inputs, never a PR run.
        condition = notify["if"]
        self.assertIn("github.event_name == 'schedule'", condition)
        self.assertNotIn("pull_request", condition)
        for step in notify["steps"]:
            if uses(step) == "actions/checkout":
                self.assertNotIn("repository", step.get("with") or {})
            # No third-party actions other than checking out this repository.
            self.assertIn(uses(step), {"", "actions/checkout"})
            self.assertNotIn("artifact", text(step))


class SecretsWorkflow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = load("secrets.yml")
        cls.jobs = cls.workflow["jobs"]
        # `yq` keeps `on` a string; PyYAML reads it as the boolean True.
        cls.on = cls.workflow.get("on", cls.workflow.get(True))

    def test_one_job_named_no_secrets(self):
        self.assertEqual(set(self.jobs), {"no-secrets"})

    def test_no_top_level_permissions(self):
        self.assertEqual(self.workflow["permissions"], {})

    def test_the_job_grants_nothing(self):
        job = self.jobs["no-secrets"]
        self.assertNotIn("environment", job)
        self.assertEqual(job.get("permissions", {}), {})

    def test_the_only_secrets_reference_is_tojson_in_one_step_env(self):
        # The top level names no secret; one step reads the whole context. The
        # workflow's own `name` is the word `secrets`, so skip it here.
        top = {k: v for k, v in self.workflow.items() if k not in ("jobs", "name")}
        self.assertFalse(SECRETS.search(text(top)))
        with_secrets = [s for s in self.jobs["no-secrets"]["steps"] if SECRETS.search(text(s))]
        self.assertEqual(len(with_secrets), 1)
        env = with_secrets[0]["env"]
        self.assertEqual([v for v in env.values() if SECRETS.search(v)], ["${{ toJSON(secrets) }}"])

    def test_the_only_action_is_checkout_without_credentials(self):
        for step in self.jobs["no-secrets"]["steps"]:
            self.assertIn(uses(step), {"", "actions/checkout"})
            if uses(step) == "actions/checkout":
                self.assertIs((step.get("with") or {}).get("persist-credentials"), False)

    def test_runner_is_github_hosted(self):
        self.assertNotIn("self-hosted", str(self.jobs["no-secrets"]["runs-on"]))

    def test_it_runs_on_every_schedule_push_and_pull_request(self):
        self.assertIn("schedule", self.on)
        self.assertEqual(self.on["push"], {"branches": ["main"]})
        self.assertIn("workflow_dispatch", self.on)
        # A required check must report on every PR, so no `paths` filter.
        self.assertIn("pull_request", self.on)
        self.assertNotIn("paths", self.on["pull_request"] or {})


class TestWorkflow(unittest.TestCase):
    def test_unit_tests_hold_no_secrets(self):
        workflow = load("test.yml")
        self.assertFalse(SECRETS.search(text(workflow)))
        self.assertEqual(workflow["permissions"], {"contents": "read"})


if __name__ == "__main__":
    unittest.main()
