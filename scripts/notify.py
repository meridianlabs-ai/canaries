"""Post canary state changes to Slack.

Runs in the workflow's notify job after a scheduled run. Each canary job's
conclusion is compared with the same canary's conclusion in the most recent
earlier scheduled run that ran it; a message goes out only when a canary
turns red or recovers. Standard library only.

With CANARY_SLACK_BOT_TOKEN and CANARY_SLACK_CHANNEL_ID, each message gets a
threaded reply with the failed tests, the end of the failing step's log and
the package versions that changed since the canary last passed. Otherwise the
message goes to CANARY_SLACK_WEBHOOK_URL on its own.

Job logs come from runs that installed unreviewed packages, so their text is
treated as untrusted: it is stripped of control characters, truncated,
escaped for Slack and posted only inside code blocks under a label.
"""

import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta

RED = {"failure", "timed_out"}
GREEN = {"success"}
NOT_CANARIES = {"notify"}  # jobs in the workflow that aren't canaries
HISTORY_RUNS = 100  # earlier scheduled runs searched for a canary's last result

LOG_TAIL_LINES = 40
LINE_CHARS = 300
TESTS_CHARS = 1200
LOG_CHARS = 3000
VERSIONS_CHARS = 1500

UNTRUSTED = "Untrusted log output from a run that installed unreviewed packages."
TESTED_MARKER = "canary-tested: "
VERSIONS_STEP = "Installed versions"

TIMESTAMP = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.\d+)?Z ?")
ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
TESTED = re.compile(r"^([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@([0-9a-f]{40})$")
FAILED_TEST = re.compile(r"^(?:FAILED|ERROR) (\S+)")
PACKAGE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s+(\S+)")


# --- state ------------------------------------------------------------------


def state(conclusion):
    """'red', 'green', or None for a result that says neither (cancelled, skipped)."""
    if conclusion in RED:
        return "red"
    if conclusion in GREEN:
        return "green"
    return None


def previous_job(name, history, want=("red", "green")):
    """The newest job named `name` in `history` whose state is in `want`.

    `history` is an iterable of job lists, newest run first.
    """
    for jobs in history:
        for job in jobs:
            if job["name"] == name and state(job["conclusion"]) in want:
                return job
    return None


def changed(job, previous):
    """Whether `job` differs in state from `previous` (None: never ran before).

    A canary with no earlier result counts as previously green, so a new
    canary alerts on its first failure and stays quiet while it passes.
    """
    before = state(previous["conclusion"]) if previous else "green"
    return state(job["conclusion"]) != before


# --- log text ---------------------------------------------------------------


def slack_escape(text):
    """Escape the characters Slack treats as markup in message text.

    `&`, `<` and `>` are the escapes Slack documents; without them log text
    could form mentions (<!channel>) or links. Backticks would close the code
    block the text sits in, so they become quotes.
    """
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("`", "'")


def clean(line):
    """A log line without its timestamp, colors, control characters or excess length."""
    line = CONTROL.sub("", ANSI.sub("", TIMESTAMP.sub("", line, count=1)))
    if len(line) > LINE_CHARS:
        line = line[: LINE_CHARS - 1] + "…"
    return line


def fit(lines, max_chars, keep="head"):
    """Join lines within max_chars, dropping from the tail (or head) with a note."""
    kept, used = [], 0
    ordered = lines if keep == "head" else list(reversed(lines))
    for line in ordered:
        if used + len(line) + 1 > max_chars:
            break
        kept.append(line)
        used += len(line) + 1
    dropped = len(lines) - len(kept)
    if keep == "tail":
        kept.reverse()
    if dropped:
        note = f"… {dropped} more line{'s' if dropped != 1 else ''}"
        kept = kept + [note] if keep == "head" else [note] + kept
    return "\n".join(kept)


def code_block(lines, max_chars, keep="head"):
    return "```\n" + slack_escape(fit(lines, max_chars, keep)) + "\n```"


def parse_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)


def is_header(line):
    return TIMESTAMP.sub("", line, count=1).startswith("##[group]Run ")


def has_header(step):
    """Whether the runner logs a `##[group]Run` header for this step."""
    name = step.get("name", "")
    return step.get("conclusion") != "skipped" and name not in ("Set up job", "Complete job") and not name.startswith("Post ")


def step_lines(log, step, steps=()):
    """The raw log lines a step wrote.

    The jobs API gives step times to the second, so the lines from the step's
    start to its end take in the neighbouring steps' lines from the same
    seconds. Within that window the step starts at its own `##[group]Run`
    header, after those of the earlier `steps` that started in the same
    second, and ends at the next header or at the post-job cleanup, which
    logs no header.
    """
    if not step.get("started_at") or not step.get("completed_at"):
        return []
    start = parse_time(step["started_at"])
    end = parse_time(step["completed_at"]) + timedelta(seconds=1)
    lines, current = [], None
    for line in log.splitlines():
        match = TIMESTAMP.match(line)
        if match:
            current = datetime.fromisoformat(match.group(1))
        if current is not None and start <= current < end:
            lines.append(line)
        elif current is not None and current >= end:
            break
    earlier = sum(
        1
        for s in steps
        if s.get("number", 0) < step.get("number", 0) and s.get("started_at") == step["started_at"] and has_header(s)
    )
    headers = [i for i, line in enumerate(lines) if is_header(line)]
    if len(headers) > earlier:
        lines = lines[headers[earlier] :]
    for i, line in enumerate(lines[1:], 1):
        if is_header(line) or TIMESTAMP.sub("", line, count=1) == "Post job cleanup.":
            return lines[:i]
    return lines


def output_lines(lines):
    """Step lines with the runner's group markers and command header removed."""
    out, in_header = [], False
    for line in lines:
        text = clean(line)
        if text.startswith("##[group]Run "):
            in_header = True
            continue
        if text.startswith("##[endgroup]"):
            in_header = False
            continue
        if in_header:
            continue
        out.append(text.removeprefix("##[error]"))
    return out


def tested_commit(log):
    """(repo, sha) from the first `canary-tested:` line, written before any install."""
    for line in log.splitlines():
        text = clean(line)
        if text.startswith(TESTED_MARKER):
            match = TESTED.match(text[len(TESTED_MARKER) :].strip())
            return match.groups() if match else None
    return None


def failed_tests(lines):
    """Test ids from pytest's `-ra` summary (FAILED/ERROR lines), in order, unique."""
    tests = []
    for line in lines:
        match = FAILED_TEST.match(line)
        if match and match.group(1) not in tests:
            tests.append(match.group(1))
    return tests


def parse_versions(lines):
    """{normalized name: version} from `uv pip list` output."""
    versions, table = {}, False
    for line in lines:
        if line.startswith("---"):
            table = True
            continue
        match = PACKAGE.match(line) if table else None
        if match:
            name = re.sub(r"[-_.]+", "-", match.group(1)).lower()
            versions[name] = match.group(2)
    return versions


def version_diff(old, new):
    """Lines describing what changed between two {name: version} maps."""
    lines = []
    for name in sorted(old.keys() | new.keys()):
        before, after = old.get(name), new.get(name)
        if before == after:
            continue
        if before is None:
            lines.append(f"+ {name} {after}")
        elif after is None:
            lines.append(f"- {name} {before}")
        else:
            lines.append(f"  {name} {before} → {after}")
    return lines


def failing_step(job):
    """The step that failed, else the one cut off by a timeout or cancellation."""
    steps = job.get("steps") or []
    for want in ("failure", "cancelled"):
        for step in steps:
            if step.get("conclusion") == want:
                return step
    return None


def find_step(job, name):
    for step in job.get("steps") or []:
        if step.get("name") == name:
            return step
    return None


# --- messages ---------------------------------------------------------------


def alert_text(name, red, job_url, commit):
    """The channel message: canary, what it tested, and the run."""
    name = slack_escape(name)
    if red:
        head = f":red_circle: Canary *{name}* is failing on the newest releases."
    else:
        head = f":large_green_circle: Canary *{name}* recovered."
    if commit:
        repo, sha = commit
        head += f" Tested <https://github.com/{repo}/commit/{sha}|{repo}@{sha[:10]}>."
    return f"{head} <{job_url}|Run log>"


def details_text(job, log, green_job, green_log, green_url):
    """The threaded reply for a canary that turned red."""
    parts = [f"_{UNTRUSTED}_"]
    step = failing_step(job)
    step_output = output_lines(step_lines(log, step, job["steps"])) if step else []
    lines = step_output or output_lines(log.splitlines())

    tests = failed_tests(step_output)
    if tests:
        parts.append(f"*Failed tests* ({len(tests)}):\n" + code_block(tests, TESTS_CHARS))

    where = f'"{slack_escape(step["name"])}"' if step else "the job"
    # pytest -ra lists every skipped test after the failures; leave those out.
    tail = [line for line in lines if line.strip() and not line.startswith("SKIPPED [")][-LOG_TAIL_LINES:]
    parts.append(f"*Last lines of {where}:*\n" + code_block(tail, LOG_CHARS, keep="tail"))

    if green_job is None:
        parts.append("*Versions:* no earlier passing run to compare with.")
    else:
        old = parse_versions(output_lines(step_lines(green_log, find_step(green_job, VERSIONS_STEP) or {}, green_job["steps"])))
        new = parse_versions(output_lines(step_lines(log, find_step(job, VERSIONS_STEP) or {}, job["steps"])))
        if not new:
            parts.append("*Versions:* this run didn't get as far as installing.")
        elif not old:
            parts.append(f"*Versions:* couldn't read the installed versions of <{green_url}|the last passing run>.")
        else:
            diff = version_diff(old, new)
            label = f"*Versions changed since <{green_url}|the last passing run>* ({len(diff)}):"
            parts.append(label + "\n" + code_block(diff, VERSIONS_CHARS) if diff else label + " none.")
    return "\n\n".join(parts)


# --- GitHub and Slack -------------------------------------------------------


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def request(url, data=None, headers=None, opener=urllib.request.urlopen):
    req = urllib.request.Request(url, data=data, headers=headers or {})
    with opener(req, timeout=60) as response:
        return response.read().decode("utf-8", errors="replace")


class GitHub:
    def __init__(self, api, repo, token):
        self.api, self.repo, self.token = api, repo, token
        self._jobs = {}

    def headers(self):
        return {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def get(self, path):
        return json.loads(request(f"{self.api}/repos/{self.repo}/{path}", headers=self.headers()))

    def jobs(self, run_id):
        if run_id not in self._jobs:
            jobs, page = [], 1
            while True:
                data = self.get(f"actions/runs/{run_id}/jobs?per_page=100&page={page}")
                jobs += data["jobs"]
                if len(jobs) >= data["total_count"] or not data["jobs"]:
                    break
                page += 1
            self._jobs[run_id] = jobs
        return self._jobs[run_id]

    def earlier_scheduled_runs(self, run):
        """Completed scheduled runs of this workflow created before `run`, newest first."""
        data = self.get(
            f"actions/workflows/{run['workflow_id']}/runs"
            f"?event=schedule&status=completed&per_page={HISTORY_RUNS}"
        )
        created = parse_time(run["created_at"])
        return [r for r in data["workflow_runs"] if r["id"] != run["id"] and parse_time(r["created_at"]) < created]

    def history(self, runs):
        for r in runs:
            yield self.jobs(r["id"])

    def log(self, job_id):
        """A job's log. GitHub answers with a redirect to storage, which is
        followed without the token."""
        opener = urllib.request.build_opener(NoRedirect).open
        try:
            return request(f"{self.api}/repos/{self.repo}/actions/jobs/{job_id}/logs", headers=self.headers(), opener=opener)
        except urllib.error.HTTPError as e:
            if e.code not in (301, 302, 303, 307, 308):
                raise
            return request(e.headers["Location"])


class Slack:
    def __init__(self, bot_token, channel, webhook):
        self.bot_token, self.channel, self.webhook = bot_token, channel, webhook
        self.posted = False

    @property
    def threads(self):
        return bool(self.bot_token and self.channel)

    def post(self, text, thread_ts=None):
        """Post a message; returns its ts when posted with the bot token."""
        if self.posted:
            time.sleep(1)  # Slack allows about one message a second per channel
        self.posted = True
        body = {"text": text, "unfurl_links": False, "unfurl_media": False}
        if not self.threads:
            request(self.webhook, json.dumps(body).encode(), {"Content-Type": "application/json"})
            return None
        body.update(channel=self.channel, link_names=False)
        if thread_ts:
            body["thread_ts"] = thread_ts
        response = json.loads(
            request(
                "https://slack.com/api/chat.postMessage",
                json.dumps(body).encode(),
                {"Content-Type": "application/json; charset=utf-8", "Authorization": f"Bearer {self.bot_token}"},
            )
        )
        if not response.get("ok"):
            raise RuntimeError(f"chat.postMessage failed: {response.get('error')}")
        return response["ts"]


def job_url(server, repo, job):
    return f"{server}/{repo}/actions/runs/{job['run_id']}/job/{job['id']}"


def main():
    env = os.environ
    slack = Slack(env.get("SLACK_BOT_TOKEN"), env.get("SLACK_CHANNEL_ID"), env.get("SLACK_WEBHOOK_URL"))
    if slack.bot_token and not slack.channel:
        print("::notice::CANARY_SLACK_CHANNEL_ID is not set; posting through the webhook, without thread replies.")
    if not slack.threads and not slack.webhook:
        print("::warning::No Slack credentials are set; not posting.")
        return

    server, repo, run_id = env["GITHUB_SERVER_URL"], env["GITHUB_REPOSITORY"], env["GITHUB_RUN_ID"]
    run_url = f"{server}/{repo}/actions/runs/{run_id}"

    if env.get("TEST_SLACK") == "true":
        ts = slack.post(f"Canaries test message: alerts are wired up. <{run_url}|Run>")
        if ts:
            slack.post("Test reply: failure details for an alert go in its thread.", thread_ts=ts)
        print(f"Posted a test message {'with a thread reply' if ts else 'through the webhook'}.")
        return

    github = GitHub(env["GITHUB_API_URL"], repo, env["GH_TOKEN"])
    run = github.get(f"actions/runs/{run_id}")
    current = [j for j in github.jobs(run_id) if j["name"] not in NOT_CANARIES and state(j["conclusion"])]
    earlier = github.earlier_scheduled_runs(run)

    for job in current:
        previous = previous_job(job["name"], github.history(earlier))
        if not changed(job, previous):
            print(f"{job['name']}: still {state(job['conclusion'])}")
            continue
        red = state(job["conclusion"]) == "red"
        print(f"{job['name']}: now {'red' if red else 'green'}")
        url = job_url(server, repo, job)
        try:
            log = github.log(job["id"])
        except Exception as e:  # still alert, without the commit and details
            log = ""
            print(f"::warning::log for {job['name']}: {e!r}")
        ts = slack.post(alert_text(job["name"], red, url, tested_commit(log)))
        if not (red and ts):
            continue
        try:
            green = previous_job(job["name"], github.history(earlier), want=("green",))
            green_log = github.log(green["id"]) if green else ""
            green_url = job_url(server, repo, green) if green else ""
            reply = details_text(job, log, green, green_log, green_url)
        except Exception as e:  # the alert is out; say why the details aren't
            reply = f"Couldn't collect the failure details: {slack_escape(type(e).__name__)}. See the run log."
            print(f"::warning::details for {job['name']}: {e!r}")
        slack.post(reply, thread_ts=ts)


if __name__ == "__main__":
    sys.exit(main())
