"""Post canary state changes to Slack.

Runs in the workflow's notify job after a scheduled run. Each canary job's
conclusion is compared with the same canary's conclusion in the most recent
earlier scheduled run that ran it; a message goes out only when a canary
turns red or recovers. Standard library only.

With CANARY_SLACK_BOT_TOKEN and CANARY_SLACK_CHANNEL_ID, each message gets a
threaded reply with the failed tests, the end of the job's log and the
package versions that changed since the canary last passed. Otherwise the
message goes to CANARY_SLACK_WEBHOOK_URL on its own. The canary job marks the
lines this reads (`canary-tested:`, `canary-installed:`), so each log is read
as a whole, never split into steps.

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

RED = {"failure", "timed_out"}
GREEN = {"success"}
PLAN_JOB = "plan"
NOT_CANARIES = {PLAN_JOB, "notify"}  # jobs in the workflow that aren't canaries
HISTORY_PAGE = 100
HISTORY_LIMIT = 400  # earlier scheduled runs searched for a canary's last result (about a month)

LOG_TAIL_LINES = 40
LINE_CHARS = 300
NAME_CHARS = 80
MAX_TESTS = 100
LOG_HEAD_BYTES = 8 << 20  # a log's first and last bytes kept; the middle of a huge log is dropped
LOG_TAIL_BYTES = 24 << 20
TESTS_CHARS = 1200
LOG_CHARS = 3000
VERSIONS_CHARS = 1500

UNTRUSTED = "Untrusted log output from a run that installed unreviewed packages."
TESTED_MARKER = "canary-tested: "
INSTALLED_MARKER = "canary-installed: "

TIMESTAMP = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.\d+)?Z ?")
ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
TESTED = re.compile(r"^([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@([0-9a-f]{40})$")
FAILED_TEST = re.compile(r"^(?:FAILED|ERROR) (\S+)")
INSTALLED = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*) (\S+)$")


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

    `history` is an iterable of job lists, newest run first; None if none has one.
    """
    for jobs in history:
        for job in jobs:
            if job["name"] == name and state(job["conclusion"]) in want:
                return job
    return None


def changed(job, previous):
    """Whether `job` differs in state from `previous` (None: never ran before).

    A canary with no earlier result in the searched history is new and
    counts as previously green, so it alerts on its first failure and stays
    quiet while it passes.
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


def plain(name):
    """A job or step name for display: one line, no markup, bounded.

    Shown in an inline code span, where Slack applies no formatting, so the
    underscores in names like inspect_ai stay as they are.
    """
    name = slack_escape(re.sub(r"[\x00-\x1f\x7f]+", " ", name)).replace("*", "").replace("~", "").strip()
    if len(name) > NAME_CHARS:
        name = name[: NAME_CHARS - 1] + "…"
    return f"`{name}`"


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


def output_lines(log):
    """The job's log lines up to the post-job cleanup, cleaned, without group markers."""
    out = []
    for line in log.splitlines():
        text = clean(line)
        if text == "Post job cleanup.":
            break
        if text.startswith("##[endgroup]"):
            continue
        out.append(text.removeprefix("##[group]").removeprefix("##[error]"))
    return out


def tested_commit(log):
    """(repo, sha) from the first `canary-tested:` line, written before any install."""
    for line in log.splitlines():
        text = clean(line)
        if text.startswith(TESTED_MARKER):
            match = TESTED.match(text[len(TESTED_MARKER) :].strip())
            return match.groups() if match else None
    return None


def failed_tests(lines, limit=MAX_TESTS):
    """Test ids from pytest's `-ra` summary (FAILED/ERROR lines), in order, unique.

    Returns (ids, more): at most `limit` ids, and whether there were more.
    """
    tests = []
    for line in lines:
        match = FAILED_TEST.match(line)
        if match and match.group(1) not in tests:
            if len(tests) >= limit:
                return tests, True
            tests.append(match.group(1))
    return tests, False


def parse_versions(lines):
    """{normalized name: version} from the `canary-installed: <name> <version>` lines."""
    versions = {}
    for line in lines:
        match = INSTALLED.match(line[len(INSTALLED_MARKER) :]) if line.startswith(INSTALLED_MARKER) else None
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
    """The step that failed, else the one cut off by a timeout or cancellation (from the API)."""
    steps = job.get("steps") or []
    for want in ("failure", "cancelled"):
        for step in steps:
            if step.get("conclusion") == want:
                return step
    return None


# --- messages ---------------------------------------------------------------


def alert_text(name, red, job_url, commit):
    """The channel message: canary, what it tested, and the run."""
    if red:
        head = f":red_circle: Canary {plain(name)} is failing on the newest releases."
    else:
        head = f":large_green_circle: Canary {plain(name)} recovered."
    if commit:
        repo, sha = commit
        head += f" Tested <https://github.com/{repo}/commit/{sha}|{repo}@{sha[:10]}>."
    return f"{head} <{job_url}|Run log>"


def planning_failed_text(job_url):
    return f":warning: Canary planning failed, so no canaries ran. <{job_url}|Run log>"


def details_text(job, log, green_job, green_log, green_url):
    """The threaded reply for a canary that turned red."""
    parts = [f"_{UNTRUSTED}_"]
    lines = output_lines(log)

    tests, more = failed_tests(lines)
    if tests:
        count = f"{len(tests)}+" if more else str(len(tests))
        parts.append(f"*Failed tests* ({count}):\n" + code_block(tests, TESTS_CHARS))

    step = failing_step(job)
    where = f" (failed step {plain(step['name'])})" if step else ""
    # Leave out the version list and pytest's list of skipped tests.
    tail = [line for line in lines if line.strip() and not line.startswith((INSTALLED_MARKER, "SKIPPED ["))]
    parts.append(f"*Last lines of the job*{where}:\n" + code_block(tail[-LOG_TAIL_LINES:], LOG_CHARS, keep="tail"))

    if green_job is None:
        parts.append("*Versions:* no earlier passing run found to compare with.")
    else:
        old, new = parse_versions(output_lines(green_log)), parse_versions(lines)
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


def read_bounded(response, head=LOG_HEAD_BYTES, tail=LOG_TAIL_BYTES):
    """A response's first `head` and last `tail` bytes, read in chunks.

    A log's commit line and installed versions are near its start and the
    failure near its end; anything dropped between them is replaced by a
    line saying so.
    """
    first = response.read(head)
    rest, dropped = bytearray(), 0
    while chunk := response.read(1 << 20):
        rest += chunk
        if len(rest) > tail:
            dropped += len(rest) - tail
            del rest[: len(rest) - tail]
    if dropped:
        cut = rest.find(b"\n") + 1
        dropped += cut
        rest = f"\n… {dropped} bytes of log left out …\n".encode() + rest[cut:]
    return bytes(first + rest)


def request(url, data=None, headers=None, opener=urllib.request.urlopen, read=lambda r: r.read()):
    req = urllib.request.Request(url, data=data, headers=headers or {})
    with opener(req, timeout=60) as response:
        return read(response).decode("utf-8", errors="replace")


class GitHub:
    def __init__(self, api, repo, token):
        self.api, self.repo, self.token = api, repo, token
        self._jobs = {}
        self._runs, self._exhausted = [], False

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

    def _fetch_earlier(self, run):
        """Adds the next page of scheduled runs created before the oldest seen so far.

        Pages go by creation time rather than page number, so runs started
        while paging (or re-runs, which keep their creation time) can't shift
        the pages. Runs still in progress are included: their finished jobs
        have results, which matters when a nightly and a 2h run overlap.
        """
        before = self._runs[-1]["created_at"] if self._runs else run["created_at"]
        seen = {run["id"]} | {r["id"] for r in self._runs}
        data = self.get(
            f"actions/workflows/{run['workflow_id']}/runs"
            f"?event=schedule&per_page={HISTORY_PAGE}&created=%3C%3D{before}"
        )
        new = [r for r in data["workflow_runs"] if r["id"] not in seen]
        self._runs += new
        self._exhausted = not new

    def history(self, run):
        """Job lists of the scheduled runs created before `run`, newest first.

        Ends when the history does, or after HISTORY_LIMIT runs, which only
        bounds the API calls.
        """
        i = 0
        while i < HISTORY_LIMIT:
            if i == len(self._runs):
                if self._exhausted:
                    return
                self._fetch_earlier(run)
                continue
            yield self.jobs(self._runs[i]["id"])
            i += 1

    def log(self, job_id):
        """A job's log. GitHub answers with a redirect to storage, which is
        followed without the token."""
        opener = urllib.request.build_opener(NoRedirect).open
        try:
            url = f"{self.api}/repos/{self.repo}/actions/jobs/{job_id}/logs"
            return request(url, headers=self.headers(), opener=opener, read=read_bounded)
        except urllib.error.HTTPError as e:
            if e.code not in (301, 302, 303, 307, 308):
                raise
            return request(e.headers["Location"], read=read_bounded)


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
    jobs = github.jobs(run_id)
    # A planning failure isn't a canary's state; it says so on every run it happens.
    plan = next((j for j in jobs if j["name"] == PLAN_JOB), None)
    if plan and state(plan["conclusion"]) == "red":
        print("Planning failed.")
        slack.post(planning_failed_text(job_url(server, repo, plan)))
        return
    current = [j for j in jobs if j["name"] not in NOT_CANARIES and state(j["conclusion"])]

    for job in current:
        previous = previous_job(job["name"], github.history(run))
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
            green = previous_job(job["name"], github.history(run), want=("green",))
            green_log = github.log(green["id"]) if green else ""
            green_url = job_url(server, repo, green) if green else ""
            reply = details_text(job, log, green, green_log, green_url)
        except Exception as e:  # the alert is out; say why the details aren't
            reply = f"Couldn't collect the failure details: {slack_escape(type(e).__name__)}. See the run log."
            print(f"::warning::details for {job['name']}: {e!r}")
        slack.post(reply, thread_ts=ts)


if __name__ == "__main__":
    sys.exit(main())
