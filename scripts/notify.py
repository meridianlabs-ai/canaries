"""Post canary red results and recoveries to Slack.

Runs in the workflow's notify job after a scheduled run. A canary with
variants runs as several jobs named `<canary> (<label>)`, its parts; it is
red if any part is red and green if every part that ran is green. Each
canary's state and failed tests are compared with the most recent earlier
scheduled run that ran it. A message goes out when a canary turns red, when
the set of its failed tests changes, and when it recovers. A canary that
stays red with the same failures gets no new message; the last red post is
edited to count the repeats. Standard library only.

A red part's failed tests come from the `canary-failed:` lines its job writes
from the pytest JUnit report. The failure set of a canary is the (part,
test id) pairs of its red parts; a red part with no ids counts as one "red,
no test ids" item. notify keeps its state in its own job log: one
`canary-notify: <canary> <state> <hash> <count> <ts>` line per canary, which
the next run reads to compare failure sets and to count the repeats.

With CANARY_SLACK_BOT_TOKEN and CANARY_SLACK_CHANNEL_ID, each red alert gets
a threaded reply with, for each failing part, the failed tests, the end of
its log and the package versions that changed since that part last passed.
Otherwise the message goes to CANARY_SLACK_WEBHOOK_URL on its own, with no
repeat count. The canary job marks the lines this reads (`canary-tested:`,
`canary-installed:`, `canary-failed:`), so each log is read as a whole,
never split into steps.

Job logs come from runs that installed unreviewed packages, so their text is
treated as untrusted: it is stripped of control characters, truncated,
escaped for Slack and posted only inside code blocks under a label. Test ids
are only hashed and compared, never posted.
"""

import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from collections import namedtuple
from datetime import datetime
from zoneinfo import ZoneInfo

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
LABEL_CHARS = 40  # a part's label as shown
MAX_PARTS = 6  # failing parts shown in detail and named in the alert; the rest are counted
REPLY_CHARS = 12000  # the whole threaded reply, after escaping; Slack truncates at 40,000

UNTRUSTED = "Untrusted log output from a run that installed unreviewed packages."
TESTED_MARKER = "canary-tested: "
INSTALLED_MARKER = "canary-installed: "
FAILED_MARKER = "canary-failed: "
NOTIFY_MARKER = "canary-notify: "
NO_TEST_IDS = "red, no test ids"
TIMEZONE = ZoneInfo("America/New_York")

TIMESTAMP = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.\d+)?Z ?")
ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
TESTED = re.compile(r"^([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@([0-9a-f]{40})$")
FAILED_TEST = re.compile(r"^(?:FAILED|ERROR) (\S+)")
INSTALLED = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*) (\S+)$")
# The job names scripts/plan.py generates: `<canary>` or `<canary> (<label>)`,
# both parts matching its NAME pattern.
JOB_NAME = re.compile(r"([A-Za-z0-9][A-Za-z0-9._-]*)(?: \(([A-Za-z0-9][A-Za-z0-9._-]*)\))?")
# A `canary-notify:` state line this script writes and its next run reads.
RECORD = re.compile(r"canary-notify: ([A-Za-z0-9][A-Za-z0-9._-]*) (red|green) (-|[0-9a-f]{64}) (\d+) (-|\d+\.\d+)")


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


def canary_and_part(job_name):
    """(canary, part label) from a job name `<canary> (<label>)`; a canary
    without variants has one job, named after it, and no label. None for a
    name the planner can't generate, or one of the workflow's own jobs.

    Job names are trusted repository metadata, not canary output: GitHub sets
    them from the matrix the plan job builds from this repository's canary
    files at the run's commit, canary jobs (read-only token) can't rename
    jobs, and the notify job runs only for scheduled runs of main and
    explicit dispatches, never for pull requests. The strict pattern only
    keeps out names nothing here generates.
    """
    match = JOB_NAME.fullmatch(job_name)
    if not match or match.group(1) in NOT_CANARIES:
        return None
    return match.groups()


def by_canary(jobs):
    """{canary: its jobs}, in job order; jobs whose names don't parse are left out."""
    canaries = {}
    for job in jobs:
        if parsed := canary_and_part(job["name"]):
            canaries.setdefault(parsed[0], []).append(job)
    return canaries


def canary_state(jobs):
    """'red' if any of a canary's jobs is red, 'green' if every one that ran
    is green, None if none ran."""
    states = {state(job["conclusion"]) for job in jobs} - {None}
    return "red" if "red" in states else "green" if states else None


def previous_run(canary, history):
    """The jobs of the newest run in `history` that ran any part of `canary`.

    `history` is an iterable of job lists, newest run first; None if none ran
    it. The record of the canary's last result and its last state both come
    from this run.
    """
    for jobs in history:
        if canary_state(by_canary(jobs).get(canary, [])):
            return jobs
    return None


def previous_state(canary, history):
    """The canary's state in the newest run of `history` that ran any part of it.

    `history` is an iterable of job lists, newest run first; None if none ran it.
    """
    jobs = previous_run(canary, history)
    return canary_state(by_canary(jobs).get(canary, [])) if jobs else None


# --- log text ---------------------------------------------------------------


def slack_escape(text):
    """Escape the characters Slack treats as markup in message text.

    `&`, `<` and `>` are the escapes Slack documents; without them log text
    could form mentions (<!channel>) or links. Backticks would close the code
    block the text sits in, so they become quotes.
    """
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("`", "'")


def cut(text, limit):
    """Escaped text cut to `limit` characters, not ending in half an escape."""
    if len(text) <= limit:
        return text
    return re.sub(r"&[a-z]*$", "", text[: limit - 1]) + "…"


def plain(name, limit=NAME_CHARS):
    """A job or step name for display: one line, no markup, at most `limit`
    characters after escaping (plus the backticks).

    Shown in an inline code span, where Slack applies no formatting, so the
    underscores in names like inspect_ai stay as they are.
    """
    name = slack_escape(re.sub(r"[\x00-\x1f\x7f]+", " ", name)).replace("*", "").replace("~", "").strip()
    return f"`{cut(name, limit)}`"


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
    """Lines in a code block, escaped first so max_chars bounds the escaped
    text; each line is cut to a quarter of that, so a few always fit."""
    return "```\n" + fit([cut(slack_escape(line), max(max_chars // 4, 20)) for line in lines], max_chars, keep) + "\n```"


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


# --- failure set and state record -------------------------------------------


Record = namedtuple("Record", "canary state hash count ts")


def failed_ids(log):
    """Unique `canary-failed:` ids from a log, in order (cleaned lines)."""
    ids = []
    for line in log.splitlines():
        text = clean(line)
        if text.startswith(FAILED_MARKER):
            id = text[len(FAILED_MARKER) :].strip()
            if id and id not in ids:
                ids.append(id)
    return ids


def failure_set(parts, read_log):
    """A canary's failure set as {(label, id)}, or None if a red part's log
    can't be read.

    `read_log(job)` returns a job's log text, or None when it can't be read.
    label is a part's label, "" for a canary without parts. A red part with
    no `canary-failed:` id contributes one (label, "red, no test ids") item.
    """
    items = set()
    for job in parts:
        if state(job["conclusion"]) != "red":
            continue
        log = read_log(job)
        if log is None:
            return None
        label = canary_and_part(job["name"])[1] or ""
        ids = failed_ids(log)
        items |= {(label, id) for id in ids} if ids else {(label, NO_TEST_IDS)}
    return items


def set_hash(items):
    """sha256 hex of a failure set, or '-' when it is None (unknown)."""
    if items is None:
        return "-"
    text = "\n".join(sorted(f"{label}\t{id}" for label, id in items))
    return hashlib.sha256(text.encode()).hexdigest()


def record_line(record):
    """The `canary-notify:` log line for one canary's result this run."""
    return f"{NOTIFY_MARKER}{record.canary} {record.state} {record.hash} {record.count} {record.ts}"


def records(log):
    """{canary: Record} from a notify job's log; malformed lines are ignored."""
    found = {}
    for line in log.splitlines():
        match = RECORD.fullmatch(clean(line))
        if match:
            canary, result, hash, count, ts = match.groups()
            found[canary] = Record(canary, result, hash, int(count), ts)
    return found


def repeat_line(count, run):
    """The line added to a repeated red post: the count and the run's time."""
    stamp = run.get("run_started_at") or run["created_at"]
    when = datetime.fromisoformat(stamp.replace("Z", "+00:00")).astimezone(TIMEZONE)
    plural = "" if count == 1 else "s"
    return f"Same failures in {count} more run{plural}, last at {when:%b %-d, %-I:%M %p} ET"


# --- messages ---------------------------------------------------------------


def part_list(labels):
    """Up to MAX_PARTS labels, each bounded, and a count of the rest."""
    shown = ", ".join(plain(label, LABEL_CHARS) for label in labels[:MAX_PARTS])
    more = len(labels) - MAX_PARTS
    return f"{shown} and {more} more" if more > 0 else shown


def alert_text(name, red, url, commit, failing_parts=()):
    """The channel message: canary, its failing parts, what it tested, and the run."""
    if red:
        parts = f" ({part_list(failing_parts)})" if failing_parts else ""
        head = f":rotating_light: Canary {plain(name)} is failing on the newest releases{parts}."
    else:
        head = f":white_check_mark: Canary {plain(name)} recovered."
    if commit:
        repo, sha = commit
        head += f" Tested <https://github.com/{repo}/commit/{sha}|{repo}@{sha[:10]}>."
    return f"{head} <{url}|Run log>"


def planning_failed_text(job_url):
    return f":warning: Canary planning failed, so no canaries ran. <{job_url}|Run log>"


def job_details(job, log, green_job, green_log, green_url, share=1):
    """Failed tests, the end of the log and the changed versions for one red
    job, each in 1/share of its budget."""
    parts = []
    lines = output_lines(log)

    tests, more = failed_tests(lines)
    if tests:
        count = f"{len(tests)}+" if more else str(len(tests))
        parts.append(f"*Failed tests* ({count}):\n" + code_block(tests, TESTS_CHARS // share))

    step = failing_step(job)
    where = f" (failed step {plain(step['name'])})" if step else ""
    # Leave out the version list and pytest's list of skipped tests.
    tail = [line for line in lines if line.strip() and not line.startswith((INSTALLED_MARKER, "SKIPPED ["))]
    tail = tail[-max(LOG_TAIL_LINES // share, 1) :]
    parts.append(f"*Last lines of the job*{where}:\n" + code_block(tail, LOG_CHARS // share, keep="tail"))

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
            parts.append(label + "\n" + code_block(diff, VERSIONS_CHARS // share) if diff else label + " none.")
    return parts


def within(sections, limit, note):
    """Sections joined by blank lines; if that's over `limit` characters,
    whole sections are dropped from the end and `note` added instead."""
    text = "\n\n".join(sections)
    while len(text) > limit and len(sections) > 1:
        sections = sections[:-1]
        text = "\n\n".join(sections + [note])
    return text


def details_text(failing, ran=1, run_url=""):
    """The threaded reply for a canary that turned red.

    `failing` holds (job, url, log, green_job, green_log, green_url) for each
    red job; `ran` counts the canary's jobs with a result. A canary with parts
    gets a section for each of its first MAX_PARTS failing parts, which share
    the bounds of one job; the rest are counted, with the run's link. The
    whole reply stays within REPLY_CHARS.
    """
    texts = [f"_{UNTRUSTED}_"]
    note = f"_Some details left out to keep this short; see <{run_url}|the run>._" if run_url else "_Some details left out to keep this short._"
    if len(failing) == 1 and canary_and_part(failing[0][0]["name"])[1] is None:
        job, _, *rest = failing[0]
        return within(texts + job_details(job, *rest), REPLY_CHARS, note)
    labels = [canary_and_part(job["name"])[1] or job["name"] for job, *_ in failing]
    texts.append(f"*Failing parts* ({len(failing)} of {ran}): {part_list(labels)}")
    shown = failing[:MAX_PARTS]
    for (job, url, *rest), label in zip(shown, labels):
        texts.append(f"*Part* {plain(label, LABEL_CHARS)} (<{url}|Run log>)")
        texts += job_details(job, *rest, share=len(shown))
    if len(failing) > len(shown):
        more = len(failing) - len(shown)
        where = f": see <{run_url}|the run>" if run_url else ""
        texts.append(f"_{more} more failing part{'s' if more != 1 else ''} not shown{where}._")
    return within(texts, REPLY_CHARS, note)


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

    def _fetch_earlier(self, run, per_page=HISTORY_PAGE):
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
            f"?event=schedule&per_page={per_page}&created=%3C%3D{before}"
        )
        new = [r for r in data["workflow_runs"] if r["id"] not in seen]
        self._runs += new
        self._exhausted = not new

    def history(self, run, limit=HISTORY_LIMIT):
        """Job lists of the scheduled runs created before `run`, newest first.

        Ends when the history does, or after `limit` runs, which only bounds
        the API calls.
        """
        i = 0
        while i < limit:
            if i == len(self._runs):
                if self._exhausted:
                    return
                self._fetch_earlier(run, min(HISTORY_PAGE, limit + 1))  # +1: the page can include `run`
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
            error = f"chat.postMessage failed: {response.get('error')}"
            if not self.webhook:
                raise RuntimeError(error)
            # Still get the alert out: webhook from here on, without threads.
            print(f"::warning::{error}; falling back to the webhook without thread replies.")
            self.bot_token = None
            request(self.webhook, json.dumps({k: body[k] for k in ("text", "unfurl_links", "unfurl_media")}).encode(), {"Content-Type": "application/json"})
            return None
        return response["ts"]

    def update(self, ts, text):
        """Edit the message at `ts` (chat.update); a no-op on the webhook path.

        On failure it warns and returns: the alert is already posted, so the
        edit just carries the repeat count, which the next run tries again.
        """
        if not self.threads:
            return
        body = {"channel": self.channel, "ts": ts, "text": text, "link_names": False, "unfurl_links": False, "unfurl_media": False}
        response = json.loads(
            request(
                "https://slack.com/api/chat.update",
                json.dumps(body).encode(),
                {"Content-Type": "application/json; charset=utf-8", "Authorization": f"Bearer {self.bot_token}"},
            )
        )
        if not response.get("ok"):
            print(f"::warning::chat.update failed: {response.get('error')}")


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

    # A manual re-post of an earlier run's red canaries, e.g. one that alerted
    # before the threaded details existed. No state comparison.
    repost = env.get("REPOST_RUN", "").strip()
    if repost and not repost.isdigit():
        print(f"::error::repost_run must be a run ID, not {repost!r}")
        return 1
    if repost:
        run_id = repost

    github = GitHub(env["GITHUB_API_URL"], repo, env["GH_TOKEN"])
    run = github.get(f"actions/runs/{run_id}")
    jobs = github.jobs(run_id)
    # A planning failure isn't a canary's state; it says so on every run it happens.
    plan = next((j for j in jobs if j["name"] == PLAN_JOB), None)
    if plan and state(plan["conclusion"]) == "red":
        print("Planning failed.")
        slack.post(planning_failed_text(job_url(server, repo, plan)))
        return
    read = {}  # job id -> log text, or None when it couldn't be read

    def read_log(job):
        if job["id"] not in read:
            try:
                read[job["id"]] = github.log(job["id"])
            except Exception as e:  # still alert, without the commit and details
                read[job["id"]] = None
                print(f"::warning::log for {job['name']}: {e!r}")
        return read[job["id"]]

    def log(job):
        return read_log(job) or ""

    def current_alert(name, parts, red):
        """The channel message for a canary's result this run."""
        ran = [j for j in parts if state(j["conclusion"])]
        failing = [j for j in ran if state(j["conclusion"]) == "red"]
        first = (failing or ran)[0]
        # A canary with parts links the run, which lists them all.
        url = job_url(server, repo, first) if len(parts) == 1 else f"{server}/{repo}/actions/runs/{first['run_id']}"
        labels = [label for label in (canary_and_part(j["name"])[1] for j in failing) if label]
        return alert_text(name, red, url, tested_commit(log(first)), labels)

    def announce(name, parts, red):
        """Post the alert, and for a red canary its threaded reply. Returns
        the channel message ts, or None on the webhook path."""
        ts = slack.post(current_alert(name, parts, red))
        if not (red and ts):
            return ts
        ran = [j for j in parts if state(j["conclusion"])]
        failing = [j for j in ran if state(j["conclusion"]) == "red"]
        canary_run = f"{server}/{repo}/actions/runs/{failing[0]['run_id']}"
        try:
            details = []
            for i, job in enumerate(failing):
                if i >= MAX_PARTS:  # only counted in the reply
                    details.append((job, job_url(server, repo, job), "", None, "", ""))
                    continue
                green = previous_job(job["name"], github.history(run), want=("green",))
                green_log = github.log(green["id"]) if green else ""
                green_url = job_url(server, repo, green) if green else ""
                details.append((job, job_url(server, repo, job), log(job), green, green_log, green_url))
            reply = details_text(details, len(ran), canary_run)
        except Exception as e:  # the alert is out; say why the details aren't
            reply = f"Couldn't collect the failure details: {slack_escape(type(e).__name__)}. See the run log."
            print(f"::warning::details for {name}: {e!r}")
        slack.post(reply, thread_ts=ts)
        return ts

    def read_record(name, jobs):
        """The canary's record from its last run's notify job, or None if it
        can't be read (no completed notify job, read error, or no line)."""
        notify_job = next((j for j in jobs if j["name"] == "notify"), None)
        if not notify_job or notify_job["conclusion"] is None:
            print(f"::warning::{name}: its last run has no completed notify job")
            return None
        log = read_log(notify_job)  # warns on a read error
        if log is None:
            return None
        record = records(log).get(name)
        if record is None:
            print(f"::warning::{name}: no record in its last notify log")
        return record

    for name, parts in by_canary(jobs).items():
        now = canary_state(parts)
        if now is None:
            continue
        if repost:
            if now == "red":
                print(f"{name}: now red")
                announce(name, parts, True)
            continue

        try:
            previous = previous_run(name, github.history(run))
        except Exception as e:  # unknown history: red posts, green doesn't
            print(f"::warning::history for {name}: {e!r}")
            previous = None
        before = canary_state(by_canary(previous).get(name, [])) if previous else None

        if now == "green":
            if before == "red":
                print(f"{name}: now green")
                announce(name, parts, False)
            else:
                print(f"{name}: still green")
            print(record_line(Record(name, "green", "-", 0, "-")))
            continue

        hash = set_hash(failure_set(parts, read_log))
        if before == "red":
            record = read_record(name, previous)
            if record and record.state == "red" and record.hash != "-" and record.hash == hash:
                count = record.count + 1
                print(f"{name}: still red, same failures (x{count})")
                if record.ts != "-":  # the webhook path left no message to edit
                    slack.update(record.ts, f"{current_alert(name, parts, True)}\n{repeat_line(count, run)}")
                print(record_line(Record(name, "red", hash, count, record.ts)))
                continue

        print(f"{name}: now red")
        ts = announce(name, parts, True)
        print(record_line(Record(name, "red", hash, 0, ts or "-")))


if __name__ == "__main__":
    sys.exit(main())
