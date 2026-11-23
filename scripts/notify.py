"""Post the canary table to Slack.

Runs in the workflow's notify job after a scheduled run. A canary with
variants runs as several jobs named `<canary> (<label>)`, its parts; it is
red if any part is red and green if every part that ran is green. Each
canary's state and failed tests are compared with the most recent earlier
scheduled run that ran it.

The post is a table of every canary that has a result: its state in this
run, else its last result in the earlier runs. A new table goes out when a
canary turns red, when the set of a red canary's failed tests changes, when
a canary recovers, and after every nightly run. Its text line names those
changes. Otherwise notify edits the latest table, so that its cells link the
newest runs. Standard library only.

A red part's failed tests come from the `canary-failed:` lines its job writes
from the pytest JUnit report. The failure set of a canary is the (part,
test id) pairs of its red parts; a red part with no ids counts as one "red,
no test ids" item. notify keeps its state in its own job log: one
`canary-notify: <canary> <state> <hash>` line per canary that ran, which the
next run reads to compare failure sets, and one `canary-table: <ts> <text>`
line for the table it posted or edited, which the next run edits. An edit
updates the counts in the text line and keeps its changes, so that a reader
of the channel never misses them; the cells and their links update too.

A canary's previous state, red or green, comes from the earlier runs' job
results. The `canary-notify:` record only compares a red canary's failed
tests. So a canary that recovers shows as recovered even when its record
cannot be read. If notify cannot read the earlier runs, a red canary shows
as turned red and none as recovered. If it cannot read a red canary's last
record, its failures show as changed. If it cannot read the latest table's
ts, it posts a new table.

With CANARY_SLACK_BOT_TOKEN and CANARY_SLACK_CHANNEL_ID, the table is a
Block Kit table, and each canary that turned red or whose failures changed
gets a threaded reply with, for each failing part, the failed tests and the
package versions that changed since that part last passed. Otherwise the
text line and the table as plain lines go to CANARY_SLACK_WEBHOOK_URL, with
no thread and no edits. The canary job marks the lines this reads
(`canary-tested:`, `canary-installed:`, `canary-failed:`), so each log is
read as a whole, never split into steps.

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

RED = {"failure", "timed_out"}
GREEN = {"success"}
PLAN_JOB = "plan"
NOT_CANARIES = {PLAN_JOB, "notify"}  # jobs in the workflow that aren't canaries
HISTORY_PAGE = 100
HISTORY_LIMIT = 400  # earlier scheduled runs searched for a canary's last result (about a month)

LINE_CHARS = 300
NAME_CHARS = 80
MAX_TESTS = 100
LOG_HEAD_BYTES = 8 << 20  # a log's first and last bytes kept; the middle of a huge log is dropped
LOG_TAIL_BYTES = 24 << 20
TESTS_CHARS = 1200
VERSIONS_CHARS = 1500
LABEL_CHARS = 40  # a part's label as shown
MAX_PARTS = 6  # failing parts shown in detail and named in the alert; the rest are counted
REPLY_CHARS = 12000  # the whole threaded reply, after escaping; Slack truncates at 40,000

UNTRUSTED = "Untrusted log output from a run that installed unreviewed packages."
TESTED_MARKER = "canary-tested: "
INSTALLED_MARKER = "canary-installed: "
FAILED_MARKER = "canary-failed: "
NOTIFY_MARKER = "canary-notify: "
TABLE_MARKER = "canary-table: "
NO_TEST_IDS = "red, no test ids"
NIGHTLY = "30 5 * * *"  # the schedule after which a new table always goes out
BAND = 5  # canaries in each band of the table: a row of names over a row of dots
DOTS = {"red": "red_circle", "green": "large_green_circle"}  # Slack emoji names
PLAIN_DOTS = {"red": "🔴", "green": "🟢"}
CANARIES = os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "canaries")

TIMESTAMP = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.\d+)?Z ?")
ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
TESTED = re.compile(r"^([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@([0-9a-f]{40})$")
FAILED_TEST = re.compile(r"^(?:FAILED|ERROR) (\S+)")
INSTALLED = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*) (\S+)$")
# The job names scripts/plan.py generates: `<canary>` or `<canary> (<label>)`,
# both parts matching its NAME pattern.
JOB_NAME = re.compile(r"([A-Za-z0-9][A-Za-z0-9._-]*)(?: \(([A-Za-z0-9][A-Za-z0-9._-]*)\))?")
# The state lines this script writes and its next run reads. Runs before the
# table also wrote a repeat count and a ts after the hash; they are ignored.
RECORD = re.compile(r"canary-notify: ([A-Za-z0-9][A-Za-z0-9._-]*) (red|green) (-|[0-9a-f]{64})(?: \d+ (?:-|\d+\.\d+))?")
# The table's ts and its text line, whose changes are kept when a later run
# edits it. Canary names hold only [A-Za-z0-9._-].
TABLE = re.compile(r"canary-table: (\d+\.\d+) Canaries: \d+ red, \d+ green\.([A-Za-z0-9 ,.:_-]*)")


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


def clean(line, limit=LINE_CHARS):
    """A log line without its timestamp, colors, control characters, and length
    over `limit`. A caller that compares ids passes `limit=None` to keep the
    full text."""
    line = CONTROL.sub("", ANSI.sub("", TIMESTAMP.sub("", line, count=1)))
    if limit is not None and len(line) > limit:
        line = line[: limit - 1] + "…"
    return line


def fit(lines, max_chars):
    """Join lines within max_chars, dropping from the tail with a note."""
    kept, used = [], 0
    for line in lines:
        if used + len(line) + 1 > max_chars:
            break
        kept.append(line)
        used += len(line) + 1
    dropped = len(lines) - len(kept)
    return "\n".join(kept + ([f"… {dropped} more line{'s' if dropped != 1 else ''}"] if dropped else []))


def code_block(lines, max_chars):
    """Lines in a code block, escaped first so max_chars bounds the escaped
    text; each line is cut to a quarter of that, so a few always fit."""
    return "```\n" + fit([cut(slack_escape(line), max(max_chars // 4, 20)) for line in lines], max_chars) + "\n```"


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


# --- failure set and state record -------------------------------------------


Record = namedtuple("Record", "canary state hash")


def failed_ids(log):
    """Unique `canary-failed:` ids from a log, in order (cleaned lines)."""
    ids = []
    for line in log.splitlines():
        text = clean(line, limit=None)
        if text.startswith(FAILED_MARKER):
            test_id = text[len(FAILED_MARKER) :].strip()
            if test_id and test_id not in ids:
                ids.append(test_id)
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
        items |= {(label, test_id) for test_id in ids} if ids else {(label, NO_TEST_IDS)}
    return items


def set_hash(items):
    """sha256 hex of a failure set, or '-' when it is None (unknown)."""
    if items is None:
        return "-"
    text = "\n".join(sorted(f"{label}\t{test_id}" for label, test_id in items))
    return hashlib.sha256(text.encode()).hexdigest()


def record_line(record):
    """The `canary-notify:` log line for one canary's result this run."""
    return f"{NOTIFY_MARKER}{record.canary} {record.state} {record.hash}"


def records(log):
    """{canary: Record} from a notify job's log; malformed lines are ignored."""
    matches = (RECORD.fullmatch(clean(line)) for line in log.splitlines())
    return {match.group(1): Record(*match.groups()) for match in matches if match}


def table_line(ts, text):
    """The `canary-table:` log line for the table this run posted or edited."""
    return f"{TABLE_MARKER}{ts} {text}"


def table_record(log):
    """(ts, changes) from the last `canary-table:` line of a notify job's log,
    or None. changes is the text line after its counts, "" for none. The
    line is read whole: with many changes it is longer than LINE_CHARS."""
    found = [match.groups() for match in (TABLE.fullmatch(clean(line, limit=None)) for line in log.splitlines()) if match]
    return found[-1] if found else None


# --- messages ---------------------------------------------------------------


Cell = namedtuple("Cell", "canary state url")  # one canary in the table


def short_name(canary):
    """The name shown in the table: without the `inspect_` prefix."""
    return canary.removeprefix("inspect_")


def bands(cells):
    """The cells in bands of BAND."""
    return [cells[i : i + BAND] for i in range(0, len(cells), BAND)]


def summary_text(cells, turned_red=(), changed=(), recovered=()):
    """The table's text line: the counts, then the changes this run, by full name."""
    red = sum(cell.state == "red" for cell in cells)
    changes = (("Turned red", turned_red), ("Failures changed", changed), ("Recovered", recovered))
    return f"Canaries: {red} red, {len(cells) - red} green." + "".join(f" {label}: {', '.join(sorted(names))}." for label, names in changes if names)


def rich_cell(element):
    return {"type": "rich_text", "elements": [{"type": "rich_text_section", "elements": [element]}]}


def table_blocks(text, cells):
    """The text line, then a table block: for each band, a row of names, each
    linking that canary's last run, over a row of red and green dots. A short
    last band is padded with empty cells."""
    width = min(len(cells), BAND)
    rows = [
        row + [{"type": "raw_text", "text": ""}] * (width - len(row))
        for band in bands(cells)
        for row in (
            [rich_cell({"type": "link", "url": cell.url, "text": short_name(cell.canary)}) for cell in band],
            [rich_cell({"type": "emoji", "name": DOTS[cell.state]}) for cell in band],
        )
    ]
    return [{"type": "section", "text": {"type": "plain_text", "text": text}}, {"type": "table", "rows": rows}]


def plain_table(text, cells):
    """The text line and the table as plain lines, for the webhook: one line
    per band, each canary a dot and its name, linking its last run."""
    lines = ["  ".join(f"{PLAIN_DOTS[cell.state]} <{cell.url}|{short_name(cell.canary)}>" for cell in band) for band in bands(cells)]
    return "\n".join([text, *lines])


def part_list(labels):
    """Up to MAX_PARTS labels, each bounded, and a count of the rest."""
    shown = ", ".join(plain(label, LABEL_CHARS) for label in labels[:MAX_PARTS])
    more = len(labels) - MAX_PARTS
    return f"{shown} and {more} more" if more > 0 else shown


def reply_head(name, change, url, commit):
    """The first line of a canary's threaded reply: the canary, its change,
    what it tested, and its run."""
    tested = f" Tested <https://github.com/{commit[0]}/commit/{commit[1]}|{commit[0]}@{commit[1][:10]}>." if commit else ""
    return f"Canary {plain(name)} {change}.{tested} <{url}|Run log>"


def planning_failed_text(job_url):
    return f":warning: Canary planning failed, so no canaries ran. <{job_url}|Run log>"


def job_details(log, green_job, green_log, green_url, share=1):
    """Failed tests and the changed versions for one red job, each in 1/share
    of its budget."""
    parts = []
    lines = output_lines(log)

    tests, more = failed_tests(lines)
    if tests:
        count = f"{len(tests)}+" if more else str(len(tests))
        parts.append(f"*Failed tests* ({count}):\n" + code_block(tests, TESTS_CHARS // share))

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


def details_text(head, failing, ran=1, run_url=""):
    """The threaded reply for a red canary: `head`, then the details.

    `failing` holds (job, url, log, green_job, green_log, green_url) for each
    red job; `ran` counts the canary's jobs with a result. A canary with parts
    gets a section for each of its first MAX_PARTS failing parts, which share
    the bounds of one job; the rest are counted, with the run's link. The
    whole reply stays within REPLY_CHARS.
    """
    texts = [head, f"_{UNTRUSTED}_"]
    note = f"_Some details left out to keep this short; see <{run_url}|the run>._" if run_url else "_Some details left out to keep this short._"
    if len(failing) == 1 and canary_and_part(failing[0][0]["name"])[1] is None:
        _, _, *rest = failing[0]
        return within(texts + job_details(*rest), REPLY_CHARS, note)
    labels = [canary_and_part(job["name"])[1] or job["name"] for job, *_ in failing]
    texts.append(f"*Failing parts* ({len(failing)} of {ran}): {part_list(labels)}")
    shown = failing[:MAX_PARTS]
    for (job, url, *rest), label in zip(shown, labels):
        texts.append(f"*Part* {plain(label, LABEL_CHARS)} (<{url}|Run log>)")
        texts += job_details(*rest, share=len(shown))
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

    def post(self, text, blocks=None, thread_ts=None, webhook_text=None):
        """Post a message; returns its ts when posted with the bot token.

        `blocks` go only with the bot token. The webhook gets `webhook_text`,
        else `text`.
        """
        if self.posted:
            time.sleep(1)  # Slack allows about one message a second per channel
        self.posted = True
        plain_body = {"text": webhook_text or text, "unfurl_links": False, "unfurl_media": False}
        if not self.threads:
            request(self.webhook, json.dumps(plain_body).encode(), {"Content-Type": "application/json"})
            return None
        body = {"text": text, "unfurl_links": False, "unfurl_media": False, "channel": self.channel, "link_names": False}
        if blocks:
            body["blocks"] = blocks
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
            # Still get the post out: webhook from here on, without threads.
            print(f"::warning::{error}; falling back to the webhook without thread replies.")
            self.bot_token = None
            request(self.webhook, json.dumps(plain_body).encode(), {"Content-Type": "application/json"})
            return None
        return response["ts"]

    def update(self, ts, text, blocks):
        """Edit the message at `ts` (chat.update); a no-op on the webhook path.

        On a failed edit it warns and returns: the table is already posted, so
        the edit only refreshes its counts and links, which the next run tries
        again. A failed edit is a not-ok reply or a transport error from
        request().
        """
        if not self.threads:
            return
        body = {"channel": self.channel, "ts": ts, "text": text, "blocks": blocks, "link_names": False, "unfurl_links": False, "unfurl_media": False}
        try:
            response = json.loads(
                request(
                    "https://slack.com/api/chat.update",
                    json.dumps(body).encode(),
                    {"Content-Type": "application/json; charset=utf-8", "Authorization": f"Bearer {self.bot_token}"},
                )
            )
            if not response.get("ok"):
                print(f"::warning::chat.update failed: {response.get('error')}")
        except Exception as e:
            print(f"::warning::chat.update failed: {e!r}")


def job_url(server, repo, job):
    return f"{server}/{repo}/actions/runs/{job['run_id']}/job/{job['id']}"


def canary_names(directory=CANARIES):
    """The canaries in this repository, by file name, in file order."""
    return sorted(name.removesuffix(".yml") for name in os.listdir(directory) if name.endswith(".yml"))


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
        text = "Canaries test message: alerts are wired up. Every cell links this run."
        cells = [Cell(name, "green", run_url) for name in canary_names()]
        ts = slack.post(text, table_blocks(text, cells), webhook_text=plain_table(text, cells))
        if ts:
            slack.post("Test reply: the failure details of a canary go in the table's thread.", thread_ts=ts)
        print(f"Posted a test message {'with a thread reply' if ts else 'through the webhook'}.")
        return

    # A manual re-post of an earlier run's table, with every red canary
    # shown as turned red and given a threaded reply. No state comparison.
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
            except Exception as e:  # still post, without the commit and details
                read[job["id"]] = None
                print(f"::warning::log for {job['name']}: {e!r}")
        return read[job["id"]]

    def log(job):
        return read_log(job) or ""

    def last_run(name, parts):
        """The canary's cell from `parts`, its jobs in one run: its state, and
        a link to its first failing job, else its first job. A canary with
        parts links the run, which lists them all."""
        ran = [j for j in parts if state(j["conclusion"])]
        first = ([j for j in ran if state(j["conclusion"]) == "red"] or ran)[0]
        url = job_url(server, repo, first) if len(parts) == 1 else f"{server}/{repo}/actions/runs/{first['run_id']}"
        return Cell(name, canary_state(parts), url)

    def reply(name, parts, change, ts):
        """Post the threaded reply under the table for a red canary."""
        ran = [j for j in parts if state(j["conclusion"])]
        failing = [j for j in ran if state(j["conclusion"]) == "red"]
        canary_run = f"{server}/{repo}/actions/runs/{failing[0]['run_id']}"
        head = reply_head(name, change, last_run(name, parts).url, tested_commit(log(failing[0])))
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
            text = details_text(head, details, len(ran), canary_run)
        except Exception as e:  # the table is out; say why the details aren't
            text = f"{head}\n\nCouldn't collect the failure details: {slack_escape(type(e).__name__)}. See the run log."
            print(f"::warning::details for {name}: {e!r}")
        slack.post(text, thread_ts=ts)

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

    def latest_table():
        """(ts, changes) of the table the newest earlier run's notify job
        posted or edited, or None if it can't be read."""
        try:
            jobs = next(iter(github.history(run)), [])
        except Exception as e:
            print(f"::warning::history for the latest table: {e!r}")
            return None
        notify_job = next((j for j in jobs if j["name"] == "notify" and j["conclusion"] is not None), None)
        table = table_record(read_log(notify_job) or "") if notify_job else None
        if table is None:
            print("::warning::no table in the last run's notify log")
        return table

    cells, turned_red, changed, recovered, now_parts, state_lines = {}, [], [], [], {}, {}
    for name, parts in by_canary(jobs).items():
        now = canary_state(parts)
        if now is None:
            continue
        cells[name], now_parts[name] = last_run(name, parts), parts
        if repost:
            if now == "red":
                print(f"{name}: red")
                turned_red.append(name)
            continue

        try:
            previous = previous_run(name, github.history(run))
        except Exception as e:  # unknown history: red shows as turned red, green as no change
            print(f"::warning::history for {name}: {e!r}")
            previous = None
        before = canary_state(by_canary(previous).get(name, [])) if previous else None

        if now == "green":
            if before == "red":
                print(f"{name}: now green")
                recovered.append(name)
            else:
                print(f"{name}: still green")
            state_lines[name] = record_line(Record(name, "green", "-"))
            continue

        digest = set_hash(failure_set(parts, read_log))
        if before != "red":
            print(f"{name}: now red")
            turned_red.append(name)
        else:
            record = read_record(name, previous)
            if record and record.state == "red" and record.hash != "-" and record.hash == digest:
                print(f"{name}: still red, same failures")
            else:
                print(f"{name}: still red, failures changed")
                changed.append(name)
        state_lines[name] = record_line(Record(name, "red", digest))

    # Canaries that didn't run this time show their last result.
    for name in [] if repost else sorted(set(canary_names()) - set(cells)):
        try:
            previous = previous_run(name, github.history(run))
        except Exception as e:
            print(f"::warning::history for {name}: {e!r}; left out of the table")
            continue
        if previous:
            cells[name] = last_run(name, by_canary(previous)[name])

    table = [cells[name] for name in sorted(cells)]
    if not table:
        print("No canary has a result; nothing to post.")
        return
    text = summary_text(table, turned_red, changed, recovered)
    # The state for the next run. The canaries this table reports as turned
    # red or changed get theirs only once it is out (a failed post raises),
    # so their change shows again next run.
    reported = sorted(turned_red + changed)
    print("\n".join(line for name, line in state_lines.items() if name not in reported))
    ts = None
    if turned_red or changed or recovered or repost or env.get("SCHEDULE") == NIGHTLY:
        ts = slack.post(text, table_blocks(text, table), webhook_text=plain_table(text, table))
        print(f"Posted the table: {text}")
    elif not slack.threads:
        print("No change, and the webhook can't edit the table; nothing to post.")
    elif latest := latest_table():
        ts, changes = latest
        text = summary_text(table) + changes
        print(f"No change; editing the table at {ts}: this run's counts, its changes kept.")
        slack.update(ts, text, table_blocks(text, table))
    else:
        print("No change, and no table to edit; nothing to post.")
    if ts:
        print(table_line(ts, text))
    print("\n".join(state_lines[name] for name in reported if name in state_lines))
    for name in reported if ts else []:
        reply(name, now_parts[name], "turned red" if name in turned_red else "failures changed", ts)


if __name__ == "__main__":
    sys.exit(main())
