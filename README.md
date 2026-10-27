# canaries

Scheduled tests that run [Meridian Labs](https://meridianlabs.ai) and [Inspect](https://inspect.aisi.org.uk) projects against the **newest releases of their dependencies**. When an upstream release breaks one of them, we find out within hours, before it reaches a contributor's pull request or a user.

## Why a separate repository

Our project repositories install dependencies only from their lockfiles, pinned to reviewed versions and refreshed through reviewed updates. That keeps their CI reproducible and limits what a compromised package could reach. But it also means they wouldn't notice an upstream break until the next lockfile update.

The canaries do the opposite: each run installs the latest of everything, with no lockfile and no waiting period for new releases. Those are exactly the runs where a malicious new release would execute, so they live here, isolated from everything else:

- **No secrets.** Canary jobs have no credentials. The only secrets in this repository are the Slack credentials for our alert channel, available only to the job that sends alerts. That job checks out only this repository, without credentials, and runs [`scripts/notify.py`](scripts/notify.py), which uses only the Python standard library: no third-party code. It reads the canary results and logs, and treats log text as untrusted. Job names, by contrast, are trusted repository metadata: GitHub sets them from the matrix the planner builds out of this repository's canary files, canary jobs can't rename them, and alerts go out only for scheduled runs of `main` and manual runs, never for pull requests. [`secrets.yml`](.github/workflows/secrets.yml) fails if any secret other than `github_token` becomes visible to this repository, for example an organization secret shared with all repositories.
- **Read-only token.** Every job's `GITHUB_TOKEN` is read-only.
- **No caches.** Canary jobs neither restore nor save the Actions cache.
- **Nothing downstream.** No other workflow or repository consumes anything a canary produces.
- **GitHub-hosted runners only.**

Because GitHub keeps caches, secrets and permissions separate per repository, a bad package that lands in a canary run can't reach the projects it tests.

## How it works

[`canaries/`](canaries) has one file per canary. Each names the repository and ref to check out, how to install with the newest dependencies, what to run, and how often (every 2 hours or nightly). [`.github/workflows/canary.yml`](.github/workflows/canary.yml) runs the due entries on a schedule and sends an alert when a canary changes state. A nightly canary whose latest scheduled result is red also runs every 2 hours, so a fix shows as recovered within about two hours of landing; once green, it goes back to nightly.

Tests that need secrets or API keys skip themselves here. Those run separately, against each project's lockfile.

A red canary means something upstream changed, not that our code did. Each run logs the exact commit tested and the versions it installed.

## Alerts

After each scheduled run, [`scripts/notify.py`](scripts/notify.py) compares every canary with its result in the most recent earlier scheduled run that ran it (searching back about a month; a canary with no result in that time counts as new, so its first failure alerts), and posts to Slack only when one turns red or recovers; a canary that stays red stays quiet. A canary with variants is red if any part is red and green if every part that ran is green. If the planning job fails, so that no canaries ran, each such run posts a plain "planning failed" message instead. The message names the canary, the repository and commit tested, and links the run. With the bot token `CANARY_SLACK_BOT_TOKEN` (secret, `slack` environment) and the channel ID `CANARY_SLACK_CHANNEL_ID` (repository variable), a red alert also gets a threaded reply with, for each failing part (up to six; the rest are counted, with a link to the run), the failed tests, the end of its log (naming the failed step) and the package versions that changed since that part last passed, escaped, labelled as untrusted, and kept to 12,000 characters. Without both, alerts go to the incoming webhook `CANARY_SLACK_WEBHOOK_URL` as a single message. Manual and pull request runs never alert; **Run workflow** with `test_slack` sends a test message.

## What a canary runs

A canary exists to catch breakage from the newest, unlocked versions of its dependencies. It runs every test and static analysis step its repository's CI runs, as far as it can, and nothing more. It adds no test, marker, flag or checker that CI doesn't run: if a canary needs one, add it to the repository's CI first. "As far as it can" means it skips tests that need secrets or API keys (a canary has none), and it may cover fewer Python versions than CI's matrix: each part runs one Python version, the one in its file. Tests marked flaky are not run either.

Slow tests are the one exception to "nothing more". They are tests CI would run if they weren't so slow, so a canary runs a repository's slow tests (with `--runslow` or the repository's equivalent) even when CI skips them for time. Tests that need secrets or API keys still don't run.

Two CI steps are left out: ruff and prettier. They check only our own code's style, so a run against the newest dependencies can show only the tool's own rule or format changes, which is noise, and each repository's CI already enforces them against its locked version.

Repository checks that read only our own files are left out for the same reason: suppression ledgers, config carve-out ledgers, docstring and override checks, pre-commit hooks, and a rebuilt `dist/` compared to the committed one. A new dependency release can't change what they report. Checks of generated files — schemas, generated types — stay in, because their output depends on the installed packages.

When you add or change a canary, compare it with the repository's `.github/workflows`. [`scripts/test_canaries.py`](scripts/test_canaries.py) fails any canary whose test script calls no type checker (mypy, pyright, tsc) or eslint, so the principle can't quietly drift. A canary whose repository has none sets `static-analysis-exempt` to a reason instead.

## Adding a canary

Add a file to `canaries/`, named after the canary:

```yaml
# canaries/inspect_ai.yml
name: inspect_ai            # unique (letters, digits, . _ -); shown in job names and alerts
repo: UKGovernmentBEIS/inspect_ai
ref: main
cadence: 2h                 # 2h or nightly
python: "3.11"
timeout-minutes: 60
install: |                  # newest releases of everything, ignoring any cooldown
  uv venv
  uv pip install --exclude-newer false -e ".[dev]"
test: |                     # every static analysis tool CI runs, plus the tests
  status=0                  # each check runs; the step fails if any did
  echo "::group::pytest"; uv run --no-sync pytest -ra -n logical || status=1; echo "::endgroup::"
  echo "::group::mypy"; uv run --no-sync mypy src tests || status=1; echo "::endgroup::"
  exit $status
```

Optional fields: `runs-on` (a runner label; default `ubuntu-latest`), `node` (a Node.js version to set up before installing), and `static-analysis-exempt` (a reason string, for a canary whose repository has no type checker or eslint to run; a top-level field, not allowed in a variant). Set environment variables inside `install` or `test` with `export`.

To split a canary into parts that run in parallel, add `variants`: each has a short `label` and may override `python`, `install`, `test`, `runs-on`, `node` or `timeout-minutes`; the rest comes from the top level. Each part is its own job, named `<canary> (<label>)`, but the canary still alerts once: it is red when any part fails, and the alert names the failing parts.

```yaml
variants:
  - label: py311
  - label: py314
    python: "3.14"
```

A pull request runs only the canaries it changes, so a new entry shows its first result on the PR. A change to the workflow or the planner runs every canary; notifier changes run its unit tests instead. To run one canary by hand (all its parts): **Actions → canary → Run workflow**, with `only` set to its name.
