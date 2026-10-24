# canaries

Scheduled tests that run [Meridian Labs](https://meridianlabs.ai) and [Inspect](https://inspect.aisi.org.uk) projects against the **newest releases of their dependencies**. When an upstream release breaks one of them, we find out within hours, before it reaches a contributor's pull request or a user.

## Why a separate repository

Our project repositories install dependencies only from their lockfiles, pinned to reviewed versions and refreshed through reviewed updates. That keeps their CI reproducible and limits what a compromised package could reach. But it also means they wouldn't notice an upstream break until the next lockfile update.

The canaries do the opposite: each run installs the latest of everything, with no lockfile and no waiting period for new releases. Those are exactly the runs where a malicious new release would execute, so they live here, isolated from everything else:

- **No secrets.** Canary jobs have no credentials. The only secrets in this repository are the Slack credentials for our alert channel, available only to the job that sends alerts. That job checks out only this repository, without credentials, and runs [`scripts/notify.py`](scripts/notify.py), which uses only the Python standard library: no third-party code. It reads the canary results and logs, and treats log text as untrusted.
- **Read-only token.** Every job's `GITHUB_TOKEN` is read-only.
- **No caches.** Canary jobs neither restore nor save the Actions cache.
- **Nothing downstream.** No other workflow or repository consumes anything a canary produces.
- **GitHub-hosted runners only.**

Because GitHub keeps caches, secrets and permissions separate per repository, a bad package that lands in a canary run can't reach the projects it tests.

## How it works

[`canaries/`](canaries) has one file per canary. Each names the repository and ref to check out, how to install with the newest dependencies, what to run, and how often (every 2 hours or nightly). [`.github/workflows/canary.yml`](.github/workflows/canary.yml) runs the due entries on a schedule and sends an alert when a canary changes state.

Tests that need API keys or external services skip themselves here. Those run separately, against each project's lockfile.

A red canary means something upstream changed, not that our code did. Each run logs the exact commit tested and the versions it installed.

## Alerts

After each scheduled run, [`scripts/notify.py`](scripts/notify.py) compares every canary with its result in the most recent earlier scheduled run that ran it (searching back about a month; a canary with no result in that time counts as new, so its first failure alerts) and posts to Slack only when one turns red or recovers; a canary that stays red stays quiet. If the planning job fails, so that no canaries ran, each such run posts a plain "planning failed" message instead. The message names the canary, the repository and commit tested, and links the run. With the bot token `CANARY_SLACK_BOT_TOKEN` (secret, `slack` environment) and the channel ID `CANARY_SLACK_CHANNEL_ID` (repository variable), a red alert also gets a threaded reply with the failed tests, the end of the job's log (naming the failed step) and the package versions that changed since the canary last passed, escaped and labelled as untrusted. Without both, alerts go to the incoming webhook `CANARY_SLACK_WEBHOOK_URL` as a single message. Manual and pull request runs never alert; **Run workflow** with `test_slack` sends a test message.

## Adding a canary

Add a file to `canaries/`, named after the canary:

```yaml
# canaries/inspect_ai.yml
name: inspect_ai            # unique; shown in job names and alerts
repo: UKGovernmentBEIS/inspect_ai
ref: main
cadence: 2h                 # 2h or nightly
python: "3.11"
timeout-minutes: 60
install: |                  # newest releases of everything, ignoring any cooldown
  uv venv
  uv pip install --exclude-newer false -e ".[dev]"
test: |
  uv run --no-sync pytest -ra -n logical
```

Optional fields: `runs-on` (a runner label; default `ubuntu-latest`) and `node` (a Node.js version to set up before installing). Set environment variables inside `install` or `test` with `export`.

A pull request runs only the canaries it changes, so a new entry shows its first result on the PR. A change to the workflow or the planner runs every canary; notifier changes run its unit tests instead. To run one entry by hand: **Actions → canary → Run workflow**, with `only` set to its name.
