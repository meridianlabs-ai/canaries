# canaries

Scheduled tests that run our repositories against the **newest releases of their dependencies**, so an upstream release that breaks us shows up within hours, on Slack, instead of on someone's PR.

These jobs deliberately install unvetted packages (no lockfile, no cooldown). This repository is built so that a malicious release landing here finds nothing to steal and can't reach anything else:

- **No secrets in canary jobs.** The only secret is the Slack webhook, held in the `slack` environment and used only by the `notify` job, which runs no third-party code, checks out nothing and reads only the canary results.
- **Read-only token.** The repository's default `GITHUB_TOKEN` permission is `read`; every job declares `contents: read` or less.
- **No caches.** Canary jobs neither restore nor save the Actions cache (`enable-cache: false`). Nothing here restores a cache.
- **Nothing consumes canary output.** No artifacts from canary jobs are used by any other workflow or repository.
- **GitHub-hosted runners only.**
- **Separate repository on purpose.** GitHub isolates caches, secrets and permissions per repository, so nothing that floats can touch the caches or credentials of the repositories it tests. Those repositories' own CI installs only from their lockfiles.

## How it works

`canaries.yml` lists one entry per check: which repository and ref to check out, how to install with the newest dependencies, which tests to run, and how often (`cadence`). `.github/workflows/canary.yml` reads it on a schedule, runs each due entry as a matrix job, and posts failures to Slack.

Tests that need provider API keys skip themselves here (no keys). Live API tests run in `meridianlabs-ai/actions`, against each repository's lockfile.

## Adding a canary

Add an entry to `canaries.yml`:

```yaml
- name: inspect_ai            # unique; shown in job names and alerts
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

Run one entry by hand: Actions → canary → Run workflow → `only: <name>`.

## Org secrets

Org-level secrets shared with "all repositories" are visible to this repository too. Canary jobs never reference them, but they should be scoped to the repositories that need them.
