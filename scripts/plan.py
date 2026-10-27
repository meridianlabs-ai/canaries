"""Select the canaries due for this run and print them as a JSON matrix.

Reads one JSON object per line: each file in canaries/ converted with
`yq -o=json -I=0` (preinstalled on GitHub's Ubuntu runners), so this needs
only the standard library.

A canary with `variants` becomes one matrix entry per variant, each named
`<canary> (<label>)`, so its parts run in parallel; scripts/notify.py groups
them back into one canary by that name.

On the 2-hour schedule it also re-runs each nightly canary whose latest
scheduled result is red, so a fix shows as recovered within about two hours;
once green it's back to nightly. That reads earlier runs with the job's
token (GH_TOKEN, `actions: read`), using scripts/notify.py's history and
grouping, so a canary is red here exactly when the notifier says so.
Messages go to stderr; its last line is the number of jobs.
"""

import json
import os
import re
import sys

from notify import GitHub, previous_state

CADENCE_BY_CRON = {"0 */2 * * *": {"2h"}, "30 5 * * *": {"2h", "nightly"}}
RECHECK_CRON = "0 */2 * * *"
# Earlier scheduled runs searched for a nightly canary's latest result: a
# day is about 13 (twelve 2-hour runs and the nightly one), so two days.
RECHECK_RUNS = 30

entries = [json.loads(line) for line in open(sys.argv[1]) if line.strip()]

# Names and labels must be YAML strings (so `1` and `"1"` can't both become
# `a (1)`) without spaces or parentheses, so each job name maps back to
# exactly one canary; scripts/notify.py parses job names with the same pattern.
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
GIT_URL = re.compile(r"git\+\S+")
VARIANT_FIELDS = {"label", "python", "install", "test", "runs-on", "node", "timeout-minutes"}
RULE = "a string of letters, digits, '.', '_' or '-' (quote it if YAML would read a number or boolean)"


def valid(value):
    return isinstance(value, str) and NAME.fullmatch(value)


def pinned_to_main(url):
    """True if a pip `git+` URL checks out main: after the `#...` fragment is
    removed, its ref -- the part after the last '@' -- is `main` not followed by
    a letter, digit, '_', '.', '/' or '-' (so trailing shell like `>/dev/null`
    is ignored, but `main-old` is not main). An unpinned URL (no
    '@ref') keeps the default branch, so it fails."""
    ref = url.split("#")[0].split("@")[-1]
    return bool(re.match(r"main(?![\w./-])", ref))


def unpinned_git_url(script):
    """The first `git+` URL in `script` not pinned to `@main`, or None."""
    return next((url for url in GIT_URL.findall(script or "") if not pinned_to_main(url)), None)


def jobs(canary):
    """One matrix entry per variant (or one for the canary), with its job name."""
    base = {k: v for k, v in canary.items() if k != "variants"} | {"canary": canary["name"]}
    if "variants" not in canary:
        return [base]
    return [base | v | {"name": f"{canary['name']} ({v['label']})"} for v in canary["variants"]]


for e in entries:
    if not valid(e.get("name")):
        sys.exit(f"canary name {e.get('name')!r} must be {RULE}")
    if e["name"] in {"plan", "notify"}:
        sys.exit("plan and notify are the workflow's own job names; a canary can't use them")
    if e.get("ref") != "main":
        sys.exit(f"{e['name']}: ref must be 'main', not {e.get('ref')!r}")
    bad = unpinned_git_url(e.get("install"))
    if bad:
        sys.exit(f"{e['name']}: install git+ URL {bad!r} must pin @main")
    variants = e.get("variants")
    if variants is None:
        continue
    if not isinstance(variants, list) or not variants:
        sys.exit(f"{e['name']}: variants must be a non-empty list")
    for v in variants:
        if not isinstance(v, dict) or not valid(v.get("label")):
            label = v.get("label") if isinstance(v, dict) else v
            sys.exit(f"{e['name']}: variant label {label!r} must be {RULE}")
        if v.keys() - VARIANT_FIELDS:
            sys.exit(f"{e['name']} ({v['label']}): a variant can only set {', '.join(sorted(VARIANT_FIELDS))}")
        bad = unpinned_git_url(v.get("install"))
        if bad:
            sys.exit(f"{e['name']} ({v['label']}): install git+ URL {bad!r} must pin @main")

names = [e["name"] for e in entries]
if len(names) != len(set(names)):
    sys.exit("duplicate canary names in canaries/")
job_names = [job["name"] for e in entries for job in jobs(e)]
duplicates = sorted({n for n in job_names if job_names.count(n) > 1})
if duplicates:
    sys.exit(f"duplicate job names {', '.join(duplicates)}: variant labels must be unique within a canary")

# Check each repository out under its own name, as its own CI does: some test
# suites expect the checkout directory to be named after the project.
for e in entries:
    e["dir"] = e["repo"].split("/")[-1]

def still_red(names):
    """Those of `names` whose latest result in the last RECHECK_RUNS scheduled
    runs is red (any part red). A canary whose result can't be read, or
    that has none, counts as not red, with a warning: fewer runs, not more."""
    env = os.environ
    try:
        github = GitHub(env["GITHUB_API_URL"], env["GITHUB_REPOSITORY"], env["GH_TOKEN"])
        run = github.get(f"actions/runs/{env['GITHUB_RUN_ID']}")
    except Exception as e:
        print(f"::warning::Couldn't read this run ({e!r}), so no red nightly canaries are re-checked.", file=sys.stderr)
        return set()
    red = set()
    for name in names:
        try:
            latest = previous_state(name, github.history(run, limit=RECHECK_RUNS))
        except Exception as e:
            print(f"::warning::Couldn't read {name}'s latest result ({e!r}), so it isn't re-checked.", file=sys.stderr)
            continue
        if latest is None:
            print(f"::warning::No result for {name} in the last {RECHECK_RUNS} scheduled runs, so it isn't re-checked.", file=sys.stderr)
        elif latest == "red":
            red.add(name)
    if red:
        print(f"Re-checking red nightly canaries: {', '.join(sorted(red))}", file=sys.stderr)
    return red


only = os.environ.get("ONLY", "").strip()
schedule = os.environ.get("SCHEDULE", "")
# On a pull request, the paths it changes (one per line). Canary files are
# named after their canary; a change to the workflow or this planner affects
# every canary, while notifier changes are covered by the unit tests.
changed = os.environ.get("CHANGED_FILES")
EVERY_CANARY = {".github/workflows/canary.yml", "scripts/plan.py"}
if only:
    due = [e for e in entries if e["name"] == only]
    if not due:
        sys.exit(f"no canary named {only!r}")
elif schedule:
    cadences = CADENCE_BY_CRON[schedule]
    recheck = still_red([e["name"] for e in entries if e["cadence"] == "nightly"]) if schedule == RECHECK_CRON else set()
    due = [e for e in entries if e["cadence"] in cadences or e["name"] in recheck]
elif changed is not None:
    paths = set(changed.split())
    due = entries if paths & EVERY_CANARY else [e for e in entries if f"canaries/{e['name']}.yml" in paths]
else:
    due = entries

include = [job for canary in due for job in jobs(canary)]
print(json.dumps({"include": include}))
print(len(include), file=sys.stderr)
