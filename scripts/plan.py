"""Select the canaries due for this run and print them as a JSON matrix.

Reads one JSON object per line: each file in canaries/ converted with
`yq -o=json -I=0` (preinstalled on GitHub's Ubuntu runners), so this needs
only the standard library.

A canary with `variants` becomes one matrix entry per variant, each named
`<canary> (<label>)`, so its parts run in parallel; scripts/notify.py groups
them back into one canary by that name.
"""

import json
import os
import re
import sys

CADENCE_BY_CRON = {"0 */2 * * *": {"2h"}, "30 5 * * *": {"2h", "nightly"}}

entries = [json.loads(line) for line in open(sys.argv[1]) if line.strip()]
names = [e["name"] for e in entries]
if len(names) != len(set(names)):
    sys.exit("duplicate canary names in canaries/")
if {"plan", "notify"} & set(names):
    sys.exit("plan and notify are the workflow's own job names; a canary can't use them")

# Names and labels can't hold spaces or parentheses, so a job name maps back to
# exactly one canary.
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
VARIANT_FIELDS = {"label", "python", "install", "test", "runs-on", "node", "timeout-minutes"}
for e in entries:
    if not NAME.fullmatch(str(e["name"])):
        sys.exit(f"canary name {e['name']!r} must be letters, digits, '.', '_' or '-'")
    variants = e.get("variants")
    if variants is None:
        continue
    if not isinstance(variants, list) or not variants:
        sys.exit(f"{e['name']}: variants must be a non-empty list")
    labels = []
    for v in variants:
        if not isinstance(v, dict) or not NAME.fullmatch(str(v.get("label", ""))):
            sys.exit(f"{e['name']}: each variant needs a label of letters, digits, '.', '_' or '-'")
        if v.keys() - VARIANT_FIELDS:
            sys.exit(f"{e['name']} ({v['label']}): a variant can only set {', '.join(sorted(VARIANT_FIELDS))}")
        labels.append(v["label"])
    if len(labels) != len(set(labels)):
        sys.exit(f"{e['name']}: duplicate variant labels")

# Check each repository out under its own name, as its own CI does: some test
# suites expect the checkout directory to be named after the project.
for e in entries:
    e["dir"] = e["repo"].split("/")[-1]

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
    due = [e for e in entries if e["cadence"] in cadences]
elif changed is not None:
    paths = set(changed.split())
    due = entries if paths & EVERY_CANARY else [e for e in entries if f"canaries/{e['name']}.yml" in paths]
else:
    due = entries


def jobs(canary):
    """One matrix entry per variant (or one for the canary), with its job name."""
    base = {k: v for k, v in canary.items() if k != "variants"} | {"canary": canary["name"]}
    if "variants" not in canary:
        return [base]
    return [base | v | {"name": f"{canary['name']} ({v['label']})"} for v in canary["variants"]]


include = [job for canary in due for job in jobs(canary)]
print(json.dumps({"include": include}))
print(len(include), file=sys.stderr)
