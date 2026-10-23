"""Select the canaries due for this run and print them as a JSON matrix.

Reads one JSON object per line: each file in canaries/ converted with
`yq -o=json -I=0` (preinstalled on GitHub's Ubuntu runners), so this needs
only the standard library.
"""

import json
import os
import sys

CADENCE_BY_CRON = {"0 */2 * * *": {"2h"}, "30 5 * * *": {"2h", "nightly"}}

entries = [json.loads(line) for line in open(sys.argv[1]) if line.strip()]
names = [e["name"] for e in entries]
if len(names) != len(set(names)):
    sys.exit("duplicate canary names in canaries/")

# Check each repository out under its own name, as its own CI does: some test
# suites expect the checkout directory to be named after the project.
for e in entries:
    e["dir"] = e["repo"].split("/")[-1]

only = os.environ.get("ONLY", "").strip()
schedule = os.environ.get("SCHEDULE", "")
if only:
    due = [e for e in entries if e["name"] == only]
    if not due:
        sys.exit(f"no canary named {only!r}")
elif schedule:
    cadences = CADENCE_BY_CRON[schedule]
    due = [e for e in entries if e["cadence"] in cadences]
else:
    due = entries

print(json.dumps({"include": due}))
