"""Select the canaries due for this run and print them as a JSON matrix.

Reads canaries.yml converted to JSON (`yq -o=json`, preinstalled on GitHub's
Ubuntu runners), so this needs only the standard library.
"""

import json
import os
import sys

CADENCE_BY_CRON = {"0 */2 * * *": {"2h"}, "30 5 * * *": {"2h", "nightly"}}

entries = json.load(open(sys.argv[1]))
names = [e["name"] for e in entries]
if len(names) != len(set(names)):
    sys.exit("duplicate canary names in canaries.yml")

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
