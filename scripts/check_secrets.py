"""Fail when any secret other than `github_token` is visible to this repository.

`GITHUB_TOKEN` cannot list secrets, so this check reads the `secrets`
context. `${{ toJSON(secrets) }}` holds every Actions secret available to the
run. It holds organization and repository secrets, plus `github_token`, which
is always present. The check cannot tell an organization secret from a
repository secret. The canary repository has no repository secret, so any
extra name is a problem either way.

On Dependabot pull request runs, the context holds Dependabot secrets in place
of Actions secrets. So those runs fail on any Dependabot secret visible to this
repository. Codespaces and Copilot agent organization secrets are not covered:
they do not reach Actions runs. Listing them needs a token with
organization-level read access to those secrets, which this repository does not
hold.

An absent `SECRETS_JSON` is a coding error in the workflow, so this check
raises. Standard library only.
"""

import json
import os
import sys

ALLOWED = "github_token"


def extra_secrets(secrets_json):
    """The secret names other than `github_token`, sorted. Names only, no values."""
    return sorted(name for name in json.loads(secrets_json) if name != ALLOWED)


def main():
    extra = extra_secrets(os.environ["SECRETS_JSON"])
    if extra:
        print(f"::error::Secrets visible to canaries: {', '.join(extra)}. Remove canaries from their repository access.")
        return 1
    print(f"Only `{ALLOWED}` is visible.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
