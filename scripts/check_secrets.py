"""Fail when any secret other than `github_token` is visible to this repository.

`GITHUB_TOKEN` has no `secrets` permission, so this check reads the `secrets`
context. `${{ toJSON(secrets) }}` holds every Actions secret available to the
run. It holds organization and repository secrets, plus `github_token`, which
is always present. The check cannot tell an organization secret from a
repository secret. The canary repository has no repository secret, so any
extra name is a problem either way.

This check does not cover Dependabot, Codespaces or Copilot agent organization
secrets. They do not reach canary Actions runs. Only an organization-admin
token can list them.

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
