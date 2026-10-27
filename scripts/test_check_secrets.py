"""Tests for check_secrets.py: python3 -m unittest discover -s scripts"""

import json
import os
import subprocess
import sys
import unittest

SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "check_secrets.py")


def run(secrets):
    # The script the way CI runs it: `python3 scripts/check_secrets.py` with
    # SECRETS_JSON in the environment.
    env = {"SECRETS_JSON": json.dumps(secrets)}
    return subprocess.run([sys.executable, SCRIPT], capture_output=True, text=True, env=env)


class CheckSecrets(unittest.TestCase):
    def test_only_github_token_passes(self):
        result = run({"github_token": "token-value"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("token-value", result.stdout)

    def test_one_extra_secret_fails(self):
        result = run({"github_token": "token-value", "DEPLOY_KEY": "deploy-value"})
        self.assertEqual(result.returncode, 1)
        self.assertIn("Secrets visible to canaries: DEPLOY_KEY.", result.stdout)
        self.assertNotIn("deploy-value", result.stdout)

    def test_several_extra_secrets_list_sorted_without_values(self):
        result = run({"github_token": "token-value", "B_KEY": "b-value", "A_KEY": "a-value"})
        self.assertEqual(result.returncode, 1)
        self.assertIn("Secrets visible to canaries: A_KEY, B_KEY.", result.stdout)
        self.assertNotIn("a-value", result.stdout)
        self.assertNotIn("b-value", result.stdout)


if __name__ == "__main__":
    unittest.main()
