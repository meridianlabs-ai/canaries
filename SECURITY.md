# Security Policy

## Reporting a vulnerability

[Report a vulnerability](https://github.com/meridianlabs-ai/canaries/security/advisories/new) through GitHub's private vulnerability reporting on this repository. Only you, the maintainers at Meridian Research Labs, and anyone they add to the report can see it. Please do not open a public issue, discussion, or pull request for a suspected vulnerability.

Include as much of the following as you can:

- The workflow, script, or canary file involved
- A description of the problem and what an attacker could do with it
- Steps to reproduce it, or a link to a run that shows it

## What to expect

- We will acknowledge your report within 3 business days.
- We will tell you within 10 business days whether we consider it a vulnerability and what we plan to do.
- We aim to merge a fix within 30 days of the report. If a fix will take longer, we will tell you why.

We reply in the advisory and keep you updated there as we work on a fix.

We do not run a bug bounty program and cannot pay for reports.

## Supported versions

Only the `main` branch of this repository is supported.

## Scope

This repository runs scheduled tests of Meridian Labs and Inspect projects against the newest releases of their dependencies. Its README describes how the canary jobs are isolated: no secrets, a read-only token, no caches, and nothing downstream. The sections below describe what we treat as a vulnerability and what we do not.

### In scope

- A way for code in a canary run to reach a secret, a write token, the Actions cache, or a workflow or repository outside its own job
- A way to make the alert job run untrusted code or post content it shouldn't, for example from a canary's log text
- A way for a pull request or a fork to run a workflow here with secrets or write access
- A way to run a canary on a runner that isn't GitHub-hosted

### Out of scope

- A dependency release that breaks a canary. Finding those is the purpose of this repository. Report a malicious release to the package's maintainers and its registry.
- Vulnerabilities in the projects the canaries test should be reported under that project's security policy.
- Reports produced by a security scanner, or written mainly by an automated tool or a language model, with no working proof of concept. We will close these without a detailed response.

## Disclosure

When the fix is merged, we publish the advisory from your report. We will tell you before we publish it. The advisory credits you unless you ask us not to.

Please keep the details private until the advisory is published.
