# Security Policy

## Supported Versions

Only the latest version on the `main` branch receives security fixes.

| Version         | Supported |
| --------------- | --------- |
| `main` (latest) | Yes       |
| Older commits   | No        |

## Reporting a Vulnerability

**Please do not open a public issue for security vulnerabilities.**

Report them privately using GitHub's
[private vulnerability reporting](https://github.com/Sahanasrajan/ks8555-sscs-assignment1/security/advisories/new)
(Security tab → "Report a vulnerability").

Please include:

- a description of the vulnerability and its impact
- steps to reproduce, or a proof of concept
- the affected commit or version

## What to Expect

- An acknowledgement within **3 business days**.
- An assessment and, if confirmed, a planned fix within **14 days**.
- Credit in the release notes once the fix is published, unless you prefer
  to stay anonymous.

## How Security Updates Are Handled

Confirmed vulnerabilities are fixed on a private branch, reviewed, and merged
into `main`. A GitHub Security Advisory is then published describing the
issue, the affected versions, and the fix. Dependency vulnerabilities are
addressed by updating `poetry.lock`.
