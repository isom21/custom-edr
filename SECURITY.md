# Security policy

## Reporting a vulnerability

If you believe you've found a security vulnerability in the EDR
project, please report it privately rather than opening a public
issue.

**Email**: `security@example.com` (replace with the operator's real
contact when the project transitions out of PoC).

**Encryption**: a PGP key for security reports will land here under
M19. Until then, please send unencrypted reports — but do not
include exploit details, only the existence of the issue and how to
reach you for follow-up.

**What to include**:

* Affected component (`agent-linux` / `agent-windows` /
  `kernel-windows` / `backend` / `frontend`).
* Affected version (commit SHA or release tag).
* Reproduction steps.
* Impact (what an attacker can do).
* Whether you've already seen this exploited in the wild.

We aim to acknowledge reports within 3 business days and ship a fix
within 30 days for critical issues, 90 days for non-critical.

## Disclosure policy

We follow a standard 90-day disclosure timeline:

1. Day 0: report received, internal triage starts.
2. Day 0–7: severity assessment, CVE reservation if appropriate.
3. Day 7–60: fix developed, tested on lab + customer pilots.
4. Day 60–80: patched release shipped to customers.
5. Day 90: public disclosure (CVE published, advisory in
   `docs/advisories/`).

Reporters who follow this timeline get credit in the advisory
unless they prefer to remain anonymous.

## Out of scope

The following are documented behaviour, not vulnerabilities:

* Same-box root can stop the agent via `systemctl stop`. By design;
  see `docs/threat-model.md`.
* `bcdedit /set testsigning on` weakens Windows driver signing —
  required only for the test-cert path; production signing covers
  this in M19 (paid).
* PoC ships with a default `EDR_RL_*` rate limit set; an operator who
  doesn't tune for their fleet size can be DoS-ed by aggressive
  agents. Operator responsibility, not a CVE-class bug.

## Hall of fame

(Empty until first real report.)
