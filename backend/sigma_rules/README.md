# Curated Sigma rules

Default rule pack shipped with the manager. The bootstrap script
(`scripts/load_sigma_rules.py`, M11 follow-up) reads every YAML file
under this directory and inserts it via the `/api/rules` API on first
manager start.

Each rule maps to one MITRE ATT&CK technique (the `tags:` field).
Operators add their own rules via the manager UI or API; the pack is
a safe minimum, not a complete ruleset.

The five files in this commit cover the broadest ATT&CK coverage
attainable with M0..M10's telemetry. Production deployments overlay
the [Sigma open-source rules][1] and IOC feeds on top.

[1]: https://github.com/SigmaHQ/sigma
