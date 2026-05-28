# Security Policy

## Supported Versions

This project is maintained on a rolling basis on the `main` branch.
Security fixes are released through automated GitHub releases.

| Version scope | Supported |
| --- | --- |
| `main` (latest release) | Yes |
| Older generated releases | Best effort |

## Legitimate Use Scope

This repository is intended for legitimate incident response and data recovery use only.
Do not use this project for unauthorized access, malware operations, or offensive activity.

## Reporting a Vulnerability

If you found a security issue:

1. Do not open a public issue with exploit details.
2. Open a private GitHub security advisory if available for the repository.
3. If private advisory is not available, contact the maintainer directly and include:
   - Affected component/file
   - Reproduction steps
   - Impact assessment
   - Suggested fix (if any)

Please allow reasonable time for triage and coordinated disclosure before public discussion.

## Security Response Expectations

- Initial triage target: within 7 business days.
- Fix ETA depends on impact and complexity.
- High-severity issues are prioritized for the next automated release.

## Supply Chain and Release Integrity

Releases provide `SHA256SUMS.txt` so users can verify downloaded artifacts.
Use checksum verification before executing release assets.
