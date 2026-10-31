# Security policy

Lintel controls physical access, so security reports get priority.

## Reporting a vulnerability

Report privately through GitHub:
[Report a vulnerability](https://github.com/xDarkzx/Lintel/security/advisories/new).
Please do not open a public issue, discussion or pull request for a security
problem.

Include what you can of:

- the component (keypad firmware, door controller, server, console, protocol)
- the version or commit
- steps to reproduce, or a proof of concept
- the impact you expect, e.g. unauthorised unlock, credential disclosure,
  audit tampering, denial of service at the door

You will get an acknowledgement within 5 working days. Fixes are developed in a
private advisory, and you will be credited in the advisory unless you ask not
to be.

## Supported versions

Only the latest release and `main` receive security fixes.

## Scope

In scope: anything that lets someone open a door they should not, read or
forge keypad traffic, recover PINs or card identifiers, bypass console
authentication or roles, or alter the audit trail without detection.

Known limits that are documented rather than vulnerabilities, such as the
development firmware not enabling secure boot or flash encryption, are listed
in [docs/SECURITY.md](../docs/SECURITY.md) and
[docs/production-hardening.md](../docs/production-hardening.md).
