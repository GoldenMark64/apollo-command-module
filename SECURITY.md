# Security

Apollo is designed to collect debugging and validation evidence without turning
a diagnostic session into an unrestricted data capture.

## Security principles

Apollo uses a fail-closed application admission model. Applications may be
launched only when the current hostname, application identity, executable path,
and working directory match a locally configured profile.

Machine-specific policy belongs in:

`config/application-profiles.json`

That file is intentionally excluded from version control.

Apollo also supports configured forbidden paths. These paths are rejected before
ordinary evidence operations inspect their contents.

Application executables are opened without following symlinks, checked to be
regular executable files, hashed from a pinned file descriptor, and checked for
mutation during hashing.

Application processes receive a deliberately restricted environment. Common
display and audio variables may be inherited, while application-specific
variables must be explicitly added to the profile allowlist.

Core files and broad process-memory dumps are not part of the normal evidence
model.

## Evidence trust

Apollo verification establishes intrinsic consistency of a bundle. It does not
by itself establish external authenticity, authorship, or a cryptographic trust
chain.

A VERIFIED result therefore means that the bundle is internally consistent with
Apollo's verification rules. It does not mean that the evidence is automatically
safe to publish or that every claim made about it is independently proven.

## Reporting security issues

Until a dedicated security-reporting process is published, avoid placing
sensitive machine data, credentials, private binaries, memory dumps, or
confidential evidence in public issues.
