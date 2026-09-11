# Contributing to Apollo Command Module

Contributions, bug reports, design ideas, and use cases are welcome.

## Where to discuss ideas

GitHub Discussions is the preferred place for feature ideas, design suggestions, questions, new use cases, and broader architectural discussion.

GitHub Issues should be used for concrete bugs, regressions, and actionable work.

## Development principles

Apollo is built around a few core ideas:

- deterministic evidence before interpretation
- bounded capture rather than unrestricted dumping
- explicit provenance rather than inference
- fail-closed application admission
- read-only offline verification
- generic tooling rather than application-specific assumptions
- machine-readable evidence that does not depend on a particular AI system

Changes should preserve these properties unless there is a clear reason to change the design.

## Application-specific support

Application-specific paths, hostnames, secrets, private data, and local environment policy should not be committed to the repository. Use local application policy instead.

See `docs/configuration.md`, `docs/application-admission.md`, and `SECURITY.md`.

## Evidence and privacy

Do not submit private binaries, credentials or access tokens, personal filesystem paths, private hostnames or network information, unrestricted memory dumps, or confidential runtime evidence.

When demonstrating a real investigation, reduce the evidence to the smallest sanitized excerpt necessary to explain the result.

## Platform support

Linux is currently the validated platform. Windows-related contributions are welcome, but Windows behavior should not be described as validated until it has equivalent automated and host-level verification.

## Contribution licensing

By submitting a contribution to Apollo, you agree that your contribution may be
distributed under the GNU General Public License v3.0 only (`GPL-3.0-only`).
