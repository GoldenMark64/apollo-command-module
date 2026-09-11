# Apollo Command Module Changelog

All notable public changes to Apollo Command Module will be documented here.

Apollo is currently under active development and has not yet reached a stable 1.0 release.

## Unreleased

### Added

- deterministic evidence operations
- regression and source-state inspection
- bounded debugger-assisted crash capture
- long-running session capture
- lifecycle and process provenance
- fail-closed application admission
- restricted application runtime environments
- application-specific environment allowlists
- offline evidence-bundle verification
- public security and architecture documentation
- GoldenEye Native post-mission input-lock case study

### Security

- machine-specific application policy moved outside tracked source
- configured forbidden filesystem roots
- no-follow executable admission
- executable hashing through a pinned file descriptor
- mutation detection during executable hashing
- isolated temporary HOME/XDG application state
- bounded diagnostic capture
- offline verification that does not launch the captured application

### Platform status

- Linux: validated
- Windows: planned / unvalidated
