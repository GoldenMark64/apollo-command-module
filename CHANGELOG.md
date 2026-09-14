# Apollo Command Module Changelog

All notable public changes to Apollo Command Module will be documented here.

Apollo is under active development and has not yet reached a stable 1.0 release.

## Unreleased

## 0.91.0 - 2026-09-14

### Added

- `apollo --version`, reporting `Apollo Command Module 0.91.0`
- `source function`, a bounded lexical C-function evidence operation
- exact function source, line bounds, function/file hashes, simple identifier
  assignments, return evidence, and recognized enclosing braced controls
- optional assignment filtering with `--variable`
- ambiguity rejection and explicit lexical-analysis limitations
- focused source-function and version regression tests
- GoldenEye CAST crash multi-AI case study

### Validation

- source-function focused tests: 5/5 passed
- version CLI test: passed
- `source function` was used during the GoldenEye CAST crash investigation
  before release

## 0.90.0 - 2026-09-11

Initial public Apollo Command Module release.

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
