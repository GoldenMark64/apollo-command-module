# Apollo Command Module

Apollo Command Module (Apollo) is a deterministic software-forensics and validation layer for human and
AI-assisted engineering.

It collects reproducible facts about source, builds, tests, traces, patches,
sessions, and crashes, then emits structured evidence that can be reviewed by a
human or consumed by any reasoning system.

Apollo is designed to answer questions such as:

- What source and executable were actually tested?
- Did a regression reproduce consistently?
- What changed between a failing and passing run?
- Did a crash capture contain the evidence it claims to contain?
- Can another machine verify an evidence bundle without rerunning the program?
- Did an automated investigation modify something it was supposed to inspect
  read-only?

Project website: https://goldenmark64.github.io/apollo-command-module/

## Why Apollo exists

Apollo grew out of my work using AI-assisted development on real debugging and
reverse-engineering problems. I noticed that a surprising amount of valuable
model context and token budget was being spent repeatedly establishing facts
that a small deterministic Python tool could determine more cheaply and
reliably: hashes, source state, build results, regression outcomes, runtime
traces, artifact provenance, and whether two runs actually differed.

I built Apollo to separate that mechanical evidence-gathering from the harder
reasoning work. Python and conventional debugging tools establish and preserve
the facts; humans and AI systems can then spend their limited attention and
tokens interpreting those facts, forming hypotheses, and deciding what to do
next. The goal is not to replace AI-assisted engineering, but to make it more
efficient, reproducible, and trustworthy.

## Current status

The current implementation is Linux-first and has been validated during development.

Windows support is planned but is currently unvalidated.

## Design goals

Apollo favors:

- deterministic evidence over narrative claims
- bounded capture over unrestricted dumping
- explicit provenance over inference
- fail-closed application admission
- read-only verification
- machine-readable output
- evidence usable by humans, automated tools, and AI systems

Apollo is not an AI model and does not require one.

## Evidence philosophy

Apollo favors deterministic, bounded, machine-readable evidence.

It records provenance such as executable hashes and session metadata, keeps missing information explicitly missing rather than guessing, and separates internal verification from decisions about whether an artifact is safe to share.

## Case studies

- [GoldenEye CAST crash — multi-AI debugging architecture](docs/case-study-cast-crash-multi-ai.md) — Apollo supplied deterministic evidence while Qwen3-Coder 30B, OpenCode, Codex, and two Linux machines divided the investigation, validation, and production-hardening work. The complete bug hunt and fix used less than 20% of the weekly Codex allowance.
- [APOLLO-009 — GoldenEye Native post-mission input lock](docs/case-study-apollo-009.md) — deterministic runtime evidence narrowed an apparent input failure to a stuck controller-poll synchronization state.

## Documentation

Start with:

- [Quick start](docs/quickstart.md)
- [Architecture](docs/architecture.md)
- [Configuration](docs/configuration.md)
- [Application admission](docs/application-admission.md)
- [Session capture](docs/session-capture.md)
- [Crash capture](docs/crash-capture.md)
- [Offline verification](docs/bundle-verification.md)
- [CAST crash multi-AI case study](docs/case-study-cast-crash-multi-ai.md)
- [APOLLO-009 GoldenEye Native case study](docs/case-study-apollo-009.md)

## Platform status

**Linux:** validated.

**Windows:** planned / unvalidated.

## Development status

Apollo is under active development. Evidence produced by Apollo should still be
reviewed according to the needs and trust model of the project using it.

## License

Apollo is licensed under the GNU General Public License v3.0 only
(`GPL-3.0-only`). See [LICENSE](LICENSE).
