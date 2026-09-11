# Architecture

Apollo separates evidence collection from reasoning.

The application, compiler, debugger, or source repository remains the authority
for the underlying event. Apollo records and normalizes the resulting facts.

## How the pieces are invoked

From the Apollo repository root, see the available operations with:

```bash
python3 apollo.py --help
```

Capture an authorized application session with:

```bash
python3 apollo.py session capture \
  --application IDENTITY \
  --executable /path/to/application \
  --output /path/to/session
```

Verify a captured session offline with:

```bash
python3 apollo.py session verify --session /path/to/session
```

## Components

### `apollo.py`

The public command-line entry point.

It provides deterministic operations for source inspection, trace comparison,
evidence handling, regression execution, bounded probes, patch inspection,
journaling, checkpoints, session capture, and verification.

### `apollo_session.py`

Captures an explicitly authorized application session.

It records bounded runtime output, debugger state, lifecycle information, crash
evidence when applicable, and application provenance.

### `apollo_policy.py`

Loads the local application-admission policy.

The policy determines which application identity, executable path, working
directory, and optional environment variables Apollo is permitted to use.

Machine-specific policy is kept outside the public source tree.

### `apollo_verify.py`

Checks an existing Apollo session bundle without rerunning the captured
application.

Verification examines artifact hashes and sizes, schema structure, lifecycle
relationships, capture metadata, terminal status, crash evidence, runtime
accounting, timestamps, and other intrinsic consistency rules.

### `apollo_crash.py`

Provides shared debugger and crash-analysis support used by the capture layer.

It contains GDB/MI parsing, crash normalization, executable hashing, bounded
debugger handling, and related safety helpers. It is not a separate public crash
command.

## AI independence

Apollo does not depend on a particular AI system.

Its structured evidence can be consumed by:

- a human engineer
- a local model
- a hosted model
- an automated validation process
- a custom analysis pipeline

This separation is intentional: reasoning systems may change, while the
underlying evidence should remain inspectable and reproducible.
