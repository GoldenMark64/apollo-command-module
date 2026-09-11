# Quick Start

Apollo captures a bounded, reproducible evidence bundle from one authorized
execution of a program.

Use it when you want to preserve facts about a run — for example, while
reproducing a crash or other runtime problem — so that you, another developer,
or an AI system can inspect the same evidence later instead of repeatedly
re-establishing what happened.

## Requirements

Apollo currently targets Linux with Python 3.

GDB is used for debugger-assisted session and crash evidence.

## 1. Configure the application

From the Apollo repository root, create a local application policy:

```bash
cp config/application-profiles.example.json config/application-profiles.json
```

Find the machine's hostname:

```bash
hostname
```

Then edit `config/application-profiles.json` and add the application you want
Apollo to run. For example:

```json
{
  "profiles": [
    {
      "hostname": "workstation-a",
      "identity": "example-application",
      "executable": "/opt/example/bin/application",
      "cwd": "/opt/example"
    }
  ]
}
```

Replace the example hostname and paths with the real values for your machine
and application.

`identity` is the name you will use when invoking Apollo.

The local policy file is ignored by Git.

## 2. Capture a run

Start the authorized application through Apollo:

```bash
python3 apollo.py session capture \
  --application example-application \
  --executable /opt/example/bin/application \
  --output ./apollo-session-001
```

Use a new output path that does not already exist.

Apollo launches the configured executable and records bounded session evidence.

Now use the application normally. If you are investigating a bug, reproduce it.
If the application crashes, Apollo attempts to collect bounded debugger and
crash evidence before finalizing the session. A normal exit is also recorded.

## 3. Verify the captured bundle

After the run finishes:

```bash
python3 apollo.py session verify --session ./apollo-session-001
```

For structured JSON output:

```bash
python3 apollo.py --json session verify --session ./apollo-session-001
```

Verification is offline: it checks the captured bundle without launching the
application again.

## What Apollo gives you

A captured session preserves reproducible facts about the run, including
application provenance, lifecycle information, bounded runtime output, and
debugger/crash evidence when applicable.

The resulting bundle can be inspected later, compared with another run, or
given to a human or AI system as evidence for debugging and engineering work.

## Next steps

- [Configuration](configuration.md) explains application profiles in more detail.
- [Application Admission](application-admission.md) explains how Apollo decides
  which executable it is allowed to launch.
- [Session Capture](session-capture.md) explains the capture lifecycle.
- [Crash Evidence](crash-capture.md) explains what happens when a captured
  application crashes.
- [Offline Bundle Verification](bundle-verification.md) explains verification.
