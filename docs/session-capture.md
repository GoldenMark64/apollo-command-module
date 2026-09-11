# Session Capture

Session capture is Apollo's main runtime-capture workflow.

Use it when you want Apollo to launch an authorized application, supervise one
run, and preserve bounded evidence about what happened during that run.

Typical uses include:

- reproducing a crash
- reproducing a runtime bug
- comparing a bad run with a good run
- preserving evidence for later human or AI-assisted analysis

## 1. Authorize the application

Before Apollo will launch a program, the application must be present in the
local application policy.

Create the local policy if you have not already done so:

```bash
cp config/application-profiles.example.json config/application-profiles.json
```

Then edit `config/application-profiles.json` for the application and machine you
want to investigate.

For example:

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

See [Configuration](configuration.md) for the complete profile format.

## 2. Start a session

From the Apollo repository root:

```bash
python3 apollo.py session capture \
  --application example-application \
  --executable /opt/example/bin/application \
  --output ./apollo-session-001
```

The output path must be new and must not already exist.

Apollo checks the configured application identity and executable path before
launching the process.

## 3. Reproduce the behavior

Once the application starts, use it normally.

If you are investigating a bug, reproduce the behavior you want to capture.

Apollo supervises the run and preserves bounded evidence such as:

- stdout
- stderr
- lifecycle checkpoints
- process and executable provenance
- debugger transcript
- terminal debugger state
- crash evidence when a fatal crash occurs

If the application exits normally, Apollo records that outcome as well.

## 4. How a session can end

Apollo distinguishes different terminal causes rather than treating every run
as equivalent.

A session may end because of:

- normal application exit
- fatal application crash
- timeout
- user interruption
- debugger or protocol failure
- incomplete capture

The original terminal cause is preserved during cleanup.

## 5. Runtime isolation

Captured applications run with a restricted environment and isolated temporary
HOME/XDG state directories.

Application-specific environment variables must be explicitly allowed by the
local application profile.

See [Application Admission](application-admission.md) for the admission and
isolation rules.

## 6. Verify the completed session

After the capture finishes:

```bash
python3 apollo.py session verify --session ./apollo-session-001
```

For structured JSON output:

```bash
python3 apollo.py --json session verify --session ./apollo-session-001
```

Verification is offline and does not launch the captured application again.

See [Offline Bundle Verification](bundle-verification.md) for details.

## Why use session capture?

The point of session capture is to preserve the facts of one execution in a
form that can be inspected later.

Instead of relying on memory, screenshots, or repeatedly rerunning the program
to rediscover the same facts, Apollo records a bounded evidence bundle that can
be reviewed by another developer, compared with another run, or supplied to an
AI system for analysis.
