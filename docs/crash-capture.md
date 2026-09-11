# Crash Evidence

Apollo collects crash evidence automatically during an application session.

There is no separate crash-capture command. Start a normal Apollo session and,
if the application terminates because of a fatal signal, Apollo gathers the
available debugger evidence before finalizing the session bundle.

## 1. Authorize the application

Configure the application in:

`config/application-profiles.json`

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

See [Configuration](configuration.md) for details.

## 2. Start the capture

From the Apollo repository root:

```bash
python3 apollo.py session capture \
  --application example-application \
  --executable /opt/example/bin/application \
  --output /path/to/new-session
```

Apollo launches the approved application under its debugger-assisted capture
layer.

Use the application normally and reproduce the crash.

## 3. What happens when the application crashes

If Apollo observes a fatal application crash, it attempts to collect bounded
evidence such as:

- terminal reason
- signal information
- fault address
- crashing thread
- bounded backtrace
- registers
- loaded modules
- disassembly
- debugger transcript
- runtime stdout and stderr

Apollo distinguishes an application crash from a timeout, debugger failure,
incomplete capture, or normal exit.

Evidence that could not be collected remains explicitly missing rather than
being inferred or invented.

## 4. Verify the resulting session

After capture, verify the bundle without rerunning the application:

```bash
python3 apollo.py session verify --session /path/to/new-session
```

See [Offline Bundle Verification](bundle-verification.md) for verification
details.
