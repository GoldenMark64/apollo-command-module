# Application Admission

Apollo does not treat an arbitrary executable path as permission to launch that
program.

Application capture requires a local application profile.

## 1. Create a local application policy

From the Apollo repository root:

```bash
cp config/application-profiles.example.json config/application-profiles.json
```

Find the machine's hostname:

```bash
hostname
```

Then edit `config/application-profiles.json` and add the application Apollo is
allowed to launch. For example:

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

Replace the hostname and paths with the real values for the machine and
application being investigated.

The `identity` value is the application name used when invoking Apollo.

## 2. Launch the authorized application

After the profile is configured, start a session with the same identity and
executable path:

```bash
python3 apollo.py session capture \
  --application example-application \
  --executable /opt/example/bin/application \
  --output ./apollo-session-001
```

Apollo rejects the request if the hostname, identity, executable path, or other
admission requirements do not match the local policy.

See [Configuration](configuration.md) for the complete profile format.

## Admission sequence

When an application session is requested, Apollo:

1. selects a profile using the actual hostname and requested identity
2. rejects unknown hostname/identity combinations
3. rejects path traversal and configured forbidden paths
4. requires the requested executable to exactly equal the configured executable
5. walks the path without following symlinks
6. opens the executable through a pinned file descriptor
7. requires a regular executable file
8. computes its SHA-256 digest
9. checks that the executable did not change during hashing

Only after successful admission can the session transport use that application
profile.

## Why this exists

A debugging tool that accepts arbitrary executable paths can accidentally become
a mechanism for running or inspecting unrelated software.

Apollo instead makes application access an explicit local policy decision.

That keeps the public command line convenient while requiring the machine owner
to decide in advance which applications Apollo is allowed to launch and inspect.
