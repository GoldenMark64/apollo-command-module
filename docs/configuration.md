# Configuration

Apollo keeps machine-specific application policy outside the tracked source.

The default local configuration path is:

```text
config/application-profiles.json
```

The repository provides:

```text
config/application-profiles.example.json
```

## Example

```json
{
  "profiles": [
    {
      "hostname": "workstation-a",
      "identity": "example-application",
      "executable": "/opt/example-a/bin/application",
      "cwd": "/opt/example-a",
      "env_allowlist": [
        "EXAMPLE_TRACE"
      ]
    }
  ],
  "forbidden_paths": [
    "/srv/apollo-private"
  ]
}
```

## Profiles

Each profile contains:

- `hostname` — the exact host name permitted to use the profile
- `identity` — a stable logical application name
- `executable` — exact approved executable path
- `cwd` — approved working directory
- `env_allowlist` — optional application-specific environment variables

The hostname and identity form the profile key.

## Forbidden paths

`forbidden_paths` identifies local trees that Apollo evidence operations must
not inspect.

These paths should describe local policy, not be committed to the public
repository.

## Alternate policy file

`APOLLO_POLICY_FILE` may point Apollo at another policy file.

This is useful for automated testing and isolated environments.
