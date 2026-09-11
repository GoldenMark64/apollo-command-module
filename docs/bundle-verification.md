# Offline Bundle Verification

Apollo can verify a captured session without rerunning the program.

This is useful when evidence is transferred to another machine or reviewed long
after the original execution.

## Usage

From the Apollo repository root, verify a captured session bundle with:

```bash
python3 apollo.py session verify --session /path/to/session
```

For structured JSON output:

```bash
python3 apollo.py --json session verify --session /path/to/session
```

To also write the verification results to a new directory:

```bash
python3 apollo.py --json session verify --session /path/to/session --output /path/to/verification-report
```

The output directory must be separate from the captured session and must not already exist. Apollo verifies the bundle offline and does not launch the captured application.

## Verification states

Apollo distinguishes:

- VERIFIED
- CORRUPTED
- UNVERIFIABLE
- UNSUPPORTED_SCHEMA

Completeness is reported separately.

## Checks

Verification includes:

- manifest structure
- expected and unexpected artifacts
- SHA-256 hashes
- artifact sizes
- session schema
- lifecycle relationships
- capture-mode consistency
- terminal status consistency
- crash evidence requirements
- thread accounting
- bounded-log accounting
- timestamp structure
- report and evidence identity relationships

## Trust boundary

VERIFIED means the bundle is internally consistent with Apollo's verification
rules.

It does not prove that the bundle was created by a trusted person or machine,
nor does it create a cryptographic chain of custody.

Apollo currently performs intrinsic verification, not external attestation.
