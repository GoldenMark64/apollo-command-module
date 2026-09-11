"""Local host/application policy for Apollo.

Machine-specific policy belongs in config/application-profiles.json, which is
intentionally ignored by Git. The public repository ships only an example.
"""
from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
import json
import os
from pathlib import Path


ROOT = Path(__file__).absolute().parent
DEFAULT_POLICY = ROOT / "config" / "application-profiles.json"


@dataclass(frozen=True)
class ApplicationProfile:
    executable: Path
    cwd: Path
    env_allowlist: tuple[str, ...] = ()


def policy_path() -> Path:
    override = os.environ.get("APOLLO_POLICY_FILE")
    return Path(override) if override else DEFAULT_POLICY


def _absolute_path(value, field: str) -> Path:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be a non-empty string")

    path = Path(value)

    if not path.is_absolute():
        raise ValueError(f"{field} must be absolute")

    if ".." in path.parts:
        raise ValueError(f"{field} must not contain '..'")

    return Path(os.path.normpath(os.fspath(path)))


@lru_cache(maxsize=None)
def load_policy(path: Path | str | None = None) -> dict:
    source = Path(path) if path is not None else policy_path()

    if not source.exists():
        return {"profiles": [], "forbidden_paths": []}

    raw = json.loads(source.read_text())

    if not isinstance(raw, dict):
        raise ValueError("Apollo policy must be a JSON object")

    profiles = raw.get("profiles", [])
    forbidden = raw.get("forbidden_paths", [])

    if not isinstance(profiles, list):
        raise ValueError("policy profiles must be a list")

    if not isinstance(forbidden, list):
        raise ValueError("policy forbidden_paths must be a list")

    return raw


def load_application_profiles(path: Path | str | None = None):
    raw = load_policy(path)
    result = {}

    for item in raw.get("profiles", []):
        if not isinstance(item, dict):
            raise ValueError("each application profile must be an object")

        hostname = item.get("hostname")
        identity = item.get("identity")

        if not isinstance(hostname, str) or not hostname:
            raise ValueError("profile hostname must be a non-empty string")

        if not isinstance(identity, str) or not identity:
            raise ValueError("profile identity must be a non-empty string")

        executable = _absolute_path(item.get("executable"), "profile executable")
        cwd = _absolute_path(item.get("cwd"), "profile cwd")

        env_allowlist = item.get("env_allowlist", [])

        if (
            not isinstance(env_allowlist, list)
            or any(not isinstance(name, str) or not name for name in env_allowlist)
        ):
            raise ValueError("profile env_allowlist must contain non-empty strings")

        key = (hostname, identity)

        if key in result:
            raise ValueError(
                f"duplicate application profile for hostname={hostname!r}, "
                f"identity={identity!r}"
            )

        result[key] = ApplicationProfile(
            executable=executable,
            cwd=cwd,
            env_allowlist=tuple(env_allowlist),
        )

    return result


def _explicit_forbidden_roots(path: Path | str | None = None):
    raw = load_policy(path)
    return tuple(
        _absolute_path(item, "forbidden path")
        for item in raw.get("forbidden_paths", [])
    )


def _lexical_absolute(value) -> Path:
    return Path(os.path.normpath(os.path.abspath(os.fspath(value))))


def _within(candidate: Path, root: Path) -> bool:
    return candidate == root or root in candidate.parents


def is_forbidden_path(value) -> bool:
    """True for explicitly private/local trees from the user's policy."""
    candidate = _lexical_absolute(value)
    return any(
        _within(candidate, root)
        for root in _explicit_forbidden_roots()
    )


def is_capture_forbidden_path(value) -> bool:
    """Capture helpers must avoid forbidden trees and configured applications."""
    candidate = _lexical_absolute(value)

    roots = list(_explicit_forbidden_roots())

    for profile in load_application_profiles().values():
        roots.append(profile.cwd)
        roots.append(profile.executable)

    return any(_within(candidate, root) for root in roots)
