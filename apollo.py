#!/usr/bin/env python3
"""Apollo: deterministic, portable evidence operations."""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import platform
from pathlib import Path

from apollo_policy import is_forbidden_path
from apollo_source import analyze_c_function

SCHEMA = "apollo.evidence.v1"


def envelope(tool, inputs, outputs, warnings=None, status="ok"):
    return {"schema_version": SCHEMA, "tool": "apollo", "operation": tool,
            "inputs": inputs, "outputs": outputs, "warnings": warnings or [], "status": status}


def emit(value, as_json):
    if as_json:
        print(json.dumps(value, indent=2, sort_keys=True))
    else:
        print(value.get("status", "ok").upper() + ": " + value["operation"])
        for key, item in value.get("outputs", {}).items():
            if isinstance(item, (dict, list)):
                print(json.dumps({key: item}, sort_keys=True))
            else:
                print(f"{key}: {item}")
        for warning in value.get("warnings", []):
            print("warning: " + warning, file=sys.stderr)


def forbidden(path: Path) -> bool:
    """Reject locally configured private trees before filesystem operations."""
    return is_forbidden_path(path)


def safe_path(value: str) -> Path:
    path = Path(value)
    if forbidden(path) or forbidden(path.absolute()) or forbidden(path.resolve(strict=False)):
        raise ValueError("refusing to access a configured forbidden path")
    return path


def _host_timestamp():
    return datetime.datetime.now(datetime.timezone.utc).astimezone().isoformat(timespec="microseconds")


def _process_metadata():
    # os.getpid() is only meaningful inside the namespace in which Apollo
    # executes.  The external runner is the authority for any host PID.
    return {"kind": "apollo_helper", "pid": os.getpid(), "pid_scope": "process_namespace"}


def _mission_metadata(env=None):
    values = os.environ if env is None else env
    result = {}
    for key in ("APOLLO_RUN_STAMP", "APOLLO_RUNNER_PID", "APOLLO_MISSION_ID"):
        if key in values:
            result[{"APOLLO_RUN_STAMP": "run_stamp", "APOLLO_RUNNER_PID": "runner_pid",
                   "APOLLO_MISSION_ID": "mission"}[key]] = values[key]
    return result


def _acquire_lock(lock_path, timeout=10):
    deadline = time.monotonic() + timeout
    while True:
        try:
            return lock_path.open("x", encoding="ascii")
        except FileExistsError:
            if time.monotonic() >= deadline:
                raise ValueError("journal lock timeout")
            time.sleep(0.01)


def _append_jsonl(path, record):
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = Path(os.fspath(path) + ".lock")
    lock = _acquire_lock(lock_path)
    try:
        with path.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        lock.close()
        try:
            lock_path.unlink()
        except FileNotFoundError:
            pass


def journal_append(args, env=None):
    path = safe_path(args.journal)
    artifacts = sorted(args.artifact or [])
    record = {"timestamp": _host_timestamp(), "hostname": platform.node(), "process": _process_metadata(),
              "phase": args.phase, "action": args.action, "status": args.status,
              "artifacts": artifacts, "next_action": args.next_action}
    record.update(_mission_metadata(env))
    _append_jsonl(path, record)
    return envelope("journal.append", {"journal": os.path.normpath(os.fspath(path))}, record)


def checkpoint_write(args):
    path = safe_path(args.file)
    payload = json.loads(args.record)
    if not isinstance(payload, dict):
        raise ValueError("checkpoint record must be a JSON object")
    payload = dict(payload)
    if "timestamp" in payload or "checkpoint_timestamp" in payload:
        raise ValueError("timestamp fields are host-generated and cannot be supplied")
    payload["checkpoint_timestamp"] = _host_timestamp()
    payload["hostname"] = platform.node()
    payload["process"] = _process_metadata()
    payload.update(_mission_metadata())
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name("." + path.name + ".tmp-" + str(os.getpid()))
    with temporary.open("w", encoding="utf-8", newline="\n") as stream:
        json.dump(payload, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    return envelope("checkpoint.write", {"file": os.path.normpath(os.fspath(path))}, payload)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_text(path: Path) -> str:
    if forbidden(path):
        raise ValueError("refusing to access a configured forbidden path")
    return path.read_text(encoding="utf-8", errors="replace")


def source_extract(args):
    path = safe_path(args.file)
    text = read_text(path)
    start = text.find(args.start)
    if start < 0:
        raise ValueError("start marker not found")
    end_search = start + len(args.start)
    end = text.find(args.end, end_search)
    if end < 0:
        raise ValueError("end marker not found after start marker")
    selected = text[start:end if args.exclude_end else end + len(args.end)]
    line_start = text.count("\n", 0, start) + 1
    line_end = text.count("\n", 0, (end if args.exclude_end else end + len(args.end))) + 1
    out = {"file": os.path.normpath(os.fspath(path)), "start_line": line_start,
           "end_line": line_end, "bytes_utf8": len(selected.encode()),
           "sha256": sha256(selected.encode()), "text": selected}
    return envelope("source.extract", {"file": out["file"], "start": args.start, "end": args.end}, out)


def source_xref(args):
    root = safe_path(args.root)
    if forbidden(root.resolve()):
        raise ValueError("refusing to access a configured forbidden path")
    pattern = re.compile(args.pattern) if args.regex else None
    matches = []
    paths = sorted(p for p in root.rglob("*") if p.is_file() and not forbidden(p))
    for path in paths:
        if args.glob and not path.match(args.glob):
            continue
        for lineno, line in enumerate(read_text(path).splitlines(), 1):
            found = bool(pattern.search(line)) if pattern else args.pattern in line
            if found:
                matches.append({"file": os.path.normpath(os.fspath(path)), "line": lineno, "text": line})
    out = {"matches": matches, "count": len(matches)}
    return envelope("source.xref", {"root": os.path.normpath(os.fspath(root)), "pattern": args.pattern}, out)



def source_function(args):
    path = safe_path(args.file)
    text = read_text(path)
    out = analyze_c_function(text, args.symbol, args.variable, args.max_lines, args.max_bytes)
    out["file"] = os.path.normpath(os.fspath(path))
    out["file_sha256"] = sha256(text.encode("utf-8"))
    return envelope(
        "source.function",
        {
            "file": out["file"],
            "symbol": args.symbol,
            "variables": sorted(set(args.variable or [])),
            "max_lines": args.max_lines,
            "max_bytes": args.max_bytes,
        },
        out,
    )

KV = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)=([^\s]+)")


def parse_int(value):
    try:
        return int(value, 0)
    except (TypeError, ValueError):
        return None


def trace_compare(args):
    path = safe_path(args.file)
    groups = {}
    records = malformed = 0
    for lineno, line in enumerate(read_text(path).splitlines(), 1):
        if args.prefix not in line:
            continue
        payload = line.split(args.prefix, 1)[1]
        fields = dict(KV.findall(payload))
        records += 1
        observed, reference = parse_int(fields.get(args.observed)), parse_int(fields.get(args.reference))
        if observed is None or reference is None:
            malformed += 1
            continue
        site = fields.get(args.site, "UNKNOWN")
        groups.setdefault(site, []).append({"line": lineno, "index": parse_int(fields.get(args.index)),
                                             "observed": observed, "reference": reference,
                                             "delta": observed - reference})
    sites = {}
    for site in sorted(groups):
        events = groups[site]
        deltas = sorted({e["delta"] for e in events})
        ratios = sorted({e["delta"] // e["index"] for e in events
                         if e["index"] not in (None, 0) and e["delta"] % e["index"] == 0})
        sites[site] = {"events": len(events), "matches": sum(e["delta"] == 0 for e in events),
                       "mismatches": sum(e["delta"] != 0 for e in events),
                       "nonzero_index_events": sum(e["index"] not in (None, 0) for e in events),
                       "unique_deltas": deltas, "integer_delta_per_index": ratios}
    out = {"records_seen": records, "records_usable": sum(map(len, groups.values())),
           "malformed": malformed, "sites": sites}
    status = "ok" if records else "no_records"
    return envelope("trace.compare", {"file": os.path.normpath(os.fspath(path)), "prefix": args.prefix}, out,
                    status=status)


def classify(path):
    name = path.name.lower()
    if name.endswith((".core", ".dmp", ".mdmp")) or name in {"core", "core.dump"}:
        return "LOCAL_ONLY"
    if name.endswith((".z64", ".n64", ".v64", ".rom")) or "rom" in name:
        return "REJECTED_GAME_DATA"
    return "text_or_binary"


def evidence_manifest(args):
    records = []
    for value in args.paths:
        path = safe_path(value)
        if not path.exists():
            raise ValueError(f"input does not exist: {path}")
        candidates = [path] if path.is_file() else sorted(p for p in path.rglob("*") if p.is_file())
        for item in candidates:
            if forbidden(item):
                raise ValueError("refusing to access a configured forbidden path")
            kind = classify(item)
            if kind == "REJECTED_GAME_DATA":
                raise ValueError(f"refusing game-data artifact: {item.name}")
            data = item.read_bytes()
            records.append({"path": os.path.normpath(os.fspath(item)), "bytes": len(data),
                            "sha256": sha256(data), "publication": kind})
    records.sort(key=lambda x: x["path"])
    out = {"artifacts": records, "count": len(records), "manifest_sha256": sha256(
        json.dumps(records, sort_keys=True, separators=(",", ":")).encode())}
    return envelope("evidence.manifest", {"paths": args.paths}, out)


def _env_pairs(values):
    result = {}
    for value in values or []:
        if "=" not in value:
            raise ValueError(f"environment override must be NAME=VALUE: {value}")
        key, val = value.split("=", 1)
        if not key or "=" in key:
            raise ValueError(f"invalid environment name: {key}")
        result[key] = val
    return result


def _run_argv(argv, cwd=None, timeout=60, env=None):
    started = time.time()
    try:
        completed = subprocess.run(argv, cwd=cwd, env=env, capture_output=True,
                                   text=True, encoding="utf-8", errors="replace",
                                   timeout=timeout, check=False)
        return completed, time.time() - started, None
    except subprocess.TimeoutExpired as exc:
        return exc, time.time() - started, "TIMEOUT"
    except (OSError, ValueError) as exc:
        return None, time.time() - started, str(exc)


def _result_status(rc, expected):
    return "PASS" if rc in expected else "FAIL"


def regression_run(args):
    manifest_path = safe_path(args.manifest)
    data = json.loads(read_text(manifest_path))
    cases = data.get("cases")
    if not isinstance(cases, list):
        raise ValueError("manifest cases must be an array")
    selected = [c for c in cases if args.case is None or c.get("id") == args.case]
    if args.case is not None and not selected:
        raise ValueError(f"case not found: {args.case}")
    selected.sort(key=lambda c: c.get("id", ""))
    records = []
    host = platform.system().lower()
    for case in selected:
        argv = case.get("argv")
        if case.get("available") is False:
            records.append({"case_id": case.get("id"), "display_name": case.get("display_name", case.get("id")),
                            "argv": argv or [], "cwd": case.get("cwd", "."), "platform": host,
                            "status": "SKIP", "reason": case.get("reason", "runner not established")})
            continue
        if not isinstance(argv, list) or not argv or not all(isinstance(x, str) for x in argv):
            raise ValueError(f"case {case.get('id')} argv must be a non-empty string array")
        cwd = os.path.normpath(os.fspath(safe_path(case.get("cwd", "."))))
        supported = case.get("supported_platforms", ["linux", "windows", "darwin"])
        expected = case.get("expected_exit_codes", [0])
        env_names = case.get("environment_allowlist", [])
        env = {k: os.environ[k] for k in env_names if k in os.environ}
        env.update(_env_pairs(case.get("environment_overrides", [])))
        record = {"case_id": case.get("id"), "display_name": case.get("display_name", case.get("id")),
                  "argv": argv, "cwd": cwd, "platform": host, "environment": env,
                  "expected_exit_codes": expected}
        if host not in [str(x).lower() for x in supported]:
            record["status"] = "SKIP"; record["reason"] = "unsupported platform"
        elif not Path(cwd).is_dir():
            record["status"] = "SKIP"; record["reason"] = "working directory unavailable"
        elif any(not shutil.which(argv[0], path=env.get("PATH")) and not Path(argv[0]).is_file()
                 for _ in [0]):
            record["status"] = "SKIP"; record["reason"] = "executable unavailable"
        elif args.dry_run:
            record["status"] = "SKIP"; record["reason"] = "dry run"
        else:
            full_env = os.environ.copy(); full_env.update(env)
            proc, duration, error = _run_argv(argv, cwd, float(case.get("timeout", 60)), full_env)
            record["duration_seconds"] = duration
            if error == "TIMEOUT":
                record["status"] = "TIMEOUT"; record["stdout"] = getattr(proc, "stdout", "") or ""; record["stderr"] = getattr(proc, "stderr", "") or ""; record["exit_code"] = None
            elif error:
                record["status"] = "ERROR"; record["error"] = error; record["exit_code"] = None
            else:
                record["exit_code"] = proc.returncode; record["stdout"] = proc.stdout; record["stderr"] = proc.stderr
                record["status"] = _result_status(proc.returncode, expected)
        records.append(record)
    statuses = {s: sum(r["status"] == s for r in records) for s in ("PASS", "FAIL", "SKIP", "TIMEOUT", "ERROR")}
    status = "ok" if not any(statuses[x] for x in ("FAIL", "TIMEOUT", "ERROR")) else "error"
    return envelope("regression.run", {"manifest": os.path.normpath(os.fspath(manifest_path)), "case": args.case, "dry_run": args.dry_run},
                    {"manifest_version": data.get("manifest_version", 1), "results": records, "counts": statuses}, status=status)


def compiler_version(executable):
    proc, _, error = _run_argv([executable, "--version"], timeout=10)
    if error or proc.returncode:
        return {"executable": executable, "error": error or "version command failed"}
    return {"executable": executable, "version": (proc.stdout or proc.stderr).splitlines()[0] if (proc.stdout or proc.stderr) else ""}


def probe_compile(args):
    compiler = shutil.which(args.compiler) or (args.compiler if Path(args.compiler).is_file() else None)
    inputs = [safe_path(p) for p in args.inputs]
    if not compiler:
        return envelope("probe.compile", {"compiler": args.compiler, "inputs": args.inputs}, {"status": "SKIP", "reason": "compiler unavailable"}, status="ok")
    for path in inputs:
        if not path.is_file():
            raise ValueError(f"input does not exist: {path}")
    output = safe_path(args.output) if args.output else Path(tempfile.gettempdir()) / ("apollo-probe.exe" if os.name == "nt" else "apollo-probe")
    argv = [compiler, *args.flags, *[os.fspath(p) for p in inputs], "-o", os.fspath(output)]
    proc, duration, error = _run_argv(argv, args.cwd, args.timeout, os.environ.copy())
    result = {"compiler": compiler, "compiler_metadata": compiler_version(compiler), "argv": argv,
              "cwd": os.path.abspath(args.cwd or os.getcwd()), "duration_seconds": duration,
              "input_digests": [{"path": os.fspath(p), "sha256": sha256(p.read_bytes())} for p in inputs],
              "output": os.fspath(output), "status": "TIMEOUT" if error == "TIMEOUT" else ("ERROR" if error else ("PASS" if proc.returncode == 0 else "FAIL")),
              "exit_code": None if error else proc.returncode, "stdout": "" if error else proc.stdout, "stderr": error or ("" if error else proc.stderr)}
    return envelope("probe.compile", {"compiler": args.compiler, "inputs": args.inputs}, result, status="ok" if result["status"] == "PASS" else "error")


def patch_check(args):
    repo = safe_path(args.repo); patch = safe_path(args.patch)
    if not repo.is_dir() or not patch.is_file(): raise ValueError("repo or patch does not exist")
    digest = sha256(patch.read_bytes())
    def git(*parts):
        return _run_argv(["git", *parts], str(repo), 20, os.environ.copy())[0]
    head = git("rev-parse", "HEAD"); ident = git("remote", "get-url", "origin"); stat = git("status", "--short")
    check, duration, error = _run_argv(["git", "apply", "--check", "--", str(patch)], str(repo), 30, os.environ.copy())
    if error: state = "execution-error"
    else: state = "applies" if check.returncode == 0 else "does-not-apply"
    out = {"result": state, "repo": os.path.abspath(repo), "head": (head.stdout.strip() if head else None),
           "repository_identity": (ident.stdout.strip() if ident and ident.returncode == 0 else None),
           "status_short": stat.stdout if stat and stat.returncode == 0 else None, "patch": os.path.abspath(patch),
           "patch_sha256": digest, "argv": ["git", "apply", "--check", "--", str(patch)], "duration_seconds": duration,
           "exit_code": None if error else check.returncode, "stdout": "" if error else check.stdout, "stderr": error or check.stderr}
    return envelope("patch.check", {"repo": os.fspath(repo), "patch": os.fspath(patch)}, out, status="ok" if state == "applies" else "error")


def parser():
    p = argparse.ArgumentParser(prog="apollo", description=__doc__)
    p.add_argument("--json", action="store_true", help="emit the full structured evidence envelope")
    sub = p.add_subparsers(dest="group", required=True)
    from apollo_session import add_cli as add_session_cli
    add_session_cli(sub)
    source = sub.add_parser("source", help="deterministic source facts")
    ss = source.add_subparsers(dest="action", required=True)
    ex = ss.add_parser("extract", help="extract text between literal markers")
    ex.add_argument("--file", required=True); ex.add_argument("--start", required=True); ex.add_argument("--end", required=True)
    ex.add_argument("--exclude-end", action="store_true"); ex.set_defaults(func=source_extract)
    xr = ss.add_parser("xref", help="find sorted source references")
    xr.add_argument("--root", required=True); xr.add_argument("--pattern", required=True); xr.add_argument("--regex", action="store_true"); xr.add_argument("--glob")
    xr.set_defaults(func=source_xref)
    fn = ss.add_parser("function", help="extract bounded lexical evidence for one C function")
    fn.add_argument("--file", required=True); fn.add_argument("--symbol", required=True)
    fn.add_argument("--variable", action="append", default=[])
    fn.add_argument("--max-lines", type=int, default=500); fn.add_argument("--max-bytes", type=int, default=131072)
    fn.set_defaults(func=source_function)
    trace = sub.add_parser("trace", help="compare structured key/value traces")
    ts = trace.add_subparsers(dest="action", required=True)
    tc = ts.add_parser("compare", help="group observed/reference deltas")
    tc.add_argument("--file", required=True); tc.add_argument("--prefix", default="TRACE_COMPARE"); tc.add_argument("--site", default="site")
    tc.add_argument("--observed", default="observed"); tc.add_argument("--reference", default="reference"); tc.add_argument("--index", default="index"); tc.set_defaults(func=trace_compare)
    ev = sub.add_parser("evidence", help="safe artifact evidence")
    es = ev.add_subparsers(dest="action", required=True)
    em = es.add_parser("manifest", help="hash explicitly named artifacts"); em.add_argument("paths", nargs="+"); em.set_defaults(func=evidence_manifest)
    regression = sub.add_parser("regression", help="run declarative regressions")
    rs = regression.add_subparsers(dest="action", required=True)
    rr = rs.add_parser("run", help="execute manifest cases with argv arrays")
    rr.add_argument("--manifest", required=True); rr.add_argument("--case"); rr.add_argument("--dry-run", action="store_true"); rr.set_defaults(func=regression_run)
    probe = sub.add_parser("probe", help="bounded toolchain probes")
    ps = probe.add_subparsers(dest="action", required=True)
    pc = ps.add_parser("compile", help="compile inputs and report compiler facts")
    pc.add_argument("inputs", nargs="+"); pc.add_argument("--compiler", default=os.environ.get("CC", "cc")); pc.add_argument("--cwd", default=None)
    pc.add_argument("--output"); pc.add_argument("--timeout", type=float, default=60); pc.add_argument("--flag", dest="flags", action="append", default=[]); pc.set_defaults(func=probe_compile)
    patch = sub.add_parser("patch", help="read-only patch operations")
    pas = patch.add_subparsers(dest="action", required=True)
    pcheck = pas.add_parser("check", help="check patch applicability without applying")
    pcheck.add_argument("--repo", required=True); pcheck.add_argument("--patch", required=True); pcheck.set_defaults(func=patch_check)
    journal = sub.add_parser("journal", help="semantic records with host-generated timestamp metadata")
    js = journal.add_subparsers(dest="action", required=True)
    ja = js.add_parser("append", help="append one JSONL record; timestamp comes from the host clock")
    ja.add_argument("--journal", required=True); ja.add_argument("--phase", required=True)
    ja.add_argument("--action", required=True); ja.add_argument("--status", required=True)
    ja.add_argument("--artifact", action="append", default=[])
    ja.add_argument("--next-action", required=True); ja.set_defaults(func=journal_append)
    checkpoint = sub.add_parser("checkpoint", help="atomically write a host-metadata checkpoint")
    cs = checkpoint.add_subparsers(dest="action", required=True)
    cw = cs.add_parser("write", help="write JSON object; timestamp fields are unavailable to callers")
    cw.add_argument("--file", required=True); cw.add_argument("--record", required=True); cw.set_defaults(func=checkpoint_write)
    return p


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        result = args.func(args)
    except (OSError, ValueError) as exc:
        result = envelope(getattr(args, "action", "unknown"), {}, {}, [str(exc)], "error")
        emit(result, args.json)
        return 2
    emit(result, args.json)
    return 0 if result["status"] == "ok" else 2


if __name__ == "__main__":
    raise SystemExit(main())
