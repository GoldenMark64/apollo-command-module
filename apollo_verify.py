"""Offline, read-only intrinsic verification of Apollo session v1 bundles."""
import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat

ROOT = Path(__file__).absolute().parent
FIELDS = ('backtrace', 'registers', 'disassembly', 'modules', 'threads')
BASE = {'evidence.json', 'report.md', *(f + '.txt' for f in FIELDS)}
RUNTIME = {'runtime-tail.json', 'runtime.stdout.log', 'runtime.stderr.log', 'debugger-transcript.txt'}
TERMINAL = {'PROGRAM_EXITED_NORMALLY', 'CRASH_CAPTURED', 'TIMEOUT', 'INTERRUPTED', 'DEBUGGER_ERROR', 'CAPTURE_INCOMPLETE'}
COMPLETE = {'PROGRAM_EXITED_NORMALLY', 'CRASH_CAPTURED'}
FATAL = {'SIGSEGV', 'SIGABRT', 'SIGILL', 'SIGFPE', 'SIGBUS', 'SIGTRAP', 'SIGSYS'}
LIMIT = 32 * 1024 * 1024


def local(value):
    # Lexical rejection precedes every filesystem operation. Never resolve links.
    p = Path(os.path.abspath(value))
    if not p.is_relative_to(ROOT):
        raise ValueError('verification paths must stay inside Apollo')
    return p


def directory(path):
    """Walk from the workspace using pinned, no-follow directory descriptors."""
    fd = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NOATIME)
    try:
        for part in path.relative_to(ROOT).parts:
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NOATIME, dir_fd=fd)
            os.close(fd)
            fd = nxt
        return fd
    except BaseException:
        os.close(fd)
        raise


def decode(data):
    def pairs(items):
        out = {}
        for k, v in items:
            if k in out: raise ValueError('duplicate JSON key')
            out[k] = v
        return out
    def constant(_): raise ValueError('nonfinite JSON number')
    return json.loads(data, object_pairs_hook=pairs, parse_constant=constant)


def verify(session):
    path = local(session)
    r = dict(schema_version='apollo.session-verification.v1', verification_status='UNVERIFIABLE',
             completeness='UNKNOWN', session_status=None, session_id=None,
             verified_artifact_count=0, failed_artifact_count=0, missing_artifacts=[],
             unexpected_artifacts=[], hash_mismatches=[], size_mismatches=[],
             schema_result='UNKNOWN', semantic_checks=[], reasons=[], warnings=[
                 'Intrinsic consistency only; no signed trust anchor or external provenance verification.',
                 'All evidence remains REVIEW_REQUIRED; VERIFIED does not authorize sharing.'])
    bad = set()
    def fail(reason, artifact=None):
        r['reasons'].append(reason)
        if artifact: bad.add(artifact)
    data = {}
    fd = None
    try:
        fd = directory(path)
        names = sorted(os.listdir(fd))
        for name in names:
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            # Known ephemeral FIFO names from the v1 controller are not evidence.
            if name in ('.stdout.fifo', '.stderr.fifo') and stat.S_ISFIFO(info.st_mode):
                r['warnings'].append('Unopened controller FIFO: ' + name)
                continue
            if not stat.S_ISREG(info.st_mode):
                fail('Unsafe nonregular artifact: ' + name, name)
                continue
            f = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOATIME, dir_fd=fd)
            try:
                before = os.fstat(f)
                if not stat.S_ISREG(before.st_mode) or before.st_size > LIMIT:
                    fail('Nonregular or oversized artifact: ' + name, name)
                    continue
                with os.fdopen(os.dup(f), 'rb') as stream: blob = stream.read(LIMIT + 1)
                after = os.fstat(f)
                if (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                    fail('Artifact changed during read: ' + name, name)
                data[name] = blob
                core = blob[:4] == b'MDMP' or (blob[:4] == b'\x7fELF' and len(blob) >= 18 and int.from_bytes(blob[16:18], 'little' if blob[5] == 1 else 'big') == 4)
                if core or re.search(r'(^core($|[.])|[.](core|dmp|mdmp|minidump)$)', name, re.I):
                    fail('Forbidden raw dump artifact: ' + name, name)
            finally: os.close(f)
    except OSError:
        fail('Bundle unreadable or unsafe path')
        return finish(r, bad)
    finally:
        if fd is not None: os.close(fd)
    try:
        e = decode(data['evidence.json']); m = decode(data['manifest.json'])
        if not isinstance(e, dict) or not isinstance(m, dict): raise ValueError()
    except (KeyError, ValueError, UnicodeError, RecursionError):
        fail('Missing or malformed evidence.json or manifest.json')
        return finish(r, bad)
    r['session_status'] = e.get('status') if isinstance(e.get('status'), str) else None
    r['session_id'] = e.get('session_id') if isinstance(e.get('session_id'), str) else None
    if e.get('schema_version') != 'apollo.session.v1' or m.get('schema_version') != 'apollo.session-manifest.v1':
        r['schema_result'] = 'UNSUPPORTED'; r['verification_status'] = 'UNSUPPORTED_SCHEMA'
        fail('Unsupported evidence or manifest schema')
        return finish(r, bad)
    r['schema_result'] = 'SUPPORTED'
    r['verification_status'] = 'CORRUPTED'
    records = m.get('artifacts')
    if not isinstance(records, list):
        fail('Manifest artifacts must be a list')
        return finish(r, bad)
    inventory = set()
    for a in records:
        if not isinstance(a, dict) or not isinstance(a.get('path'), str) or not re.fullmatch('[a-z][a-z0-9.-]*', a['path']) or a['path'] == 'manifest.json':
            fail('Invalid manifest artifact name'); continue
        name = a['path']
        if name in inventory: fail('Duplicate artifact: ' + name, name)
        inventory.add(name)
        if name not in BASE | RUNTIME: fail('Unknown v1 artifact: ' + name, name)
        if a.get('safety') != 'REVIEW_REQUIRED' or a.get('raw_memory_dump') is not False:
            fail('Invalid safety classification: ' + name, name)
        if name not in data:
            r['missing_artifacts'].append(name); fail('Missing artifact: ' + name, name); continue
        if type(a.get('bytes')) is not int or a['bytes'] != len(data[name]):
            r['size_mismatches'].append(name); fail('Byte count mismatch: ' + name, name)
        if not isinstance(a.get('sha256'), str) or not re.fullmatch('[0-9a-f]{64}', a['sha256']) or a['sha256'] != hashlib.sha256(data[name]).hexdigest():
            r['hash_mismatches'].append(name); fail('SHA-256 mismatch: ' + name, name)
    actual = set(names) - {'manifest.json'} - {n for n in names if n in ('.stdout.fifo', '.stderr.fifo') and n not in data and n not in bad}
    r['unexpected_artifacts'] = sorted(actual - inventory)
    for n in r['unexpected_artifacts']: fail('Uninventoried artifact: ' + n, n)
    required = BASE | (RUNTIME if 'runtime' in e or e.get('status') in {'RUNNING', *COMPLETE} else set())
    for n in sorted(required - inventory):
        fail('Required artifact absent from manifest: ' + n, n)
        if n not in data: r['missing_artifacts'].append(n)
    def check(name, ok):
        r['semantic_checks'].append({'check': name, 'passed': bool(ok)})
        if not ok: fail('Semantic inconsistency: ' + name)
    try:
        semantics(e, m, data, check)
    except (KeyError, TypeError, ValueError, AttributeError, OverflowError, RecursionError):
        check('required semantic structure and types', False)
    r['verified_artifact_count'] = len(inventory - bad)
    if not r['reasons']:
        r['verification_status'] = 'VERIFIED'
        r['completeness'] = 'COMPLETE' if e['status'] in COMPLETE else 'PARTIAL'
    return finish(r, bad)


def semantics(e, m, data, check):
    mode = e.get('capture_mode')
    check('capture mode identity', (
        mode == 'application' and 'fixture' in e and e['fixture'] is None
        and isinstance(e.get('application'), str) and bool(e.get('application'))
    ))
    check('runtime marker applicability',
          'runtime_marker_reached' in e and e['runtime_marker_reached'] is None)
    check('explicit mode metadata', 'fixture' in e and 'application' in e)
    status = e['status']; stale = status in {'STARTING', 'RUNNING'}
    check('manifest policy', m.get('excludes_self') is True and m.get('raw_cores') is False)
    sid = e['session_id']
    check('session identity and manifest reference', isinstance(sid, str) and bool(sid) and not sid.startswith('/') and all(p not in ('', '.', '..') for p in sid.split('/')) and '\\' not in sid and e.get('artifact_manifest') == 'manifest.json')
    check('report identity and status', data['report.md'].decode() == f"# Apollo session {sid}\n\nStatus: {status}\n\nPartial: {e['partial']}\n\nAll artifacts require local review before sharing.\n")
    check('status and partial', status in TERMINAL | {'STARTING', 'RUNNING'} and type(e['partial']) is bool and e['partial'] == (status not in COMPLETE))
    valid = [['STARTING']] if status == 'STARTING' else ([['STARTING', 'RUNNING']] if status == 'RUNNING' else [['STARTING', status], ['STARTING', 'RUNNING', status]])
    check('lifecycle', e['lifecycle'] in valid and (status not in COMPLETE or e['lifecycle'] == ['STARTING', 'RUNNING', status]))
    start = datetime.datetime.fromisoformat(e['timestamp_started'])
    check('start timestamp timezone', start.utcoffset() is not None)
    if stale:
        check('unfinished checkpoint', e.get('timestamp_finished') is None and 'duration_seconds' not in e and e.get('stop') is None)
    else:
        end = datetime.datetime.fromisoformat(e['timestamp_finished']); duration = e['duration_seconds']
        check('ordered terminal timestamps', end.utcoffset() is not None and end >= start and type(duration) in (int, float) and math.isfinite(duration) and duration >= 0)
    limits = e['limits']
    check('capture limits', type(limits['runtime_bytes_per_stream']) is int and 1 <= limits['runtime_bytes_per_stream'] <= 2097152 and limits['debugger_transcript_bytes'] == 2097152 and limits['mi_record_bytes'] == 2097152 and limits['stack_frames'] == 32 and limits['thread_summary_count'] == 64 and limits['core_bytes'] == 0 and limits['all_thread_backtraces'] is False and 0 < limits['timeout_seconds'] <= 86400)
    for field in FIELDS:
        check(field + ' artifact agrees', decode(data[field + '.txt']) == e.get(field))
    if 'runtime' in e:
        rt = decode(data['runtime-tail.json'])
        check('runtime metadata agrees', rt['streams'] == e['runtime'] and type(rt['observation_complete']) is bool and (not rt['observation_complete'] or status == 'PROGRAM_EXITED_NORMALLY'))
        def tail(meta, name, limit):
            obs, retained, chunks = (meta[k] for k in ('observed_bytes', 'retained_bytes', 'observed_read_chunks'))
            check(name + ' accounting', all(type(v) is int and v >= 0 for v in (obs, retained, chunks)) and retained == len(data[name]) == min(obs, limit) and chunks <= obs and (chunks == 0) == (obs == 0) and meta['configured_limit'] == limit and type(meta['truncated']) is bool and meta['truncated'] == (obs > retained))
        for stream in ('stdout', 'stderr'): tail(e['runtime'][stream], 'runtime.' + stream + '.log', limits['runtime_bytes_per_stream'])
        tail(e['transcript'], 'debugger-transcript.txt', limits['debugger_transcript_bytes'])
    else: check('absent runtime only before transport', not (set(data) & RUNTIME) and status not in {'RUNNING', *COMPLETE})
    stop = e.get('stop') or {}
    required = ['signal', 'crashing_thread', 'stop_frame', *FIELDS]
    if not stale:
        if e.get('signal') == 'SIGSEGV': required.append('fault_address')
        missing = [k for k in required if not e.get(k)]
        if not e['debugger'].get('version'): missing.append('debugger_version')
        if not e['executable'].get('sha256'): missing.append('executable_sha256')
        if not data.get('debugger-transcript.txt'): missing.append('debugger_transcript')
        check('missing crash evidence accounting', e.get('missing_crash_evidence') == missing)
        if status == 'CAPTURE_INCOMPLETE':
            check('incomplete outcome', stop.get('reason') not in ('exited', 'exited-normally') and not (stop.get('reason') in ('signal-received', 'exited-signalled') and e.get('signal') in FATAL and not missing))
    if status == 'PROGRAM_EXITED_NORMALLY': check('normal stop', stop.get('reason') in ('exited', 'exited-normally') and not e.get('signal') and not e.get('errors'))
    if status == 'CRASH_CAPTURED':
        check('crash required evidence', all(e.get(k) for k in required) and e.get('missing_crash_evidence') == [] and not e.get('errors') and bool(e['debugger'].get('version')) and bool(re.fullmatch('[0-9a-f]{64}', e['executable'].get('sha256') or '')) and bool(data.get('debugger-transcript.txt')))
        check('crash stop agrees', stop.get('reason') in ('signal-received', 'exited-signalled') and e['signal'] in FATAL and stop.get('signal-name') == e['signal'] and stop.get('thread-id') == e['crashing_thread'] and stop.get('frame') == e['stop_frame'] and e['thread_id_scope'] == 'gdb')
        check('fault address', e['signal'] != 'SIGSEGV' or bool(re.fullmatch('0x[0-9a-fA-F]+', e.get('fault_address') or '')))
        check('crashing thread retained', any(t['id'] == e['crashing_thread'] for t in e['threads']))
    if e.get('backtrace') is not None: check('stack bound', isinstance(e['backtrace'], list) and len(e['backtrace']) <= 32)
    if e.get('threads') is not None:
        t = e['thread_summary']; count = len(e['threads'])
        check('thread accounting', type(t['observed_threads']) is int and t['observed_threads'] >= count and count == t['retained_threads'] == min(t['observed_threads'], 64) and t['configured_limit'] == 64 and type(t['truncated']) is bool and t['truncated'] == (t['observed_threads'] > count) and len({x['id'] for x in e['threads']}) == count)


def finish(r, bad):
    r['failed_artifact_count'] = len(bad)
    for key in ('reasons', 'warnings', 'missing_artifacts', 'unexpected_artifacts', 'hash_mismatches', 'size_mismatches'):
        r[key] = sorted(set(r[key]))
    r['semantic_checks'].sort(key=lambda c: c['check'])
    return r


def report(result):
    return '# Apollo offline session verification\n\n```json\n' + json.dumps(result, indent=2, sort_keys=True) + '\n```\n'


def cli(args):
    from apollo import envelope
    target = local(args.session)
    if args.output:
        output = local(args.output)
        if output.is_relative_to(target) or target.is_relative_to(output):
            raise ValueError('output must be separate from the target bundle')
        parent = directory(output.parent)
        try: os.mkdir(output.name, mode=0o700, dir_fd=parent)
        finally: os.close(parent)
    result = verify(target)
    if args.output:
        fd = directory(output)
        try:
            for name, blob in [('verification.json', json.dumps(result, indent=2, sort_keys=True) + '\n'), ('report.md', report(result))]:
                f = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
                with os.fdopen(f, 'w') as stream: stream.write(blob)
        finally: os.close(fd)
    return envelope('session.verify', {'session': str(target)}, result, status='ok' if result['verification_status'] == 'VERIFIED' else 'error')
