"""Linux session controller with explicit application admission and bounded GDB/MI transport."""
import datetime
import hashlib
import json
import math
import os
from pathlib import Path

from apollo_policy import (
    ApplicationProfile,
    is_forbidden_path,
    load_application_profiles,
)
import platform
import re
import selectors
import shlex
import shutil
import signal
import stat
import subprocess
import tempfile
import time

from apollo_crash import MIParser, ProtocolError, parse_record, safe_local, digest_executable, child_limits, FATAL

ROOT = Path(__file__).absolute().parent
APPLICATION_PROFILES = load_application_profiles()


def application_profile(identity):
    """Select by actual hostname and identity without accessing application paths."""
    profile = APPLICATION_PROFILES.get((platform.node(), identity))
    if profile is None:
        raise ValueError('application hostname/identity is not approved')
    return profile


APPLICATION_ENV_ALLOWLIST = (
    'DISPLAY', 'XAUTHORITY', 'WAYLAND_DISPLAY', 'XDG_RUNTIME_DIR',
    'DBUS_SESSION_BUS_ADDRESS', 'PULSE_SERVER', 'SDL_AUDIODRIVER',
    'SDL_VIDEODRIVER',
)
TEXT_LIMIT = 2 * 1024 * 1024


def application_limits():
    """Disable cores without changing the host's inherited file-size limits."""
    import resource
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def local(value):
    path = Path(os.path.abspath(value))
    if not path.is_relative_to(ROOT):
        raise ValueError('session paths must stay in the Apollo workspace')
    return safe_local(path)



def admit_application(identity, value):
    """Return an approved path, pinned executable fd and SHA-256; caller closes fd.

    Lexical checks precede IO. Walk each component relative to a pinned directory;
    neither ancestor links nor a substituted final symlink can be followed.
    """
    profile = application_profile(identity)
    raw = Path(value)
    if '..' in raw.parts or is_forbidden_path(raw):
        raise ValueError('forbidden application path')
    path = Path(os.path.abspath(value))
    approved = profile.executable
    if is_forbidden_path(path) or approved is None or path != approved:
        raise ValueError('application identity/path is not approved')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:-1]:
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nxt
        executable = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    finally:
        os.close(fd)
    try:
        before = os.fstat(executable)
        if not stat.S_ISREG(before.st_mode) or not before.st_mode & 0o111:
            raise ValueError('application must be a regular executable file')
        digest = hashlib.sha256()
        while chunk := os.read(executable, 65536):
            digest.update(chunk)
        after = os.fstat(executable)
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError('application changed during hashing')
        os.lseek(executable, 0, os.SEEK_SET)
        return path, executable, digest.hexdigest()
    except BaseException:
        os.close(executable)
        raise


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def normalize(stop, missing=(), cause=None):
    # The first controller terminal cause is latched; cleanup cannot replace it.
    if cause is not None:
        return cause
    reason = (stop or {}).get('reason')
    if reason in ('exited', 'exited-normally'):
        return 'PROGRAM_EXITED_NORMALLY'
    if reason == 'exited-signalled' or (reason == 'signal-received' and stop.get('signal-name') in FATAL):
        return 'CAPTURE_INCOMPLETE' if missing else 'CRASH_CAPTURED'
    return 'CAPTURE_INCOMPLETE'


def thread_summary(threads, crashing_thread, limit=64):
    if not isinstance(threads, list) or any(not isinstance(t, dict) for t in threads):
        raise ProtocolError('invalid thread summary')
    selected = threads[:limit]
    crash = next((t for t in threads if t.get('id') == crashing_thread), None)
    if crash is not None and crash not in selected:
        selected[-1:] = [crash]
    return selected, {'observed_threads': len(threads), 'retained_threads': len(selected),
                      'configured_limit': limit, 'truncated': len(threads) > len(selected),
                      'identity_scope': 'gdb; target-id is retained as opaque debugger text'}


class Tail:
    """Byte tail, bounded independently of record size and session duration."""
    def __init__(self, limit):
        self.limit = limit
        self.data = bytearray()
        self.observed = self.records = 0

    def append(self, data):
        self.observed += len(data)
        self.records += 1
        self.data.extend(data[-self.limit:])
        del self.data[:-self.limit]

    def metadata(self):
        return {'truncated': self.observed > len(self.data), 'retained_bytes': len(self.data),
                'observed_bytes': self.observed, 'observed_read_chunks': self.records,
                'configured_limit': self.limit}


class Bundle:
    def __init__(self, output):
        self.path = local(output)
        self.path.mkdir(parents=True, exist_ok=False, mode=0o700)
        self.session_id = str(self.path.relative_to(ROOT))

    def write(self, name, data):
        if not re.fullmatch(r'[a-z][a-z0-9.-]*', name):
            raise ValueError('invalid artifact basename')
        path = local(self.path / name)
        temp = local(self.path / ('.' + name + '.tmp'))
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp, path)
            fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY)
            try: os.fsync(fd)
            finally: os.close(fd)
        finally:
            if temp.exists(): temp.unlink()

    def json(self, name, value):
        self.write(name, (json.dumps(value, indent=2, sort_keys=True) + '\n').encode())

    def checkpoint(self, evidence, transport=None):
        if transport:
            for name, tail in transport.tails.items():
                self.write(name, bytes(tail.data))
            evidence['runtime'] = {name: transport.tails['runtime.' + name + '.log'].metadata()
                                   for name in ('stdout', 'stderr')}
            evidence['transcript'] = transport.tails['debugger-transcript.txt'].metadata()
            evidence['runtime_marker_reached'] = transport.marker_reached
            evidence['debugger']['pid'] = transport.proc.pid
            evidence['inferior']['pid'] = transport.inferior_pid
            self.json('runtime-tail.json', {'streams': evidence['runtime'],
                'ordering': 'Per-stream byte order only; no cross-stream emission order is claimed.',
                'accounting': 'Observed pipe bytes/read chunks; unread bytes after forced cleanup are unknown.',
                'observation_complete': evidence.get('status') == 'PROGRAM_EXITED_NORMALLY' and transport.drain_complete})
        for field in ('backtrace', 'registers', 'disassembly', 'modules', 'threads'):
            self.json(field + '.txt', evidence.get(field))
        evidence['artifact_manifest'] = 'manifest.json'
        self.json('evidence.json', evidence)
        self.write('report.md', (f"# Apollo session {self.session_id}\n\nStatus: {evidence['status']}\n\n"
            f"Partial: {evidence['partial']}\n\nAll artifacts require local review before sharing.\n").encode())
        records = []
        for path in sorted(self.path.iterdir()):
            if path.name == 'manifest.json' or path.name.startswith('.'): continue
            local(path)
            if not path.is_file(): raise ValueError('unexpected session artifact')
            data = path.read_bytes()
            records.append({'path': path.name, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
                            'safety': 'REVIEW_REQUIRED', 'raw_memory_dump': False})
        self.json('manifest.json', {'schema_version': 'apollo.session-manifest.v1', 'artifacts': records,
                  'excludes_self': True, 'raw_cores': False, 'checkpoint_atomicity': 'per-file; verify hashes after unclean shutdown'})


class Transport:
    def __init__(self, argv, bundle, timeout, limit, marker, *, application=None):
        self.deadline = time.monotonic() + timeout
        self.tails = {name: Tail(limit if name.startswith('runtime.') else TEXT_LIMIT)
                      for name in ('runtime.stdout.log', 'runtime.stderr.log', 'debugger-transcript.txt')}
        self.selector = selectors.DefaultSelector()
        self.pending = b''
        self.results = {}
        self.stop_record = None
        self.version = ''
        self.token = 0
        self.inferior_pid = None
        self.inferior_fd = None
        self.proc = None
        self.fifos = []
        self.fds = []
        self.marker = marker.encode() if marker is not None else None
        self.marker_pending = b''
        self.marker_reached = False if marker is not None else None
        self.closed = False
        self.drain_complete = False
        self.runtime_state = None
        try:
            cwd = bundle.path
            limits = child_limits
            env = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'HOME': str(bundle.path), 'DEBUGINFOD_URLS': ''}
            if application is not None:
                profile = application_profile(application)
                cwd = profile.cwd
                limits = application_limits
                # Explicit /tmp avoids host TMPDIR placing state inside evidence.
                self.runtime_state = tempfile.TemporaryDirectory(prefix='apollo-application-', dir='/tmp')
                state = Path(self.runtime_state.name)
                allowed_env = APPLICATION_ENV_ALLOWLIST + profile.env_allowlist
                env.update({name: os.environ[name] for name in allowed_env if name in os.environ})
                for name, directory in (('HOME', 'home'), ('XDG_CACHE_HOME', 'cache'),
                                        ('XDG_CONFIG_HOME', 'config'), ('XDG_DATA_HOME', 'data')):
                    path = state / directory
                    path.mkdir(mode=0o700)
                    env[name] = str(path)
            for name in ('stdout', 'stderr'):
                path = local(bundle.path / ('.' + name + '.fifo'))
                os.mkfifo(path, 0o600)
                self.fifos.append(path)
                fd = os.open(path, os.O_RDWR | os.O_NONBLOCK | os.O_NOFOLLOW)
                self.fds.append(fd)
                self.selector.register(fd, selectors.EVENT_READ, 'runtime.' + name + '.log')
            self.proc = subprocess.Popen(argv, cwd=cwd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, start_new_session=True, preexec_fn=limits, env=env)
            self.selector.register(self.proc.stdout, selectors.EVENT_READ, 'debugger-transcript.txt')
        except BaseException:
            self.close()
            raise

    def read(self, key):
        try: data = os.read(key.fd, 8192)
        except BlockingIOError: return
        if not data:
            self.selector.unregister(key.fileobj)
            return
        self.tails[key.data].append(data)
        if key.data == 'runtime.stdout.log' and self.marker is not None:
            probe = self.marker_pending + data
            self.marker_reached |= self.marker in probe
            self.marker_pending = probe[-len(self.marker):]
        if key.data != 'debugger-transcript.txt': return
        self.pending += data
        if len(self.pending) > TEXT_LIMIT: raise ProtocolError('MI line exceeds limit')
        while b'\n' in self.pending:
            line, self.pending = self.pending.split(b'\n', 1)
            line = line.decode('utf-8', 'replace').rstrip('\r')
            if not line or line.strip() == '(gdb)': continue
            if line[0] in '~@&':
                parser = MIParser(line[1:]); value = parser.value()
                if parser.i != len(parser.text) or not isinstance(value, str): raise ProtocolError('bad MI stream')
                if self.token == 1: self.version = (self.version + value)[-65536:]
                continue
            record = parse_record(line)
            if record['kind'] == '^':
                if record['token'] != str(self.token): raise ProtocolError('unexpected MI result token')
                self.results[record['token']] = record
            elif record['kind'] == '*' and record['class'] == 'stopped':
                if self.stop_record is None: self.stop_record = record['data']
            elif record['kind'] == '=' and record['class'] == 'thread-group-started':
                pid = record['data'].get('pid', '')
                if not str(pid).isdigit() or self.inferior_pid is not None: raise ProtocolError('invalid inferior identity')
                self.inferior_pid = int(pid)
                try: self.inferior_fd = os.pidfd_open(self.inferior_pid)
                except ProcessLookupError: pass

    def pump(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0: raise TimeoutError('session deadline exceeded')
        for key, _ in self.selector.select(min(.1, remaining)): self.read(key)
        if self.proc.poll() is not None and not any(k.data == 'debugger-transcript.txt' for k in self.selector.get_map().values()):
            if not self.results and self.stop_record is None: raise ProtocolError('debugger closed protocol stream')

    def command(self, command, optional=False):
        self.token += 1
        token = str(self.token)
        self.proc.stdin.write((token + command + '\n').encode()); self.proc.stdin.flush()
        while token not in self.results:
            self.pump()
            if self.proc.poll() is not None and token not in self.results: raise ProtocolError('debugger exited during command')
        result = self.results.pop(token)
        if result['class'] == 'error' and not optional: raise ProtocolError(result['data'].get('msg', 'command failed'))
        return result

    def close(self):
        if self.closed: return
        self.closed = True
        errors = []
        if self.inferior_fd is not None:
            try: signal.pidfd_send_signal(self.inferior_fd, signal.SIGKILL)
            except ProcessLookupError: pass
            except OSError as exc: errors.append(str(exc))
            finally: os.close(self.inferior_fd)
        if self.proc is not None:
            # Do not signal a numeric group after reaping its leader (PID reuse).
            if self.proc.poll() is None:
                try: os.killpg(self.proc.pid, signal.SIGKILL)
                except ProcessLookupError: pass
                except OSError as exc: errors.append(str(exc))
            try: self.proc.wait(timeout=2)
            except subprocess.TimeoutExpired: errors.append('debugger reap deadline exceeded')
            # Drain is bounded in time even if a defective descendant retains a pipe.
            deadline = time.monotonic() + .5
            while time.monotonic() < deadline:
                ready = self.selector.select(0)
                if not ready:
                    self.drain_complete = True
                    break
                for key, _ in ready:
                    try: self.read(key)
                    except (OSError, ValueError) as exc: errors.append(str(exc))
            for stream in (self.proc.stdin, self.proc.stdout):
                try: stream.close()
                except OSError as exc: errors.append(str(exc))
        self.selector.close()
        for fd in self.fds: os.close(fd)
        for path in self.fifos: path.unlink(missing_ok=True)
        if self.runtime_state is not None:
            try: self.runtime_state.cleanup()
            except OSError as exc: errors.append('application state cleanup: ' + str(exc))
        return errors


def capture(args):
    from apollo import envelope, _process_metadata, _mission_metadata
    if not math.isfinite(args.timeout) or not 0 < args.timeout <= 86400:
        raise ValueError('timeout must be within (0, 86400] seconds')
    if not 1 <= args.log_limit <= TEXT_LIMIT: raise ValueError('log limit must be 1..2097152 bytes per stream')
    application = getattr(args, 'application', None)
    if not isinstance(application, str) or not application:
        raise ValueError('application identity is required')
    mode = 'application'
    bundle = Bundle(args.output)
    started = time.monotonic()
    e = {'schema_version': 'apollo.session.v1', 'session_id': bundle.session_id,
         'timestamp_started': now(), 'timestamp_finished': None, 'hostname': platform.node(),
         'platform': platform.system(), 'architecture': platform.machine(), 'process': _process_metadata(),
         'inferior': {'pid': None, 'pid_scope': 'process_namespace'},
         'debugger': {'backend': 'gdb-mi2', 'pid': None, 'pid_scope': 'process_namespace', 'version': None, 'argv': []},
         'executable': {'path': args.executable, 'sha256': None}, 'fixture': None,
         'capture_mode': mode, 'application': application,
         'status': 'STARTING', 'lifecycle': ['STARTING'], 'partial': True, 'stop': None,
         'signal': None, 'fault_address': None, 'crashing_thread': None,
         'thread_id_scope': 'gdb', 'stop_frame': None, 'runtime_marker_reached': None,
         'unavailable': {}, 'errors': [], 'reason': None,
         'limits': {'timeout_seconds': args.timeout, 'runtime_bytes_per_stream': args.log_limit,
                    'debugger_transcript_bytes': TEXT_LIMIT, 'mi_record_bytes': TEXT_LIMIT,
                    'stack_frames': 32, 'thread_summary_count': 64, 'core_bytes': 0, 'all_thread_backtraces': False}}
    e.update(_mission_metadata())
    bundle.checkpoint(e)
    transport = None
    executable_fd = None
    cause = None
    previous = {}
    def interrupted(signum, frame):
        raise KeyboardInterrupt('controller received ' + signal.Signals(signum).name)
    try:
        for sig in (signal.SIGINT, signal.SIGTERM):
            previous[sig] = signal.signal(sig, interrupted)
        if platform.system() != 'Linux': raise ValueError('Linux only; Windows DEFERRED / UNVALIDATED')
        if not hasattr(os, 'pidfd_open') or not hasattr(signal, 'pidfd_send_signal'): raise ValueError('pidfd support required')
        exe, executable_fd, digest = admit_application(application, args.executable)
        e['executable'] = {'path': str(exe), 'sha256': digest}
        # GDB and its startup shell open the same pinned inode, even if the
        # approved pathname is replaced after admission.
        debugger_executable = f'/proc/{os.getpid()}/fd/{executable_fd}'
        debugger = shutil.which('gdb', path='/usr/bin:/bin')
        if not debugger: raise ValueError('gdb unavailable')
        argv = [debugger, '--nx', '--nh', '--quiet', '--interpreter=mi2', '-iex', 'set auto-load off',
                '-iex', 'set debuginfod enabled off']
        e['debugger']['argv'] = argv
        transport = Transport(argv, bundle, args.timeout, args.log_limit, None,
                              application=application)
        transport.command('-gdb-version')
        e['debugger']['version'] = transport.version.strip() or None
        for command in ('-gdb-set pagination off', '-gdb-set confirm off', '-gdb-set startup-with-shell on',
                        '-gdb-set disable-randomization off'):
            transport.command(command)
        transport.command('-file-exec-and-symbols ' + json.dumps(debugger_executable))
        # GDB's startup shell redirects the inferior's two streams to separate pipes.
        redirects = '> ' + shlex.quote(str(transport.fifos[0])) + ' 2> ' + shlex.quote(str(transport.fifos[1]))
        transport.command('-exec-arguments ' + redirects)
        transport.command('-exec-run')
        e['status'] = 'RUNNING'; e['lifecycle'].append('RUNNING')
        bundle.checkpoint(e, transport)
        checkpoint_at = time.monotonic() + 1
        while transport.stop_record is None:
            transport.pump()
            if transport.proc.poll() is not None and transport.stop_record is None: raise ProtocolError('debugger exited without stop')
            if time.monotonic() >= checkpoint_at:
                bundle.checkpoint(e, transport); checkpoint_at = time.monotonic() + 1
        e['stop'] = transport.stop_record
        e['signal'] = e['stop'].get('signal-name')
        e['crashing_thread'] = e['stop'].get('thread-id')
        e['stop_frame'] = e['stop'].get('frame')
        if e['stop'].get('reason') == 'signal-received' and e['signal'] in FATAL:
            for field, command, key in (
                ('backtrace', '-stack-list-frames 0 31', 'stack'),
                ('registers', '-data-list-register-values x', 'register-values'),
                ('disassembly', '-data-disassemble -s "$pc" -e "$pc+64" -- 0', 'asm_insns'),
                ('modules', '-file-list-shared-libraries', 'shared-libraries'),
                ('threads', '-thread-info', 'threads'),
                ('fault_address', '-data-evaluate-expression "$_siginfo._sifields._sigfault.si_addr"', 'value')):
                if field == 'fault_address' and e['signal'] != 'SIGSEGV': continue
                result = transport.command(command, optional=True)
                e[field] = result['data'].get(key) if result['class'] == 'done' else None
                if e[field] is None: e['unavailable'][field] = result['data'].get('msg', 'missing MI field')
                elif field == 'threads':
                    e['threads'], e['thread_summary'] = thread_summary(e['threads'], e['crashing_thread'])
        transport.command('-gdb-exit')
        transport.proc.wait(timeout=max(.001, transport.deadline - time.monotonic()))
        if transport.proc.returncode: raise ProtocolError('nonzero debugger exit')
    except KeyboardInterrupt as exc:
        cause = 'INTERRUPTED'; e['reason'] = str(exc) or 'controller interrupted'
    except (TimeoutError, subprocess.TimeoutExpired) as exc:
        cause = 'TIMEOUT'; e['reason'] = str(exc)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        cause = 'DEBUGGER_ERROR'; e['reason'] = str(exc)
    finally:
        # Further control signals cannot interrupt bounded cleanup or final writes.
        for sig in previous: signal.signal(sig, signal.SIG_IGN)
        try:
            if transport:
                e['errors'].extend(transport.close() or [])
                e['debugger']['exit_code'] = transport.proc.returncode
                e['runtime_marker_reached'] = transport.marker_reached
            if transport and not transport.drain_complete:
                e['errors'].append('final output drain did not complete within bound')
            if e['errors'] and cause is None: cause = 'DEBUGGER_ERROR'
            if e.get('fault_address') is not None and not re.fullmatch(r'0x[0-9a-fA-F]+', str(e['fault_address'])):
                e['unavailable']['fault_address'] = 'not a hexadecimal address'; e['fault_address'] = None
            required = ['signal', 'crashing_thread', 'stop_frame', 'backtrace', 'registers', 'disassembly', 'modules', 'threads']
            if e['signal'] == 'SIGSEGV': required.append('fault_address')
            missing = [field for field in required if not e.get(field)]
            if not e['debugger']['version']: missing.append('debugger_version')
            if not e['executable']['sha256']: missing.append('executable_sha256')
            if not transport or not transport.tails['debugger-transcript.txt'].data: missing.append('debugger_transcript')
            e['missing_crash_evidence'] = missing
            for field in required:
                if not e.get(field): e['unavailable'].setdefault(field, 'not supplied / not applicable')
            e['status'] = normalize(e['stop'], missing, cause)
            e['partial'] = e['status'] not in ('CRASH_CAPTURED', 'PROGRAM_EXITED_NORMALLY')
            e['lifecycle'].append(e['status'])
            e['timestamp_finished'] = now(); e['duration_seconds'] = time.monotonic() - started
            bundle.checkpoint(e, transport)
        finally:
            if executable_fd is not None: os.close(executable_fd)
            for sig, handler in previous.items(): signal.signal(sig, handler)
    return envelope('session.capture', {'capture_mode': mode, 'fixture': None, 'application': application}, {'capture': str(bundle.path), **e},
                    status='ok' if not e['partial'] else 'error')


def add_cli(sub):
    group = sub.add_parser('session', help='Linux session capture (explicit admission)')
    commands = group.add_subparsers(dest='action', required=True)
    from apollo_verify import cli
    verifier = commands.add_parser('verify', help='offline read-only bundle verification')
    verifier.add_argument('--session', required=True)
    verifier.add_argument('--output', help='new separate report directory (parent must exist)')
    verifier.set_defaults(func=cli)
    command = commands.add_parser('capture')
    command.add_argument('--executable', required=True)
    command.add_argument('--application', required=True, metavar='IDENTITY')
    command.add_argument('--output', required=True, help='new unique session directory; never reused')
    command.add_argument('--timeout', type=float, default=300)
    command.add_argument('--log-limit', type=int, default=65536, help='retained bytes per runtime stream')
    command.set_defaults(func=capture)
