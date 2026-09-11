"""Bounded Linux GDB/MI support for Apollo session and crash capture."""
import datetime
import hashlib
import json
import math
import os
from pathlib import Path

from apollo_policy import is_capture_forbidden_path
import platform
import re
import selectors
import shutil
import signal
import subprocess
import time

ROOT = Path(__file__).absolute().parent
LIMIT = 2 * 1024 * 1024
FATAL = {'SIGSEGV', 'SIGABRT', 'SIGBUS', 'SIGILL', 'SIGFPE', 'SIGSYS', 'SIGTRAP'}


class ProtocolError(ValueError):
    pass


class MIParser:
    """Parse the MI result grammar, preserving repeated named list entries."""
    def __init__(self, text):
        self.text, self.i = text, 0
        self.depth = 0

    def value(self):
        s = self.text
        if self.i >= len(s):
            raise ProtocolError('missing MI value')
        c = s[self.i]
        if c == '"':
            start = self.i
            self.i += 1
            while self.i < len(s):
                if s[self.i] == '\\':
                    self.i += 2
                elif s[self.i] == '"':
                    self.i += 1
                    # GDB C strings also permit octal escapes.
                    raw = s[start:self.i]
                    raw = re.sub(r'\\([0-7]{1,3})', lambda m: '\\u%04x' % int(m[1], 8), raw)
                    try:
                        return json.loads(raw)
                    except ValueError as exc:
                        raise ProtocolError('invalid MI string') from exc
                else:
                    self.i += 1
            raise ProtocolError('unterminated MI string')
        if c in '[{':
            self.depth += 1
            if self.depth > 32: raise ProtocolError('MI nesting limit exceeded')
            self.i += 1
            end = ']' if c == '[' else '}'
            result = [] if c == '[' else {}
            while self.i < len(s) and s[self.i] != end:
                named = s[self.i] not in '"[{'
                if named:
                    key, val = self.pair()
                    if isinstance(result, dict):
                        if key in result: raise ProtocolError('duplicate MI key')
                        result[key] = val
                    else: result.append({key: val})
                else:
                    if isinstance(result, dict): raise ProtocolError('unnamed tuple value')
                    result.append(self.value())
                if self.i < len(s) and s[self.i] == ',': self.i += 1
                elif self.i < len(s) and s[self.i] != end: raise ProtocolError('MI separator')
            if self.i >= len(s): raise ProtocolError('unclosed MI container')
            self.i += 1
            self.depth -= 1
            return result
        raise ProtocolError('invalid MI value')

    def pair(self):
        match = re.match(r'([A-Za-z_][A-Za-z0-9_-]*)=', self.text[self.i:])
        if not match: raise ProtocolError('invalid MI result')
        self.i += len(match[0])
        return match[1], self.value()

    def results(self):
        out = {}
        while self.i < len(self.text):
            key, value = self.pair()
            if key in out: raise ProtocolError('duplicate MI key')
            out[key] = value
            if self.i == len(self.text): break
            if self.text[self.i] != ',': raise ProtocolError('trailing MI data')
            self.i += 1
        return out


def parse_record(line):
    match = re.fullmatch(r'(\d*)([\^*=+])([a-zA-Z-]+)(?:,(.*))?', line)
    if not match: raise ProtocolError('invalid MI record')
    return {'token': match[1], 'kind': match[2], 'class': match[3],
            'data': MIParser(match[4] or '').results()}


def normalize(stop, missing, *, timeout=False, error=False):
    if timeout: return 'TIMEOUT'
    if error: return 'DEBUGGER_ERROR'
    reason = (stop or {}).get('reason')
    if reason in ('exited-normally', 'exited'): return 'PROGRAM_EXITED_NORMALLY'
    if reason == 'exited-signalled' or (reason == 'signal-received' and stop.get('signal-name') in FATAL):
        return 'CAPTURE_INCOMPLETE' if missing else 'CRASH_CAPTURED'
    return 'CAPTURE_INCOMPLETE'


def safe_local(value):
    # Walk components without resolving a symlink into a forbidden tree.
    path = Path(os.path.abspath(value))
    if is_capture_forbidden_path(path):
        raise ValueError('forbidden capture path')
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        if current.is_symlink(): raise ValueError('capture paths cannot contain symlinks')
    return path


def digest_executable(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        total = 0
        while chunk := stream.read(65536):
            total += len(chunk)
            if total > 16 * 1024 * 1024: raise ValueError('executable exceeds 16 MiB')
            digest.update(chunk)
    return digest.hexdigest()


def child_limits():
    import resource
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (LIMIT, LIMIT))


class Session:
    def __init__(self, argv, cwd, timeout):
        if not hasattr(os, 'pidfd_open') or not hasattr(signal, 'pidfd_send_signal'):
            raise ValueError('Linux pidfd cleanup support is required')
        self.inferior_fds = []
        self.deadline = time.monotonic() + timeout
        self.raw = bytearray()
        self.runtime = bytearray()
        self.pending = b''
        self.records = []
        self.console = []
        self.token = 0
        self.commands = []
        self.truncated = False
        self.selector = selectors.DefaultSelector()
        import pty
        self.master, self.slave = pty.openpty()
        self.tty = os.ttyname(self.slave)
        self.proc = None
        try:
            self.proc = subprocess.Popen(argv, cwd=cwd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, start_new_session=True, preexec_fn=child_limits,
                env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'HOME': str(cwd), 'DEBUGINFOD_URLS': ''})
            self.selector.register(self.proc.stdout, selectors.EVENT_READ, 'mi')
            self.selector.register(self.master, selectors.EVENT_READ, 'runtime')
        except BaseException:
            self.close()
            raise

    def pump(self):
        previous_records = len(self.records)
        remaining = self.deadline - time.monotonic()
        if remaining <= 0: raise TimeoutError('capture deadline exceeded')
        for key, _ in self.selector.select(min(remaining, .1)):
            try: data = os.read(key.fd, 8192)
            except OSError: data = b''
            if not data:
                self.selector.unregister(key.fileobj)
                continue
            target = self.raw if key.data == 'mi' else self.runtime
            room = LIMIT - len(self.raw) - len(self.runtime)
            target.extend(data[:max(0, room)])
            if len(data) > room: raise ProtocolError('capture output limit exceeded')
            if key.data != 'mi': continue
            self.pending += data
            while b'\n' in self.pending:
                line, self.pending = self.pending.split(b'\n', 1)
                line = line.decode('utf-8', 'replace').rstrip('\r')
                if not line or line.strip() == '(gdb)': continue
                if line[0] in '~@&':
                    parser = MIParser(line[1:]); value = parser.value()
                    if parser.i != len(parser.text): raise ProtocolError('trailing stream data')
                    self.console.append(value)
                else:
                    record = parse_record(line)
                    self.records.append(record)
                    if record['kind'] == '=' and record['class'] == 'thread-group-started':
                        if self.inferior_fds: raise ProtocolError('unexpected additional inferior')
                        pid = record['data'].get('pid', '')
                        if not str(pid).isdigit(): raise ProtocolError('invalid inferior PID')
                        try: self.inferior_fds.append(os.pidfd_open(int(pid)))
                        except ProcessLookupError: pass
        if len(self.records) == previous_records and self.proc.poll() is not None and not any(k.data == 'mi' for k in self.selector.get_map().values()):
            raise ProtocolError('debugger closed protocol stream')

    def command(self, command, optional=False):
        self.token += 1
        token = str(self.token)
        self.commands.append(token + command)
        self.proc.stdin.write((token + command + '\n').encode()); self.proc.stdin.flush()
        while True:
            for record in self.records:
                if record['kind'] == '^' and record['token'] == token:
                    if record['class'] == 'error' and not optional:
                        raise ProtocolError(record['data'].get('msg', 'MI command failed'))
                    return record
            self.pump()

    def stop(self):
        while True:
            for record in self.records:
                if record['kind'] == '*' and record['class'] == 'stopped': return record['data']
            self.pump()

    def close(self):
        for fd in self.inferior_fds:
            try: signal.pidfd_send_signal(fd, signal.SIGKILL)
            except ProcessLookupError: pass
            finally: os.close(fd)
        self.inferior_fds.clear()
        if self.proc is not None:
            # Only the fresh debugger session/process group created by this capture.
            try: os.killpg(self.proc.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            self.proc.wait()
            # Drain final output after shutdown without an unbounded wait/read.
            for fd, target in ((self.proc.stdout.fileno(), self.raw), (self.master, self.runtime)):
                os.set_blocking(fd, False)
                while True:
                    try: chunk = os.read(fd, 8192)
                    except (BlockingIOError, OSError): break
                    if not chunk: break
                    room = LIMIT - len(self.raw) - len(self.runtime)
                    target.extend(chunk[:max(0, room)])
                    if len(chunk) > room:
                        self.truncated = True
                        break
            self.proc.stdin.close(); self.proc.stdout.close()
        self.selector.close()
        os.close(self.master); os.close(self.slave)
