'''
forensics.py - audit trail for SLI-KUBE.

Every record is one JSON line: UTC timestamp, pid, run id, sequence number, event name, fields,
and a SHA-256 hash chained to the previous record, so edits or deletions in the middle of
the log are detectable (`python forensics.py --verify [logfile]`).

Rule: never write secret values. Calls log argument *shapes* (type, length, path strings),
detections log key names and counts only.

Env: FORENSICS_LOG=<path> (default ./forensics.log), FORENSICS_OFF=1 disables everything.
'''
import datetime
import functools
import getpass
import hashlib
import json
import os
import platform
import socket
import sys
import time
import traceback

LOG_PATH = os.environ.get('FORENSICS_LOG', 'forensics.log')
OFF = bool(os.environ.get('FORENSICS_OFF'))
RUN_ID = '%s-%d' % (datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S'), os.getpid())
GENESIS = '0' * 64

_seq = 0
_last_hash = None


def _tail_hash():
    try:
        with open(LOG_PATH, 'rb') as f:
            last = f.read().strip().split(b'\n')[-1]
        return json.loads(last)['hash']
    except (OSError, ValueError, KeyError, IndexError):
        return GENESIS


def event(name, **fields):
    '''append one hash-chained record to the log; never raises into the caller'''
    global _seq, _last_hash
    if OFF:
        return
    try:
        if _last_hash is None:
            _last_hash = _tail_hash()
        _seq += 1
        rec = {'ts': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'pid': os.getpid(),
               'run': RUN_ID, 'seq': _seq, 'event': name, 'fields': fields, 'prev': _last_hash}
        body = json.dumps(rec, sort_keys=True, default=str)
        rec['hash'] = _last_hash = hashlib.sha256((_last_hash + body).encode()).hexdigest()
        with open(LOG_PATH, 'a') as f:
            f.write(json.dumps(rec, sort_keys=True, default=str) + '\n')
    except Exception:  # forensics must never break the scanner
        pass


def file_sha256(path):
    '''digest of the exact file version analysed; None if unreadable'''
    try:
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, TypeError):
        return None


def run_context():
    try:
        user = getpass.getuser()
    except Exception:
        user = '?'
    return {'user': user, 'host': socket.gethostname(), 'os': platform.platform(),
            'python': sys.version.split()[0], 'argv': sys.argv, 'cwd': os.getcwd()}


def brief(x):
    '''shape of a value, not its content (containers) - strings are paths/keys here, cut at 200 chars'''
    if isinstance(x, (dict, list, tuple, set)):
        return '%s(len=%d)' % (type(x).__name__, len(x))
    if isinstance(x, (str, os.PathLike)):
        return str(x)[:200]
    if x is None or isinstance(x, (bool, int, float)):
        return x
    return type(x).__name__


def audit(fn):
    '''decorator: record call, return/exception and duration of fn'''
    name = '%s.%s' % (fn.__module__, fn.__qualname__)

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        if OFF:
            return fn(*args, **kwargs)
        event('call', fn=name, args=[brief(a) for a in args], kwargs={k: brief(v) for k, v in kwargs.items()})
        t0 = time.perf_counter()
        try:
            result = fn(*args, **kwargs)
        except BaseException as e:
            last = traceback.extract_tb(e.__traceback__)[-1]
            event('exception', fn=name, type=type(e).__name__, msg=str(e)[:200],
                  at='%s:%d' % (os.path.basename(last.filename), last.lineno))
            raise
        event('return', fn=name, result=brief(result), ms=round((time.perf_counter() - t0) * 1000, 2))
        return result
    return wrapper


def verify(path=LOG_PATH):
    '''recompute the hash chain; returns (ok, records_checked, first_bad_line)'''
    prev, n = GENESIS, 0
    with open(path) as f:
        for n, line in enumerate(f, 1):
            rec = json.loads(line)
            claimed = rec.pop('hash')
            body = json.dumps(rec, sort_keys=True, default=str)
            if rec['prev'] != prev and n > 1 or hashlib.sha256((rec['prev'] + body).encode()).hexdigest() != claimed:
                return False, n, n
            prev = claimed
    return True, n, None


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--verify':
        ok, n, bad = verify(*sys.argv[2:3])
        print('chain OK, %d records' % n if ok else 'TAMPERED: chain breaks at line %d' % bad)
        sys.exit(0 if ok else 1)
    print(__doc__)
