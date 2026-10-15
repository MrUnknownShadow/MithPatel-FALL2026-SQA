'''
fuzz.py - stdlib-only fuzzer for SLI-KUBE.

Fuzzes 10 methods in parser.py and scanner.py with random trees, random YAML text
and mutated YAML files taken from TEST_ARTIFACTS/. Two kinds of findings:
  CRASH   - the method raised an unexpected exception (or hung / blew the stack)
  ORACLE  - the method returned, but broke a property a reference implementation holds

Usage:  python fuzz.py [--iterations 200] [--seed N] [--out fuzz_output] [--strict]
Exit code is 0 unless --strict is given and something was found.
'''
import argparse
import collections
import contextlib
import glob
import io
import json
import os
import random
import signal
import string
import sys
import tempfile
import time
import traceback

os.environ.setdefault('FORENSICS_OFF', '1')  # keep fuzz noise out of the forensics log

import ruamel.yaml

import parser
import scanner

HERE = os.path.dirname(os.path.abspath(__file__))
TIMEOUT_SEC = 5

# ---------------------------------------------------------------- generators

WORDS = ['kind', 'apiVersion', 'privileged', 'securityContext', 'containers', 'password',
         'username', 'secret', 'token', 'Secret', 'ConfigMap', 'http://a.b', 'hostNetwork',
         'app.kubernetes.io/name', 'a.b', 'name', 'spec', '', ' ', 'x', 'null', 'true', '[0]']


def scalar(r):
    return r.choice([
        lambda: r.choice(WORDS),
        lambda: ''.join(r.choices(string.printable, k=r.randint(0, 12))),
        lambda: r.randint(-5, 5),
        lambda: r.random() * 10,
        lambda: None,
        lambda: r.random() < .5,
        lambda: '‮☃\x00',
    ])()


def key(r):
    if r.random() < .8:
        return r.choice(WORDS)
    return r.choice([0, 1, 2, 1.5, None, True, False])


def tree(r, depth=0):
    c = r.random()
    if depth >= 4 or c < .3:
        return scalar(r)
    if c < .7:
        return {key(r): tree(r, depth + 1) for _ in range(r.randint(0, 4))}
    return [tree(r, depth + 1) for _ in range(r.randint(0, 4))]


def deep(r):
    t = 'leaf'
    for _ in range(r.randint(600, 1500)):
        t = {'a': t} if r.random() < .5 else [t]
    return t


def any_tree(r):
    return deep(r) if r.random() < .03 else tree(r)


def dict_tree(r):
    t = tree(r)
    return t if isinstance(t, dict) else {key(r): t}


CORPUS = []
for _p in sorted(glob.glob(os.path.join(HERE, 'TEST_ARTIFACTS', '*.y*ml'))):
    if os.path.getsize(_p) < 30000:
        with open(_p, 'rb') as _f:
            CORPUS.append(_f.read())


def mutate(r, data):
    lines = data.split(b'\n')
    for _ in range(r.randint(1, 4)):
        op, i = r.randint(0, 5), r.randrange(len(lines))
        if op == 0:
            del lines[i]
        elif op == 1:
            lines.insert(i, lines[i])
        elif op == 2:
            lines[i] = b'\t' + lines[i]
        elif op == 3:
            lines[i] = lines[i][:r.randint(0, len(lines[i]))]
        elif op == 4:
            lines.insert(i, r.choice([b'---', b'? [a, b]', b'1.5: x', b'null: x', b'- ', b'&a x', b'*a', b'!!python/object:os.system x']))
        else:
            lines[i] = bytes(r.randrange(256) for _ in range(r.randint(1, 6)))
    return b'\n'.join(lines)


def yaml_bytes(r):
    c = r.random()
    if c < .45 and CORPUS:
        return mutate(r, r.choice(CORPUS))
    if c < .85:
        buf = io.StringIO()
        try:
            ruamel.yaml.YAML().dump(tree(r) if r.random() < .5 else dict_tree(r), buf)
        except Exception:
            buf.write('a: b\n')
        return buf.getvalue().encode('utf-8')
    if c < .95:
        return r.choice([b'[' * 3000, b'{a: ' * 2000, b'---\n' * 500, b'&a [*a]', b'', b'\x00\xff\xfe',
                         b'- ' * 800 + b'x', b'a: b\n---\n1.5: x\n---\n1.5: y\n'])
    return bytes(r.randrange(256) for _ in range(r.randint(0, 200)))


# ---------------------------------------------------------------- references (iterative)

def ref_leaves(t):
    out, stack = [], [t]
    while stack:
        n = stack.pop()
        if isinstance(n, dict):
            stack.extend(n.values())
        elif isinstance(n, list):
            stack.extend(n)
        else:
            out.append(n)
    return out


def ref_keys(t):
    '''(key, true_depth) for every dict key reachable through dicts and lists'''
    out, stack = [], [(t, 0)]
    while stack:
        n, d = stack.pop()
        if isinstance(n, dict):
            for k, v in n.items():
                out.append((k, d))
                stack.append((v, d + 1))
        elif isinstance(n, list):
            stack.extend((x, d) for x in n)
    return out


def ref_vals_from_key(t, target):
    out, stack = [], [t]
    while stack:
        n = stack.pop()
        if isinstance(n, dict):
            for k, v in n.items():
                if k == target:
                    out.append(v)
                else:
                    stack.append(v)
        elif isinstance(n, list):
            stack.extend(n)
    return out


def to_file(data):
    fd, path = tempfile.mkstemp(suffix='.yaml', dir=TMP)
    with os.fdopen(fd, 'wb') as f:
        f.write(data)
    return path


# ---------------------------------------------------------------- targets
# each: (name, gen(r) -> case, call(case) -> result, check(case, result) -> None | (oracle_name, msg))

def check_keyMiner(c, res):
    t, v = c
    if res is not None and type(res[-1]) is not type(v):
        return ('type-confusion', 'searched %r (%s) but path ends in %r (%s): True/1 and False/0 compare equal'
                % (v, type(v).__name__, res[-1], type(res[-1]).__name__))


def gen_keyMiner(r):
    t = any_tree(r)
    leaves = ref_leaves(t)
    v = r.choice(leaves) if leaves and r.random() < .8 else r.choice([True, False, 'privileged'])
    return (t, v)


def call_getKeyRecursively(t):
    holder = []
    parser.getKeyRecursively(t, holder)
    return holder


def check_getKeyRecursively(t, res):
    got = {k for k, _ in res}
    missing = [k for k, _ in ref_keys(t) if k not in got]
    if missing:
        return ('keys-dropped', 'keys %r nested in the tree are never returned (dict keys whose value is a '
                'list of scalars are skipped)' % (missing[:3],))
    true_depths = collections.defaultdict(set)
    for k, d in ref_keys(t):
        true_depths[k].add(d)
    for k, d in res:
        if d not in true_depths[k]:
            return ('depth-leak', 'key %r reported at depth %d, real depths %s: depth_ is incremented but '
                    'never restored for later siblings' % (k, d, sorted(true_depths[k])))


def check_getValuesRecursively(t, res):
    if collections.Counter(map(repr, res)) != collections.Counter(map(repr, ref_leaves(t))):
        return ('values-mismatch', 'leaf values differ from reference traversal')


def gen_getValsFromKey(r):
    t = any_tree(r)
    ks = [k for k, _ in ref_keys(t)]
    return (t, r.choice(ks) if ks and r.random() < .8 else r.choice(WORDS))


def call_getValsFromKey(c):
    holder = []
    parser.getValsFromKey(c[0], c[1], holder)
    return holder


def check_getValsFromKey(c, res):
    want = ref_vals_from_key(*c)
    if collections.Counter(map(repr, res)) != collections.Counter(map(repr, want)):
        return ('lists-not-traversed', 'expected %d value(s) for key %r, got %d (lists nested in lists and a '
                'list at the document root are not searched)' % (len(want), c[1], len(res)))


def gen_multidocs(r):
    def doc():
        c = r.random()
        if c < .6:
            return dict_tree(r)
        return r.choice([None, [], [dict_tree(r)], ['x'], 'scalar', 5, {}])
    return [doc() for _ in range(r.randint(0, 4))]


def check_multidocs(docs, res):
    if not isinstance(res, dict):
        return ('not-a-dict', 'returned %s' % type(res).__name__)
    want = 0
    for d in docs:
        d = d[0] if isinstance(d, list) and d else d
        if isinstance(d, dict):
            want += len(d)
    if len(res) != want:
        return ('keys-lost', 'merged dict has %d keys, documents hold %d' % (len(res), want))


def call_find_json_path_keys(t):
    parser.key_jsonpath_mapping.clear()
    paths = parser.find_json_path_keys(t)
    return paths


def check_find_json_path_keys(t, res):
    bad = [k for k, v in parser.key_jsonpath_mapping.items() if not isinstance(v, list)]
    if bad:
        return ('mapping-type-inconsistent', 'key_jsonpath_mapping[%r] is a str, not a list, once the key '
                'repeats; earlier paths are overwritten and their line numbers lost' % (bad[0],))


def gen_commentfile(r):
    return yaml_bytes(r)


def call_count_initial_comment_line(data):
    return parser.count_initial_comment_line(to_file(data))


def check_count_initial_comment_line(data, res):
    if not isinstance(res, int) or res < 0:
        return ('bad-count', 'returned %r' % (res,))


def gen_secret_tree(r):
    t = dict_tree(r)
    if any(k == 'password' for k, _ in ref_keys(t)):
        t = {}
    holder = t
    for _ in range(r.randint(0, 3)):  # bury the secret under dicts / lists of dicts
        child, k = {}, r.choice(['data', 'spec', 'stringData', 'x'])
        holder[k] = child if r.random() < .5 else [child]
        holder = child
    holder['password'] = 'Tr0ub4dor-secret'
    return t


def call_scanForSecrets(t):
    return scanner.scanForSecrets(t)


def check_scanForSecrets(t, res):
    if not isinstance(res, dict):
        return ('not-a-dict', 'returned %s' % type(res).__name__)
    if 'password' not in res:
        return ('secret-missed', "hard-coded 'password: Tr0ub4dor-secret' not reported")


def call_loadMultiYAML(data):
    return parser.loadMultiYAML(to_file(data))


def call_checkIfValidK8SYaml(data):
    return parser.checkIfValidK8SYaml(to_file(data))


TARGETS = [
    ('parser.keyMiner', gen_keyMiner, lambda c: parser.keyMiner(*c), check_keyMiner),
    ('parser.getKeyRecursively', any_tree, call_getKeyRecursively, check_getKeyRecursively),
    ('parser.getValuesRecursively', any_tree, lambda t: list(parser.getValuesRecursively(t)), check_getValuesRecursively),
    ('parser.getValsFromKey', gen_getValsFromKey, call_getValsFromKey, check_getValsFromKey),
    ('parser.getSingleDict4MultiDocs', gen_multidocs, parser.getSingleDict4MultiDocs, check_multidocs),
    ('parser.find_json_path_keys', any_tree, call_find_json_path_keys, check_find_json_path_keys),
    ('parser.count_initial_comment_line', gen_commentfile, call_count_initial_comment_line, check_count_initial_comment_line),
    ('scanner.scanForSecrets', gen_secret_tree, call_scanForSecrets, check_scanForSecrets),
    ('parser.loadMultiYAML', yaml_bytes, call_loadMultiYAML, lambda c, res: None if isinstance(res, list) else ('not-a-list', repr(res))),
    ('parser.checkIfValidK8SYaml', yaml_bytes, call_checkIfValidK8SYaml, lambda c, res: None if isinstance(res, bool) else ('not-a-bool', repr(res))),
]

# ---------------------------------------------------------------- harness


class Timeout(Exception):
    pass


@contextlib.contextmanager
def time_limit(sec):
    if not hasattr(signal, 'SIGALRM'):
        yield
        return

    def _raise(*_):
        raise Timeout('no result after %ds' % sec)
    old = signal.signal(signal.SIGALRM, _raise)
    signal.alarm(sec)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old)


def where(tb):
    '''innermost frame inside the project (not fuzz.py), else innermost frame'''
    frames = traceback.extract_tb(tb)
    mine = [f for f in frames if os.path.dirname(os.path.abspath(f.filename)) == HERE
            and os.path.basename(f.filename) != 'fuzz.py']
    f = (mine or frames)[-1]
    return '%s:%d in %s' % (os.path.basename(f.filename), f.lineno, f.name)


def short(case):
    try:
        s = repr(case)
    except RecursionError:  # the input itself is the deep structure
        return '<nested too deep to print>'
    return s if len(s) <= 300 else s[:300] + '...<%d chars>' % len(s)


def record(findings, target, kind, ident, msg, case, i):
    f = findings.setdefault((target, kind, ident), {
        'target': target, 'kind': kind, 'id': ident, 'message': msg, 'count': 0,
        'first_iteration': i, 'smallest_input': None})
    f['count'] += 1
    s = short(case)
    if f['smallest_input'] is None or len(s) < len(f['smallest_input']):
        f['smallest_input'], f['message'] = s, msg


def fuzz(iterations, seed, out_dir):
    r = random.Random(seed)
    findings, calls = {}, collections.Counter()
    for name, gen, call, check in TARGETS:
        for i in range(iterations):
            case = gen(r)
            calls[name] += 1
            try:
                with time_limit(TIMEOUT_SEC), contextlib.redirect_stdout(io.StringIO()):
                    res = call(case)
            except (KeyboardInterrupt, SystemExit):
                raise
            except BaseException as e:  # RecursionError, Timeout, anything
                kind = 'HANG' if isinstance(e, Timeout) else 'CRASH'
                msg = '%s: %s' % (type(e).__name__, str(e)[:150])
                record(findings, name, kind, '%s @ %s' % (type(e).__name__, where(e.__traceback__)), msg, case, i)
                continue
            try:
                verdict = check(case, res)
            except RecursionError:  # result too deep for the oracle itself to compare; the CRASH path covers depth
                continue
            if verdict:
                record(findings, name, 'ORACLE', verdict[0], verdict[1], case, i)
    return findings, calls


def report(findings, calls, seed, iterations, out_dir):
    rows = sorted(findings.values(), key=lambda f: (f['target'], f['kind'], f['id']))
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, 'fuzz_report.json'), 'w') as f:
        json.dump({'seed': seed, 'iterations_per_target': iterations, 'targets': len(calls),
                   'unique_findings': len(rows), 'findings': rows}, f, indent=2, default=str)
    lines = ['# Fuzz report', '', 'seed=%s, %d iterations x %d targets, %d unique finding(s)' %
             (seed, iterations, len(calls), len(rows)), '',
             '| Target | Kind | Finding | Hits |', '|---|---|---|---|']
    for f in rows:
        lines.append('| `%s` | %s | %s | %d |' % (f['target'], f['kind'], f['id'].replace('|', '/'), f['count']))
    lines += ['']
    for f in rows:
        lines += ['### `%s` - %s: %s' % (f['target'], f['kind'], f['id']), f['message'],
                  '```', 'smallest input: ' + f['smallest_input'], '```', '']
    md = '\n'.join(lines)
    with open(os.path.join(out_dir, 'fuzz_report.md'), 'w') as f:
        f.write(md)
    print(md)
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as f:
            f.write(md + '\n')
    return len(rows)


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[1])
    ap.add_argument('--iterations', type=int, default=200)
    ap.add_argument('--seed', type=int, default=None)
    ap.add_argument('--out', default='fuzz_output')
    ap.add_argument('--strict', action='store_true', help='exit 1 if anything was found')
    a = ap.parse_args()
    seed = a.seed if a.seed is not None else random.randrange(2 ** 31)
    sys.setrecursionlimit(1000)
    print('fuzzing %d methods x %d iterations, seed=%d' % (len(TARGETS), a.iterations, seed))
    t0 = time.time()
    with tempfile.TemporaryDirectory() as TMP:
        findings, calls = fuzz(a.iterations, seed, a.out)
    n = report(findings, calls, seed, a.iterations, a.out)
    print('\n%d unique finding(s) in %.1fs' % (n, time.time() - t0))
    sys.exit(1 if (a.strict and n) else 0)
