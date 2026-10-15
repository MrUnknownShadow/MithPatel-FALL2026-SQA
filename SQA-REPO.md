# SQA Report - MithPatel-FALL2026-SQA

Project: SLI-KUBE (KubeSec fork), a Python static analyzer for security smells in Kubernetes manifests.
Team: MithPatel (solo; see [README.md](README.md)).

## 1. What we did

| # | Activity | Result |
|---|---|---|
| 1 | Unpack `slikube.zip` | Source in repo root; 5 modules (`parser.py`, `scanner.py`, `graphtaint.py`, `constants.py`, `main.py`) plus `TEST_*.py` and `TEST_ARTIFACTS/` |
| 4.a | Fuzzing | [`fuzz.py`](fuzz.py) fuzzes 10 methods, found 9 distinct defects (20 unique crash/oracle signatures in one run); a 10th came from the existing integration test |
| 4.b | Forensics | [`forensics.py`](forensics.py) audit trail wired into 10 methods |
| 4.c | CI | [`ci.yml`](.github/workflows/ci.yml): lint, unit tests, forensics check, fuzzing |

Baseline before our changes: `TEST_PARSING` 23/23 pass. `TEST_SCANNING` 50/115 pass locally (65 errors: the `yq` binary is missing, which `parser.show_line_for_paths` shells out to). `TEST_GRAPH` fails 27/27 because it reads files from `/Users/arahman/K8S_REPOS/...` (the original author's machine). `TEST_INTEGRATION` could not import `main.py` (see bug 9). The original workflow ran only `TEST_PARSING`.

## 2. Fuzzing (4.a)

`fuzz.py` uses only the standard library plus the project's own `ruamel.yaml`. For each of 10 methods it generates random inputs and checks two things:

- **CRASH**: an unexpected exception, a stack overflow, or a call longer than 5 s.
- **ORACLE**: the call returned, but a small reference implementation inside `fuzz.py` disagrees (a logic bug, not a crash).

Input generators: random nested dicts/lists with awkward keys (`None`, `1.5`, `True`, `0`, `''`, names such as `privileged`), very deep trees (600-1500 levels), YAML text mutated from the 76 files in `TEST_ARTIFACTS/` (line delete/duplicate/truncate, tabs, aliases, raw bytes), and pathological text (`[[[[...`, `&a [*a]`, binary noise). Findings are de-duplicated by (method, exception type, innermost project line). The report keeps the smallest input that triggered each one. The seed is printed so any run can be replayed (`--seed N`).

Fuzzed methods:

| Method | Generator | Oracle |
|---|---|---|
| `parser.keyMiner` | tree + value | returned path must end in a value of the same type |
| `parser.getKeyRecursively` | tree | every dict key must be returned, at its real depth |
| `parser.getValuesRecursively` | tree | leaves must equal an iterative traversal |
| `parser.getValsFromKey` | tree + key | values must equal an iterative traversal |
| `parser.getSingleDict4MultiDocs` | list of documents | no key may be lost |
| `parser.find_json_path_keys` | tree | `key_jsonpath_mapping` values must all be lists |
| `parser.count_initial_comment_line` | YAML bytes in a temp file | non-negative `int` |
| `scanner.scanForSecrets` | tree with a buried `password` | the secret must be reported |
| `parser.loadMultiYAML` | YAML bytes in a temp file | returns a `list` |
| `parser.checkIfValidK8SYaml` | YAML bytes in a temp file | returns a `bool` |

Run `python fuzz.py --iterations 300 --seed 20261015`: 20 unique findings in about 17 s ([evidence/fuzz_output/fuzz_report.md](evidence/fuzz_output/fuzz_report.md)). They reduce to these defects:

| # | Defect | Where | Smallest reproducer | Impact |
|---|---|---|---|---|
| 1 | `TypeError` on non-string keys. `regex_key_dot.match(key)` only guards `int`, not `None`, floats or `CommentedKeyMap` | `parser.find_json_path_keys`, so also `loadMultiYAML`, `checkIfValidK8SYaml` | file `null: x` | The whole scan aborts on any manifest with a `null:`/`~:` or float key |
| 2 | `IndexError` on an empty list document (`dic = dic[0]`) | `parser.getSingleDict4MultiDocs` | file `[]` | Scan aborts on a YAML file whose root is `[]` |
| 3 | `TypeError`: `k_ + '.YAML.DOC.' + n` when a non-string key repeats across documents | `parser.getSingleDict4MultiDocs` | file `1: a` / `---` / `1: b` | Scan aborts on multi-document YAML |
| 4 | Unbounded recursion: `RecursionError` on deep or self-referencing YAML | `keyMiner`, `getValuesRecursively`, `find_json_path_keys`, `loadMultiYAML` (not caught, since it is not a `YAMLError`) | `&a [*a]`, or 1000 nested `- ` | A crafted manifest can crash the scanner (DoS in a CI scanner) |
| 5 | `UnicodeDecodeError` is not handled | `parser.count_initial_comment_line` (also `show_line_for_paths`) | bytes `\x00\xff\xfe` | Non-UTF-8 file aborts the scan, although `loadMultiYAML` itself tolerates it |
| 6 | Keys whose value is a list of scalars are never returned; later siblings get a wrong depth because `depth_` is never restored | `parser.getKeyRecursively` | `{'args': ['--password=x']}` returns no keys | **False negatives**: every scanner that builds its key list with this function (`scanForSecrets`, `scanDockerSock`, ...) is blind to keys such as `args`, `command` or `password: [..]` |
| 7 | Lists inside lists, and a root-level list, are not searched | `parser.getValsFromKey` | `{'a': [[{'kind': 'Pod'}]]}`, key `kind` returns `[]` | Missed values (Ansible-style root lists) |
| 8 | `==` matches `True == 1` and `False == 0` | `parser.keyMiner` | `{'spec': {'replicas': 1, 'privileged': True}}`, search `True` returns `[..., 'replicas', 1]` | `scanForOverPrivileges` checks the returned path for `securityContext`, so it can **miss a privileged container** |
| 9 | `key_jsonpath_mapping[key]` becomes a `str` instead of a `list` when a key repeats, so earlier paths are lost | `parser.find_json_path_keys` | any manifest with two `name:` keys | Only the last occurrence gets a line number in the SARIF output |

A tenth defect came from the existing integration test, not from the fuzzer:

| # | Defect | Fix applied |
|---|---|---|
| 10 | `main.py` never imports `typer` or `Path`, and ends with `main()` instead of `typer.run(main)`, so the CLI and the Docker entrypoint cannot start (`NameError: name 'typer' is not defined`) | Added the two imports and `typer.run(main)` |

Not fixed: defects 1-9 are reported, not patched, so that the reproducers keep working and the CI fuzz job keeps showing them. Defect 10 was fixed because nothing could run without it. `scanner.scanForSecrets` produced no findings in our runs.

## 3. Forensics (4.b)

[`forensics.py`](forensics.py) writes an append-only JSON-lines audit log (`forensics.log`). Each record has a UTC timestamp, pid, run id, sequence number, event name, fields and a SHA-256 **hash chained to the previous record**. `python forensics.py --verify` recomputes the chain, so an edited or deleted record is detected (we tested: changing one field of line 50 gives `TAMPERED: chain breaks at line 50`).

Design rules: logs shape, not content (a `dict` is logged as `dict(len=12)`), so scanned secrets never reach the log; detections record the key name and counts only. Logging never raises into the scanner. `FORENSICS_OFF=1` disables it (the fuzzer does this).

Ten modified methods (each gets `@forensics.audit`: call, return/exception, duration; plus the explicit events listed):

| # | Method | Extra forensic events |
|---|---|---|
| 1 | `parser.loadMultiYAML` | `yaml_load` with SHA-256 of the exact file analysed |
| 2 | `parser.checkParseError` | `yaml_parse_error` with exception type and message |
| 3 | `parser.checkIfValidK8SYaml` | call/return only (verdict per file) |
| 4 | `parser.getSingleDict4MultiDocs` | `multidoc_key_collision` |
| 5 | `scanner.runScanner` | `scan_start` (user, host, OS, python, argv, cwd), `file_scanned` (path, SHA-256, helm/k8s flags), `scan_end` (counts) |
| 6 | `scanner.scanSingleManifest` | call/return/exception |
| 7 | `scanner.scanForSecrets` | `hardcoded_secret_found` (key name, counts, never values) |
| 8 | `scanner.scanForOverPrivileges` | `privileged_container_found` with key path |
| 9 | `scanner.scanDockerSock` | `docker_sock_mount_found` with key path |
| 10 | `scanner.scanForHTTP` | `insecure_http_found` with key |

Evidence: [evidence/forensics_sample.log](evidence/forensics_sample.log) (191 records from `TEST_PARSING`), [evidence/forensics_verify.txt](evidence/forensics_verify.txt). Running `TEST_SCANNING` locally produced 2006 valid records, including 40 `hardcoded_secret_found`, 60 `exception` (the missing `yq`) and 2 `docker_sock_mount_found`. The decorated functions return exactly what they did before: `TEST_PARSING` still passes 23/23 and `TEST_SCANNING` has the same 65 environment errors as the baseline.

## 4. Continuous integration (4.c)

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) replaces the original `python.build.yml` (which ran one test file, with old action versions and un-pinned `pip install`s). It runs on push to `main`/`master`, on every pull request, and on demand.

| Job | Steps |
|---|---|
| `test` | install `requirements-ci.txt` (the original `requirements.txt` is UTF-16, Windows-only and conda-pinned); `flake8` for syntax errors and undefined names; `TEST_PARSING` (must pass); `TEST_SCANNING` (informational, `continue-on-error`); `forensics.py --verify`; upload `forensics.log` |
| `fuzz` | `python fuzz.py --iterations 300 --seed <run number>`; write findings to the job summary; upload `fuzz_output/` |

Choices: the fuzz job reports but does not fail, because the 9 known defects would turn every build red; `--strict` makes it a gate once they are fixed. The seed is the run number, so each build explores new inputs and any failure is replayable. `TEST_GRAPH` is not run: it needs the original author's local repositories.

Screenshots of the first green run (Actions tab, the fuzz job summary, the artifacts list) go in `evidence/screenshots/`. Add them after the first push.

## 5. Lessons learned

- **Fuzzing finds what example-based tests never try.** The 23 passing parsing tests all use real, well-formed manifests; a YAML file containing `null:` or `[]` kills the scanner in one line of input. Small, boring generators (awkward keys, empty containers, deep nesting) found most defects within seconds.
- **Oracles matter as much as crashes.** The most serious findings (defects 6, 7, 8) do not crash; they silently make the tool report fewer issues. A security scanner that fails open is worse than one that crashes, and only a reference implementation exposes this.
- **Fuzzing needs determinism.** Printing the seed and keeping the smallest reproducer per signature turned about 470 failing calls into 9 readable defects.
- **Forensic logs are a security surface themselves.** The first instinct is to log arguments; for a secret scanner that would copy secrets into the log. Logging shapes and key names, and hash-chaining the records, gave an audit trail that is safe to share and tamper-evident.
- **Decorators keep forensics cheap and reviewable.** One `@forensics.audit` line changes no logic, so the existing tests are the regression check for the change; explicit events are used only where the method knows something worth recording.
- **CI shows what "works on my machine" hides.** `TEST_GRAPH` depends on `/Users/arahman/...`, `TEST_SCANNING` on a `yq` binary, `main.py` was un-importable, and `requirements.txt` cannot be installed on Linux. None of this was visible while only `TEST_PARSING` ran.
- **Limits of our work:** the fuzzer covers 10 of about 60 methods; the file-system and `yq`-dependent scanners (`scanForMissingSecurityContext`, etc.) were not fuzzed; defects 1-9 are reported but not fixed; the CI result on GitHub has to be confirmed from the Actions tab.

## 6. Reproduce

```bash
pip install -r requirements-ci.txt          # also install `yq` (mikefarah) for TEST_SCANNING
python fuzz.py --iterations 300 --seed 20261015
python -m unittest TEST_PARSING && python forensics.py --verify
```
