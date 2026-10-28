# review-gate

Deterministic checks that keep agent-team review honest. Git work runs in
temporary detached worktrees, one per variant; the caller's tree, index, and
branches stay as they are. Python 3.11+, standard library only.

## Install the trusted checker (once)

```sh
./install-trusted.sh
```

Run it yourself in a terminal, from a reviewed commit: until it runs, the
script and `approver.swift` are ordinary user files. It builds
`approver.swift` and uses `sudo` to install root-owned copies. On the first
install, and with `--rotate-key`, it creates a new Secure Enclave key (signing
needs Touch ID or your password) and pins the public key that this run
produced. Key files already in `~/.config/review-gate/` are never trusted.
It ends by printing the commit and the sha256 of the installed checker and
signer.

Each key handle has its own file, `~/.config/review-gate/approver-<fp>.handle`,
where `<fp>` is the first 16 hex digits of the sha256 of its public key.
close signs with the file that matches the pinned key. The installer never
trusts a file name: `approver public --key <file>` prints a key file's public
key without Touch ID, and the installer compares it with the pin. It installs
the checker and signer first and rotates last. A rotation writes the new
key's file first, never touches the pinned key's file, then switches the pin
by renaming a checked copy. So if any step fails, the pin is still the old key
or already the new one, and the matching file is there either way. An older
install's `approver.handle` is given its fingerprint name, replacing any file
that does not match, before the new checker is installed. If no file matches
the pin, the script stops and asks for `--rotate-key`. If an old
`approver.handle` is there but does not match the pin, or cannot be checked,
it stops without changing anything, also with `--rotate-key`. A file that
cannot be checked may still be the right key: run the script again first.
Move the file away only when it does not match or you no longer need it.

- `/usr/local/bin/review-gate`: wrapper for the trusted checker
- `/usr/local/libexec/review-gate/`: `review_gate.py` and `approver`
- `/usr/local/etc/review-gate/approver.pub`: the pinned public key
- `/usr/local/etc/review-gate/path`: the pinned PATH for test commands. The
  first install pins `/usr/bin:/bin:/usr/sbin:/sbin`;
  `install-trusted.sh --path DIRS` replaces it. A check is trusted only when
  no regular user can change a pinned directory, any program in it, or any
  link on the way to a program (see How commands run).

A check counts only when it runs from these root-owned files. Any other copy,
or an environment override, reports `pass-untrusted` (exit 4). Rerun the
script after changing `review_gate.py`; later runs keep the pinned key.

## Recipe: `.review-gate.json`

Each repository commits one recipe. revert-check and the replay in check read
it from the base revision of the change, never from the command line or an
evidence file, so changing how tests run is a commit that reviewers see.

```json
{
  "cmd": "node_modules/.bin/vitest run --reporter=junit --outputFile=junit.xml {tests}",
  "junit": "junit.xml",
  "tests": ["*.test.ts"],
  "copy": ["node_modules"],
  "timeout": 600
}
```

- `cmd` must write a JUnit XML report to `junit`. `{tests}` expands to the
  test files the change touches, or to every test file in the base when the
  change touches none. Use it: each replay runs `cmd` twice, so a recipe
  that runs the whole suite makes every revert-check, close, and check pay
  for the whole suite twice per fix.
- `tests` are git pathspecs for test files. Other changed paths are reverted.
- `copy` clones untracked state such as `node_modules` into each variant (APFS
  clone on macOS), so variants never share writable state. A copy source that
  contains an absolute symlink, or a relative one pointing outside itself, is
  refused; the copy is checked again after cloning. The path, and every
  directory above it in the repo, must not be a symlink, and it must not exist
  in the checkout. There is no shared `link` mode; a recipe with `link` is
  refused. `setup` runs before the test in each variant.

## How commands run

`setup` and `cmd` run with `bash --noprofile --norc` and a minimal
environment:

- `PATH` is the pinned PATH, never the caller's. Without an install it is
  `/usr/bin:/bin:/usr/sbin:/sbin`; `REVIEW_GATE_PATH` overrides it and makes
  the check untrusted. The check is also untrusted when a regular user
  could replace a program found through the pinned PATH: every pinned
  directory, every entry in it, every directory holding a symlink on the way
  to a program, and the program itself must be owned by a system account
  (uid below 500), not group- or world-writable, and without an extended
  ACL entry that allows any write right, or be protected by System
  Integrity Protection. A writable directory on the way is accepted only
  when the entry in it cannot be renamed (`sunlnk`, SIP, or a sticky
  directory that a system account owns, with a system-owned entry and no
  ACL write grant). The trust anchors (checker, approver, public key, pinned
  PATH file) are stricter: their real path, every directory above it, and
  every directory holding a link on the way must be root-owned,
  write-protected, and free of ACL write grants. `/usr/bin`, `/bin`, `/usr/sbin`, and
  `/sbin` pass; Homebrew and most of `/usr/local/bin` do not.
- `HOME` and `TMPDIR` are empty private directories inside the variant, so
  caches and temp files are never shared between variants or with the user.
- Only `USER`, `LOGNAME`, `LANG`, `TERM`, `SHELL`, and `LC_*` pass through.
- On macOS each command runs under `sandbox-exec`, which keeps variants
  from sharing state. A command:
  - writes only inside its own variant directory (checkout, private HOME and
    TMPDIR) and `/dev/null`, `/dev/zero`, `/dev/fd`;
  - cannot read another variant's directory (`review-gate-*`);
  - cannot open a FIFO, terminal, or device outside its variant directory,
    except `/dev/null`, `/dev/zero`, `/dev/random`, `/dev/urandom`, and its
    own `/dev/fd`, so a named pipe planted outside cannot hand each variant
    different data;
  - has no network, except Unix sockets inside its variant directory, so
    `setup` cannot download dependencies; provide them with `copy`;
  - has no POSIX or System V IPC (semaphores, shared memory, message
    queues) and no system services (mach lookups and registrations), except
    the read-only user directory lookup that `getpwuid` needs;
  - cannot see or signal processes outside its own sandbox.
    A run without the sandbox is not proof. macOS cannot start a sandbox
    inside another one, so the gate cannot run under another sandbox.
- Software that needs IPC or system services fails in the sandbox. A real
  PostgreSQL server needs System V semaphores and shared memory, so tests
  that start one cannot run in the gate; leave them out of the recipe's
  `cmd` (for vitest, `--exclude '**/*-postgres.test.ts'`). They then cannot
  prove a fix. They fail safely: a failed or crashed case is never proof.
- When the command ends or times out, a shell inside the same sandbox kills
  every process left in it, detached ones too, and the command's process
  group is killed. Output goes to an anonymous file, so a leftover process
  cannot stall the run.
- Each variant is a `git clone --shared` with a fresh config. The gate runs
  git without system or global config, hooks, fsmonitor, signing, external
  diff, textconv, or the repo's filter drivers, so nothing in a user-owned
  repo config runs outside the sandbox. Helper programs (`git`, `cp`,
  `sandbox-exec`, `bash`) are called by absolute path.
- Tests must keep temporary files under `TMPDIR`. A hard-coded `/tmp`, or a
  tool that ignores `TMPDIR` (macOS `mktemp -d` without a template uses the
  per-user `/var/folders` directory), fails in the sandbox. Variant
  directories sit under `/private/tmp` so Unix socket paths stay short.

JUnit reporters: vitest `--reporter=junit --outputFile=junit.xml`, pytest
`--junitxml=junit.xml`, Gradle and Maven write XML under `build/test-results`
or `target/surefire-reports` (point `junit` at one file).

## revert-check

Proves that a test case passes with the fix and fails without it.

```sh
review-gate revert-check --repo . --commit <fix> --finding B1 \
  --out scratch/review-evidence/<task>/B1-revert.json
```

- Omit `--commit` to check uncommitted work against `HEAD`.
- Proof is at least one test case that passes with the fix and fails an
  assertion without it. A `<failure>` counts as an assertion only when its
  `type` names one (`AssertionError`, `AssertionFailedError`,
  `ComparisonFailure`, and similar) or, with no type, its message starts with
  `assert` or `AssertionError` (pytest). Anything else is `other-failure`:
  exceptions thrown before an assertion, missing symbols, import errors. Errors,
  crashes, missing reports, and missing cases are not proof either. Write the
  test so the unfixed behavior fails an `expect`/`assert`, for example
  `await expect(call()).resolves...` instead of letting it throw.
- Exit 0 only when every condition holds.

## check

Fails unless every BLOCK is closed. A fixed BLOCK's evidence supplies only its
commit and finding; check reads the recipe again and replays the proof.

```sh
review-gate check scratch/review-evidence/<task>/findings.json --repo <repo>
```

check finds the BLOCK inventory itself. It reads every Reviewer, Security,
Redteam, and Oracle record under `~/.pi/agent/peer-records` whose `task_id`
starts with the findings `task_id`, and counts the `BLOCK <ID>` items in each
record's `findings` list. Give every judgment assignment of a task a TASK_ID
with that prefix. `--reviewer-record` adds a record from elsewhere; it cannot
hide a discovered one. No discovered record fails the check.

```json
{
  "task_id": "t",
  "findings": [
    {
      "id": "B1",
      "severity": "BLOCK",
      "status": "fixed",
      "change": "<fix commit or change_id>",
      "evidence": "B1-revert.json",
      "proof_tests": ["src/retry.test.ts::retries after a timeout"]
    },
    {
      "id": "B2",
      "severity": "BLOCK",
      "status": "rejected",
      "reason": "Reviewer misread the retry path; see app/src/retry.ts:40"
    },
    { "id": "W1", "severity": "WARN", "status": "open" }
  ]
}
```

`evidence` paths are relative to the findings file. The gate fails on:

- a `BLOCK <ID>` in any judgment record that is missing from the findings
  file or no longer a BLOCK there;
- a fixed BLOCK without `proof_tests`, the test case ids (`classname::name`)
  that must pass with the fix and fail an assertion without it in the replay;
- an open BLOCK;
- a fixed BLOCK without `--repo`, or whose evidence is incomplete, failed,
  from another review-gate version, bound to a different finding or change,
  or not reproduced by the replay;
- a `rejected` or `waived` BLOCK without a reason;
- no close receipt signed by the pinned key, or one that no longer matches.

Use `rejected` when the finding is wrong and `waived` when the fix is real but
cannot be proven by revert-check.

Replays run in parallel, half the CPUs at a time by default; `--jobs N`
changes that for check and close. Findings that share a fix commit share one
replay. Progress goes to stderr, one line per finished replay. Each replay
still uses its own fresh clones and sandbox; only the git reads in the source
repository run one at a time.

## close

Every task needs the user's signature before check passes, even a task with
no BLOCK. When all other checks pass, the agent (or the user) runs the
command below. Only the user's Touch ID can sign it:

```sh
review-gate close scratch/review-evidence/<task>/findings.json --repo <repo>
```

close prints a summary and macOS asks for Touch ID or the login password:

```text
Task t

Judgment records (2):
  ~/.pi/agent/peer-records/<scope>/agents/reviewer/tasks/t-review1.yaml
      sha256 9b1c...
      BLOCK: B1, B2
  ~/.pi/agent/peer-records/<scope>/agents/security/tasks/t-sec1.yaml
      sha256 40ae...
      BLOCK: none

How each BLOCK closes (2):
  B1: fixed
      change: 3f2a9c01b7d4e6a8...
      proof test: src/retry.test.ts::retries after a timeout
      reason: -
  B2: rejected
      change: -
      proof test: -
      reason: Reviewer misread the retry path; see app/src/retry.ts:40
```

The summary is rendered from the exact bytes that are signed, so every signed
field is on screen. Sign only if no review is missing from the list and each
test really proves its BLOCK. The signature covers each record's full path,
content hash, and BLOCK ids, and each BLOCK's status, change, proof tests, and
reason. After signing,
deleting, editing, or adding a judgment record, or changing any BLOCK entry,
fails check until the user signs again.

close and check hand the message to the signer over a pipe, so there is no
message file another process could swap before it is signed or verified.
check never reuses close's replay. The signature proves the user approved a
message, not that the trusted close produced it, so a reused result would
let a message signed by mistake skip the replay.

## canary

Measures whether reviewers catch a known defect.

```sh
review-gate canary seed --repo . --commit <reviewed-commit> \
  --copy node_modules --verify-junit junit.xml \
  --verify-cmd 'node_modules/.bin/vitest run --reporter=junit --outputFile=junit.xml'
# send review_base..review_commit to a fresh reviewer as an ordinary review
review-gate canary score <id> --role reviewer --model gpt-6-astra --caught yes
review-gate canary report
```

The seed flips one operator inside code on an added line. Comments and
strings (including multiline ones and nested comments in Rust, Kotlin,
Swift, and Scala), docs, and test files (`test_x.py`,
`x.test.ts`, `x_test.go`, `FooTest.java`, `tests/`, `__tests__/`) are skipped.
The lexer knows each language's raw and prefixed strings (Go backticks,
Rust `br""`/`r#""#`, C# `@""` and `"""`, Swift `#""#`, Scala interpolators,
GCC C `R"()"`) and Rust and Scala quote marks that are not character
literals. An interpolated string (JS templates, Python f-strings, Kotlin,
Swift, C#, Scala) is skipped whole, holes included; the holes are only
scanned to find where the string ends. JSX text and attributes are skipped,
but the code in JSX `{...}` holes is seeded. A backslash before CRLF
continues a string or C line comment. A file whose lexing is uncertain is
not seeded at all: a Java file whose Unicode escapes encode a quote,
backslash, newline, `/`, or `*`; a C file with a line splice after `/`, `*`,
or `\`, a backslash followed by blanks and a newline, or a `??/` trigraph; a
SQL file with a non-ASCII dollar tag; a Scala file with a backslash in an
interpolated string; a JS or Swift file with a `/` (other than a comment) in
an interpolation hole, or with a `/` followed by a quote, backtick, or `/*`
before the last `/` on its line; and a JSX file with an element where JSX is
not expected, or a `<tag` that does not parse where JSX is expected or does
not follow a name or closing bracket. In JS, TS,
and Swift, a line with a `/` in code is skipped too, because it may be a
regex literal. Shell, Ruby, PHP, and C++ files are not seeded. This masking
is best effort; only `verified` seeds, which change a test result, count as
behavioral. Known gaps, where a seed can still land in a string or comment:
line comments ended by a bare CR or U+2028/U+2029; JS HTML-like comments and
JS/Rust hashbang lines; JSX with a blank after `<`; division after `++` or
`--`; Python format specs that hold quotes; Kotlin and Scala backtick names;
C splices inside a raw-string prefix; Scala XML literals and Unicode escapes;
and SQL dialects or modes other than standard PostgreSQL (MySQL `#`
comments, Oracle `q'[...]'`, `standard_conforming_strings = off`). The seeded commit keeps the original author,
dates, message, and parent, and no branch is created. With `--verify-cmd`, the
original and the seeded commit each run in a fresh worktree, and a seed counts
as `verified` only if a test case passes on the original and fails an
assertion on the seed. The report keeps `verified` and `unverified` rates apart.
Scoring the same canary, role, and model twice needs `--supersede`; the report
counts the latest score. The ledger is
`~/.local/state/review-canary/ledger.jsonl` and stores locations and outcomes
only.

## role_lessons.py

Run, retro, candidate, human promotion, role lesson.

```sh
python3 -I role_lessons.py propose --role reviewer --lesson '...' --evidence <locator>
python3 -I role_lessons.py list
python3 -I role_lessons.py promote <id> --approved-by-user
```

Promoted lessons are appended to `~/.pi/agent/role-lessons/<role>.md`, which
peers read at task start.

## Limits

- Trust rests on the root-owned install and the Secure Enclave key. An agent
  running as the user cannot sign without Touch ID or replace the checker, but
  it can still claim a result it did not get. The user can run
  `review-gate check` to see the real verdict.
- Peer records are files owned by the user. A record deleted, or a review given
  a TASK_ID without the task prefix, before the user signs is missing from the
  close summary; the user must notice that. Proof tests are matched to BLOCKs
  by the summary the user reads, not by the tool.
- The sandbox confines the test command, not other programs. A process the
  user starts outside the gate while a check runs can read and change the
  variant directories, which the user owns. The gate cannot stop that
  without running variants as a separate account.
- Reads outside the other variants are allowed, so a test can read files
  planted before the check. Planted files are the same for both variants;
  a variant cannot change them.
- Projects whose tools live in user-owned directories (Homebrew, nvm) can run
  only with such a directory pinned (`install-trusted.sh --path` or
  `REVIEW_GATE_PATH`), and those checks report `pass-untrusted`.
- The recipe is trusted as committed. A recipe or test that inspects source
  text instead of behavior can fake a proof; reviewers must read both.
- Canary mutations are simple operator flips. They measure attention to logic
  changes, not design or security judgment. Canary commands still take their
  test command from the command line.

## Tests

```sh
python3 -I test_review_gate.py && python3 -I test_role_lessons.py
```
