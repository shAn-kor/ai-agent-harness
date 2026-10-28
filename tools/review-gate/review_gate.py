#!/usr/bin/env python3
"""Deterministic review gates for agent-team work.

Subcommands:
  revert-check  Prove a test case fails with the fix reverted and passes with it.
  check         Fail unless every BLOCK is closed; replays fix evidence.
  close         The user signs the task's review summary with Touch ID.
  canary        Seed a known defect, then score whether a reviewer caught it.

Each variant is a temporary shared clone with its own private HOME and
TMPDIR, and its commands run in a write and network sandbox. The caller's
working tree, index, and branches are never modified. The test
recipe comes from `.review-gate.json` committed at the base revision, never
from evidence files or the command line.
"""

from __future__ import annotations

import argparse
import ctypes
import datetime as dt
import hashlib
import json
import os
import random
import re
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import unicodedata
import threading
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

TAIL = 4000
SCHEMA = "review-gate.revert-check.v6"
CLOSE_SCHEMA = "review-gate.task-close.v1"
RECIPE_FILE = ".review-gate.json"
# Trust anchors. The installed copy, the signer, and the pinned public key are
# root-owned, so an agent running as the user cannot replace them. The
# environment overrides exist for tests and development; using them makes a
# passing check report "pass-untrusted".
TRUST_DIR = Path(os.environ.get("REVIEW_GATE_TRUST_DIR", "/usr/local/etc/review-gate"))
APPROVER = Path(
    os.environ.get("REVIEW_GATE_APPROVER", "/usr/local/libexec/review-gate/approver")
)
# Each Secure Enclave key handle has its own file, named by the fingerprint
# of its public key; close signs with the one that matches the pinned key.
# REVIEW_GATE_KEY names one file directly.
KEY_DIR = Path.home() / ".config/review-gate"
APPROVER_KEY = (
    Path(os.environ["REVIEW_GATE_KEY"]) if "REVIEW_GATE_KEY" in os.environ else None
)
GIT = "/usr/bin/git"
CP = "/bin/cp"
# Test commands find programs only through this PATH, never the caller's. The
# installer pins it in TRUST_DIR/path; REVIEW_GATE_PATH is a development
# override that makes a check untrusted. A trusted check also needs every
# pinned directory to be root-owned.
SYSTEM_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"
DEFAULT_PATH = SYSTEM_PATH
# git runs outside the sandbox, so nothing user-owned may make it run code:
# no system or global config, no hooks, no fsmonitor, no signing, no external
# diff or textconv, and every filter driver in the repo config is disabled.
GIT_ENV = {
    "PATH": SYSTEM_PATH,
    "HOME": "/var/empty",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_PAGER": "cat",
    "LC_ALL": "C",
}
GIT_SAFE = (
    "-c", "core.hooksPath=/dev/null",
    "-c", "core.fsmonitor=false",
    "-c", "commit.gpgSign=false",
)  # fmt: skip
# Every setup and test command runs in this write sandbox: it may write only
# inside its own variant directory (worktree, private HOME and TMPDIR) and a
# few stateless devices. Filters inside one rule match if any of them does.
SANDBOX_EXEC = Path("/usr/bin/sandbox-exec")
SANDBOX_PROFILE = """\
(version 1)
(allow default)
(deny file-write*)
(allow file-write* (subpath (param "ROOT")) (subpath "/dev/fd")
  (literal "/dev/null") (literal "/dev/zero") (literal "/dev/dtracehelper"))
(deny file-read* (regex #"/review-gate-[^/]+(/|$)"))
(allow file-read* (subpath (param "ROOT")))
(deny file-read* file-write* (vnode-type FIFO CHARACTER-DEVICE BLOCK-DEVICE TTY))
(allow file-read* file-write* (subpath (param "ROOT")) (subpath "/dev/fd")
  (literal "/dev/null") (literal "/dev/zero") (literal "/dev/random")
  (literal "/dev/urandom") (literal "/dev/dtracehelper"))
(deny network*)
(allow network* (local unix-socket (subpath (param "ROOT"))))
(allow network* (remote unix-socket (subpath (param "ROOT"))))
(deny ipc-posix* ipc-sysv* mach-lookup mach-register)
(allow mach-lookup (global-name "com.apple.system.opendirectoryd.libinfo"))
(deny process-info*)
(allow process-info* (target same-sandbox))
(deny signal)
(allow signal (target same-sandbox))
"""
PEER_RECORDS = Path(
    os.environ.get("REVIEW_GATE_PEER_RECORDS", Path.home() / ".pi/agent/peer-records")
)
JUDGMENT_ROLES = ("reviewer", "security", "redteam", "oracle")
# A BLOCK id counts only at the start of an item in a record's findings list.
BLOCK_ITEM = re.compile(r"""^\s*-\s*["']?BLOCK:?\s+([A-Z][A-Za-z0-9-]*\d)\b""")
EXCEPTION_STATUSES = {"rejected", "waived"}
LEDGER = Path(
    os.environ.get(
        "REVIEW_CANARY_LEDGER",
        Path.home() / ".local/state/review-canary/ledger.jsonl",
    )
)
CODE_SUFFIXES = {
    ".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".rs", ".go", ".java",
    ".kt", ".swift", ".c", ".cs",
    ".scala", ".sql",
}  # fmt: skip
HASH_COMMENT = {".py"}
JS_SUFFIXES = {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"}
TEST_PATH = re.compile(
    r"(^|/)(tests?|__tests__|spec|specs|testing|fixtures?)/"
    r"|(^|/)test_[^/]*$"
    r"|_test\.[^/]+$"
    r"|[._-](test|spec)s?\.[^/]+$"
    r"|[A-Za-z0-9](Test|Tests|Spec|IT)\.[^/]+$"
)
# Only an assertion failure is proof that behavior changed. Anything else, such
# as a missing symbol or an exception thrown before the assertion, is not.
ASSERTION_TYPE = re.compile(
    r"Assert|ComparisonFailure|ExpectationFailed|MultipleFailuresError"
)
ASSERTION_MESSAGE = re.compile(r"^\s*(assert\b|AssertionError\b)")
MUTATIONS = [
    (r"<=", "<"),
    (r">=", ">"),
    (r"===", "!=="),
    (r"!==", "==="),
    (r"(?<![=!<>])==(?!=)", "!="),
    (r"!=(?!=)", "=="),
    (r"&&", "||"),
    (r"\|\|", "&&"),
    (r"\btrue\b", "false"),
    (r"\bfalse\b", "true"),
    (r"\bTrue\b", "False"),
    (r"\bFalse\b", "True"),
    (r"\band\b", "or"),
    (r"\bor\b", "and"),
    (r"\+ 1\b", "- 1"),
    (r"- 1\b", "+ 1"),
]


class GateError(Exception):
    pass


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


_FILTERS: dict[str, list[str]] = {}


def filter_overrides(repo: Path) -> list[str]:
    """-c options that disable every filter driver the repo config defines."""
    key = str(repo)
    if key not in _FILTERS:
        proc = subprocess.run(
            [GIT, "-C", key, *GIT_SAFE, "config", "--name-only", "--get-regexp",
             r"^filter\."],
            capture_output=True,
            env=GIT_ENV,
        )  # fmt: skip
        names = {n.rsplit(".", 1)[0] for n in proc.stdout.decode().splitlines()}
        _FILTERS[key] = [
            arg
            for name in sorted(names)
            for kind in ("clean", "smudge", "process")
            for arg in ("-c", f"{name}.{kind}=")
        ]
    return _FILTERS[key]


def git(
    repo: Path,
    *args: str,
    check: bool = True,
    data: bytes | None = None,
    index: Path | None = None,
    env: dict | None = None,
):
    env = {**GIT_ENV, **(env or {})}
    if index is not None:
        env["GIT_INDEX_FILE"] = str(index)
    if args and args[0] == "diff":
        args = ("diff", "--no-ext-diff", "--no-textconv", *args[1:])
    proc = subprocess.run(
        [GIT, "-C", str(repo), *GIT_SAFE, *filter_overrides(repo), *args],
        input=data,
        capture_output=True,
        env=env,
    )
    if check and proc.returncode != 0:
        raise GateError(
            f"git {' '.join(args)} failed: {proc.stderr.decode(errors='replace')}"
        )
    return proc


def zlist(proc) -> list[str]:
    return [n for n in proc.stdout.decode().split("\0") if n]


def tool_sha() -> str:
    return sha256(Path(__file__).read_bytes())


# Extended ACL rights that change a file or a directory's entries.
ACL_WRITE_RIGHTS = {
    "write", "append", "writeattr", "writeextattr", "writesecurity", "chown",
    "delete", "add_file", "add_subdirectory", "delete_child",
}  # fmt: skip
ACL_TYPE_EXTENDED = 0x00000100


def acl_write_grants(path: Path) -> list[str]:
    """Extended ACL entries on path (not followed if a link) that allow any
    write right. A path whose ACL cannot be read counts as granting one."""
    libc = ctypes.CDLL(None, use_errno=True)
    libc.acl_get_link_np.restype = ctypes.c_void_p
    libc.acl_get_link_np.argtypes = [ctypes.c_char_p, ctypes.c_int]
    libc.acl_to_text.restype = ctypes.c_void_p
    libc.acl_to_text.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    libc.acl_free.argtypes = [ctypes.c_void_p]
    acl = libc.acl_get_link_np(os.fsencode(path), ACL_TYPE_EXTENDED)
    if not acl:
        # ENOENT means no extended ACL.
        return [] if ctypes.get_errno() == 2 else ["unreadable ACL"]
    try:
        text = libc.acl_to_text(acl, None)
        if not text:
            return ["unreadable ACL"]
        try:
            entries = ctypes.string_at(text).decode(errors="replace").splitlines()
        finally:
            libc.acl_free(ctypes.c_void_p(text))
    finally:
        libc.acl_free(ctypes.c_void_p(acl))
    grants = []
    for entry in entries[1:]:
        fields = entry.split(":")
        if len(fields) >= 6 and fields[4] == "allow":
            if ACL_WRITE_RIGHTS & set(fields[5].split(",")):
                grants.append(entry)
    return grants


def root_owned_problems(path: Path) -> list[str]:
    """The real file, every directory above it, and every directory holding
    a link on the way to it must be root-owned, not group/other-writable,
    and without an ACL entry that grants a write right."""
    problems: list[str] = []
    hops: list[Path] = []
    real = resolve_checked(path, problems, hops)
    checked = []
    for start in (real, *hops):
        checked += [p for p in (start, *start.parents) if p not in checked]
    for p in checked:
        try:
            st = os.lstat(p)
        except OSError:
            return [f"{path} does not exist"]
        if st.st_uid != 0 or st.st_mode & 0o022 or acl_write_grants(p):
            problems.append(f"{p} is not root-owned and write-protected")
    return list(dict.fromkeys(problems))


def trust_problems() -> list[str]:
    problems = []
    for name in ("REVIEW_GATE_TRUST_DIR", "REVIEW_GATE_APPROVER") + (
        "REVIEW_GATE_PEER_RECORDS",
        "REVIEW_GATE_PATH",
    ):
        if name in os.environ:
            problems.append(f"{name} override in use")
    for path in (
        Path(__file__).resolve(),
        APPROVER,
        TRUST_DIR / "approver.pub",
        TRUST_DIR / "path",
    ):
        problems += root_owned_problems(path)
    for directory in command_path().split(":"):
        problems += [f"pinned PATH: {p}" for p in pinned_dir_problems(Path(directory))]
    return problems


# System accounts on macOS have uids below 500; regular users start at 501.
SYSTEM_UID_LIMIT = 500
SF_RESTRICTED, SF_NOUNLINK = 0x00080000, 0x00100000


def system_controlled(path: Path, st: os.stat_result) -> bool:
    """No regular user can change it: a system account owns it and neither
    mode bits nor an ACL entry let anyone else write, or System Integrity
    Protection guards it."""
    if st.st_flags & SF_RESTRICTED:
        return True
    owned = st.st_uid < SYSTEM_UID_LIMIT and not st.st_mode & 0o022
    return owned and not acl_write_grants(path)


def protected_problems(real: Path) -> list[str]:
    """Problems that would let a regular user change the file at real (a path
    without links) or swap any directory entry on the way to it."""
    try:
        chain = [(p, os.lstat(p)) for p in (real, *real.parents)]
    except OSError as exc:
        return [f"{real}: {exc.strerror}"]
    problems = []
    if not system_controlled(*chain[0]):
        problems.append(f"{real} is not system-owned and write-protected")
    for (child, cst), (parent, pst) in zip(chain, chain[1:]):
        fixed = cst.st_flags & (SF_RESTRICTED | SF_NOUNLINK)
        # In a sticky directory only the entry's owner, the directory's owner,
        # and holders of an ACL write right can rename an entry.
        sticky = (
            pst.st_mode & stat.S_ISVTX
            and cst.st_uid < SYSTEM_UID_LIMIT
            and pst.st_uid < SYSTEM_UID_LIMIT
            and not acl_write_grants(parent)
        )
        if not (system_controlled(parent, pst) or fixed or sticky):
            problems.append(f"{child} can be replaced: {parent} is writable")
    return problems


def resolve_checked(path: Path, problems: list[str], hops=None) -> Path:
    """Resolve path like realpath, adding a problem for every link that sits
    in a directory a regular user could change. Directories holding a link
    are added to hops."""
    real, parts, links = Path("/"), list(path.parts[1:]), 0
    while parts:
        name = parts.pop(0)
        if name in ("", "."):
            continue
        if name == "..":
            real = real.parent
            continue
        candidate = real / name
        try:
            st = os.lstat(candidate)
        except OSError:
            return candidate.joinpath(*parts)
        if not stat.S_ISLNK(st.st_mode):
            real = candidate
            continue
        links += 1
        if links > 40:
            problems.append(f"{path} has too many links")
            return candidate
        problems += protected_problems(real)
        if hops is not None:
            hops.append(real)
        target = Path(os.readlink(candidate))
        if target.is_absolute():
            real = Path("/")
        parts = [p for p in target.parts if p != "/"] + parts
    return real


def pinned_dir_problems(directory: Path) -> list[str]:
    """The directory, every program in it, and every link on the way to a
    program must be out of reach of a regular user."""
    problems: list[str] = []
    real = resolve_checked(directory, problems)
    problems += protected_problems(real)
    try:
        entries = sorted(real.iterdir())
    except OSError:
        return list(dict.fromkeys(problems))
    for entry in entries:
        target = resolve_checked(entry, problems)
        if os.path.lexists(target):
            problems += protected_problems(target)
    return list(dict.fromkeys(problems))


def command_path() -> str:
    """The PATH for test commands: pinned at install, else a fixed default."""
    if "REVIEW_GATE_PATH" in os.environ:
        return os.environ["REVIEW_GATE_PATH"]
    try:
        pinned = (TRUST_DIR / "path").read_text().strip()
    except OSError:
        pinned = ""
    return pinned or DEFAULT_PATH


def load_recipe(repo: Path, rev: str) -> argparse.Namespace:
    """The test recipe committed at rev; changing it shows up in review."""
    shown = git(repo, "show", f"{rev}:{RECIPE_FILE}", check=False)
    if shown.returncode != 0:
        raise GateError(f"{RECIPE_FILE} is not committed at {rev[:12]}")
    try:
        raw = json.loads(shown.stdout.decode())
    except json.JSONDecodeError as exc:
        raise GateError(f"{RECIPE_FILE} at {rev[:12]} is not JSON: {exc}") from exc
    recipe = argparse.Namespace(
        cmd=raw.get("cmd"),
        junit=raw.get("junit"),
        tests=raw.get("tests"),
        setup=raw.get("setup"),
        copy=raw.get("copy", []),
        timeout=raw.get("timeout", 900),
    )
    if "link" in raw:
        raise GateError(
            f"{RECIPE_FILE}: 'link' is not supported because it shares state "
            "between variants; use 'copy'"
        )
    if not isinstance(recipe.cmd, str) or not recipe.cmd.strip():
        raise GateError(f"{RECIPE_FILE}: 'cmd' is required")
    if not isinstance(recipe.junit, str) or not recipe.junit:
        raise GateError(f"{RECIPE_FILE}: 'junit' is required")
    if Path(recipe.junit).is_absolute() or ".." in Path(recipe.junit).parts:
        raise GateError(f"{RECIPE_FILE}: 'junit' must be a relative path")
    if not isinstance(recipe.tests, list) or not recipe.tests:
        raise GateError(f"{RECIPE_FILE}: 'tests' must be a list of pathspecs")
    if not isinstance(recipe.timeout, int):
        raise GateError(f"{RECIPE_FILE}: 'timeout' must be an integer")
    return recipe


def escaping_links(root: Path) -> list[str]:
    """Symlinks under root that are absolute or resolve outside it.

    An absolute link keeps pointing at the original after a copy, so it would
    share state between variants even when it points inside root.
    """
    out = []
    base = root.resolve()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in dirnames + filenames:
            full = Path(dirpath) / name
            if full.is_symlink():
                target = os.readlink(full)
                resolved = (full.parent / target).resolve()
                outside = resolved != base and base not in resolved.parents
                if os.path.isabs(target) or outside:
                    out.append(str(full.relative_to(root)))
    return sorted(out)


def clone_dir(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    if sys.platform == "darwin":
        proc = subprocess.run([CP, "-cR", str(src), str(dst)], capture_output=True)
        if proc.returncode == 0:
            return
    shutil.copytree(src, dst, symlinks=True)


def variant_root() -> Path:
    """A new private directory for one variant.

    /private/tmp keeps paths short, so Unix sockets under the private TMPDIR
    stay within the 104-byte limit. Inside another review-gate run it is not
    writable, and the inherited private TMPDIR is used instead.
    """
    try:
        made = tempfile.mkdtemp(prefix="review-gate-", dir="/private/tmp")
    except OSError:
        made = tempfile.mkdtemp(prefix="review-gate-")
    return Path(made).resolve()


class Worktree:
    """A disposable checkout of a base revision in its own variant directory.

    It is a shared clone, not a git worktree: the clone has a fresh config and
    no hooks, so nothing in the user's repository config runs at checkout.
    """

    def __init__(self, repo: Path, base: str, copies=()):
        self.repo = repo
        self.base = base
        self.copies = list(copies)
        self.tmp = variant_root()
        self.path = self.tmp / "wt"
        self.home = self.tmp / "home"
        self.tmpdir = self.tmp / "tmp"
        self.home.mkdir()
        self.tmpdir.mkdir()

    def __enter__(self) -> "Worktree":
        try:
            git(self.repo, "clone", "--shared", "--no-checkout", "-q", str(self.repo),
                str(self.path))  # fmt: skip
            git(self.path, "checkout", "-q", "--detach", self.base)
            self.populate()
        except BaseException:
            self.__exit__(None, None, None)
            raise
        return self

    def populate(self) -> None:
        for rel in self.copies:
            src = self.repo / rel
            if not src.exists():
                raise GateError(f"copy path does not exist: {rel}")
            # The path and every directory above it inside the repo must be
            # real directories; a link there would share the target instead.
            for root, path in ((self.repo, src), (self.path, self.path / rel)):
                linked = [p for p in (path, *path.parents) if p.is_symlink()]
                inside = [p for p in linked if root in p.parents]
                if inside:
                    raise GateError(f"{rel} is or sits under a symlink: {inside[0]}")
            dst = self.path / rel
            if dst.exists() or dst.is_symlink():
                raise GateError(
                    f"{rel} already exists in the checkout; copy is only for "
                    "untracked state"
                )
            leaks = escaping_links(src)
            if leaks:
                raise GateError(f"{rel} has symlinks leaving it: {leaks[:5]}")
            clone_dir(src, dst)
            leaks = escaping_links(dst)
            if leaks:
                raise GateError(f"copy of {rel} has escaping links: {leaks[:5]}")

    def __exit__(self, *exc) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def apply(self, change: "Change", only_tests: bool) -> None:
        patch = change.test_patch if only_tests else change.full_patch
        if patch.strip():
            git(self.path, "apply", "--binary", "--whitespace=nowarn", data=patch)
        for rel, blob in change.untracked.items():
            if only_tests and rel not in change.untracked_tests:
                continue
            dst = self.path / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(blob)

    def run(self, cmd: str, timeout: int) -> dict:
        return run_cmd(cmd, self.path, timeout, self.tmp, self.home, self.tmpdir)


class Change:
    """The fix under test, from a commit or from uncommitted work."""

    def __init__(self, repo: Path, commit: str | None, tests: list[str]):
        self.repo = repo
        if commit:
            head = git(repo, "rev-parse", "--verify", f"{commit}^{{commit}}")
            self.head = head.stdout.decode().strip()
            self.base = git(repo, "rev-parse", f"{self.head}^").stdout.decode().strip()
            rng = [self.base, self.head]
            self.untracked: dict[str, bytes] = {}
            self.untracked_tests: set[str] = set()
        else:
            self.head = None
            self.base = git(repo, "rev-parse", "HEAD").stdout.decode().strip()
            rng = [self.base]
            others = ["ls-files", "--others", "--exclude-standard", "-z"]
            self.untracked = {
                rel: (repo / rel).read_bytes()
                for rel in zlist(git(repo, *others))
                if (repo / rel).is_file()
            }
            self.untracked_tests = set(zlist(git(repo, *others, "--", *tests)))
        self.changed = sorted(
            set(zlist(git(repo, "diff", "--name-only", "-z", *rng)))
            | set(self.untracked)
        )
        self.full_patch = git(repo, "diff", "--binary", *rng).stdout
        self.test_patch = git(repo, "diff", "--binary", *rng, "--", *tests).stdout
        changed_tests = set(
            zlist(git(repo, "diff", "--name-only", "-z", *rng, "--", *tests))
        )
        self.test_paths = sorted(changed_tests | self.untracked_tests)
        self.reverted = [p for p in self.changed if p not in set(self.test_paths)]
        # ls-tree ignores wildcards, so match the base tree through a scratch
        # index with the same pathspec rules as the diffs above.
        with tempfile.TemporaryDirectory() as tmp:
            index = Path(tmp) / "index"
            git(repo, "read-tree", f"--index-output={index}", self.base)
            listed = git(repo, "ls-files", "-z", "--", *tests, index=index)
        self.base_tests = sorted(zlist(listed))
        digest = hashlib.sha256(self.full_patch)
        for rel in sorted(self.untracked):
            digest.update(b"\0untracked\0" + rel.encode() + b"\0")
            digest.update(self.untracked[rel])
        self.change_id = digest.hexdigest()


# Test commands get only these variables, so startup hooks such as BASH_ENV,
# NODE_OPTIONS, or PYTHONPATH cannot run code the recipe does not name. PATH,
# HOME, and TMPDIR are never inherited; see clean_env.
CMD_ENV = ("USER", "LOGNAME", "LANG", "TERM", "SHELL")


def clean_env(home: Path, tmpdir: Path) -> dict:
    env = {k: os.environ[k] for k in CMD_ENV if k in os.environ}
    env.update({k: v for k, v in os.environ.items() if k.startswith("LC_")})
    env.update(PATH=command_path(), HOME=str(home), TMPDIR=f"{tmpdir}/")
    return env


# Runs the command inside the sandbox, then kills every process left in that
# sandbox, detached ones too: the profile lets signals reach only the same
# sandbox, so `kill -1` cannot touch anything else. If the gate process itself
# can be signaled, the shell is not confined and nothing is killed. On macOS
# `kill -1` also kills the shell sending it, so the shell first writes the
# command's exit status to the file descriptor named by $3.
SWEEP_WRAPPER = """\
gate=$1
sweep() { kill -0 "$gate" 2>/dev/null || kill -KILL -1 2>/dev/null; }
trap 'sweep; exit 143' TERM
/bin/bash --noprofile --norc -c "$2" &
wait $!
status=$?
echo "$status" >&"$3"
sweep
exit $status
"""


def sandbox_argv(root: Path) -> list[str]:
    if not SANDBOX_EXEC.is_file():
        return []
    return [str(SANDBOX_EXEC), "-D", f"ROOT={root}", "-p", SANDBOX_PROFILE]


def run_cmd(
    cmd: str, cwd: Path, timeout: int, root: Path, home: Path, tmpdir: Path
) -> dict:
    """Run cmd in the write sandbox with a private HOME and TMPDIR under root.

    When the command ends or times out, SWEEP_WRAPPER kills every process
    left in its sandbox, and its process group is killed too. Output goes to
    an anonymous file, so a detached descendant holding it cannot stall the run.
    """
    sandbox = sandbox_argv(root)
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as status:
        proc = subprocess.Popen(
            [*sandbox, "/bin/bash", "--noprofile", "--norc", "-c", SWEEP_WRAPPER,
             "review-gate", str(os.getpid()), cmd, str(status.fileno())],
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=out,
            stderr=subprocess.STDOUT,
            env=clean_env(home, tmpdir),
            start_new_session=True,
            pass_fds=(status.fileno(),),
        )  # fmt: skip
        timed_out = False
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                pass
        finally:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            proc.wait()
        out.seek(0)
        output = out.read()
        status.seek(0)
        written = status.read().decode().strip()
    exit_code = int(written) if written.isdigit() else proc.returncode
    return {
        "sandboxed": bool(sandbox),
        "exit_code": None if timed_out else exit_code,
        "timed_out": timed_out,
        "output": output.decode(errors="replace"),
    }


def junit_cases(path: Path) -> dict[str, str] | None:
    """Map 'classname::name' to pass, failure, other-failure, error, or skipped.

    'failure' means an assertion failed. A <failure> whose type is not an
    assertion type, or that has no type and no assertion message, is
    'other-failure' and is not proof.
    """
    if not path.is_file():
        return None
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError:
        return None
    cases: dict[str, str] = {}
    for case in root.iter("testcase"):
        key = f"{case.get('classname', '')}::{case.get('name', '')}"
        status = "pass"
        for tag in ("error", "failure", "skipped"):
            node = case.find(tag)
            if node is not None:
                status = tag
                kind, message = node.get("type") or "", node.get("message") or ""
                if tag == "failure" and not (
                    ASSERTION_TYPE.search(kind)
                    if kind
                    else ASSERTION_MESSAGE.search(message)
                ):
                    status = "other-failure"
                break
        if key in cases and cases[key] != status:
            status = "error"  # ambiguous duplicate ids prove nothing
        cases[key] = status
    return cases


def variant(change: Change, args, only_tests: bool) -> dict:
    """Run setup and the test command in its own fresh worktree."""
    with Worktree(change.repo, change.base, args.copy) as wt:
        wt.apply(change, only_tests)
        wanted = sorted(set(change.test_paths) | set(change.base_tests))
        present = [p for p in wanted if (wt.path / p).exists()]
        report = wt.path / args.junit
        result: dict = {"present_tests": present, "setup_failed": False}
        if report.exists():
            result["junit_preexisting"] = True
            report.unlink()
        sandboxed = True
        if args.setup:
            setup = wt.run(args.setup, args.timeout)
            sandboxed = setup["sandboxed"]
            if setup["exit_code"] != 0:
                result["setup_failed"] = True
                result["setup_tail"] = setup["output"][-TAIL:]
        run = wt.run(args.cmd, args.timeout)
        cases = junit_cases(report)
    result.update(
        sandboxed=sandboxed and run["sandboxed"],
        exit_code=run["exit_code"],
        timed_out=run["timed_out"],
        tail=run["output"][-TAIL:],
        junit_found=cases is not None,
        cases=cases or {},
    )
    return result


TOP_FIELDS = {
    "schema": str,
    "tool_sha256": str,
    "finding": str,
    "base": str,
    "change_id": str,
    "mode": str,
    "recipe_source": str,
    "recipe": dict,
    "cmd": str,
    "test_paths": list,
    "base_tests": list,
    "reverted_paths": list,
    "with_fix": dict,
    "fix_reverted": dict,
}
RUN_FIELDS = {
    "timed_out": bool,
    "setup_failed": bool,
    "present_tests": list,
    "junit_found": bool,
    "cases": dict,
    "sandboxed": bool,
}


def proof_cases(fixed: dict, reverted: dict) -> list[str]:
    """Cases that pass with the fix and fail an assertion without it."""
    return sorted(
        key
        for key, status in fixed.get("cases", {}).items()
        if status == "pass" and reverted.get("cases", {}).get(key) == "failure"
    )


def revert_problems(result: dict) -> list[str]:
    """Every condition a valid red/green proof must meet; shared by check."""
    problems = []
    for key, typ in TOP_FIELDS.items():
        if not isinstance(result.get(key), typ) or result.get(key) in ("", None):
            problems.append(f"missing or invalid field: {key}")
    for label in ("with_fix", "fix_reverted"):
        run = result.get(label)
        if not isinstance(run, dict):
            continue
        for key, typ in RUN_FIELDS.items():
            if not isinstance(run.get(key), typ):
                problems.append(f"missing or invalid field: {label}.{key}")
        if "exit_code" not in run:
            problems.append(f"missing field: {label}.exit_code")
    if problems:
        return problems
    fixed, reverted = result["with_fix"], result["fix_reverted"]
    if not result["reverted_paths"]:
        problems.append("nothing to revert: every changed path matches the tests")
    if not (result["test_paths"] or result["base_tests"]):
        problems.append("test pathspec matches no file in the base or the change")
    for label, run in (("with_fix", fixed), ("fix_reverted", reverted)):
        if not run["sandboxed"]:
            problems.append(f"{label} ran without the write sandbox")
        if run["setup_failed"]:
            problems.append(f"setup failed in {label}")
        if run.get("junit_preexisting"):
            problems.append(f"a junit report already existed in {label}")
        if run["timed_out"]:
            problems.append(f"{label} timed out")
        if not run["junit_found"]:
            problems.append(f"no junit report in {label}")
    if not reverted["present_tests"]:
        problems.append("no test file is present in the reverted variant")
    elif fixed["present_tests"] != reverted["present_tests"]:
        problems.append("test files differ between the two variants")
    if fixed["exit_code"] != 0:
        problems.append("test command does not pass with the fix")
    if not fixed["cases"]:
        problems.append("no test case ran with the fix")
    elif any(s not in ("pass", "skipped") for s in fixed["cases"].values()):
        problems.append("some test cases fail with the fix")
    if reverted["exit_code"] in (0, None):
        problems.append("test command still passes (or hangs) with the fix reverted")
    if not proof_cases(fixed, reverted):
        problems.append(
            "no test case passes with the fix and fails an assertion without it; "
            "other failures, errors, crashes, and missing cases are not proof"
        )
    return problems


def revert_check(args: argparse.Namespace) -> int:
    result = build_evidence(Path(args.repo).resolve(), args.commit, args.finding)
    text = json.dumps(result, ensure_ascii=False, indent=2)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(text + "\n")
    print(text)
    return 0 if result["verdict"] == "pass" else 1


# Parallel replays share the source repository; git commands there take its
# index lock, so they run one at a time. The test runs use their own clones.
SOURCE_LOCK = threading.Lock()


def build_evidence(repo: Path, commit: str | None, finding: str) -> dict:
    with SOURCE_LOCK:
        recipe, change = read_change(repo, commit)
    return evidence_for(repo, recipe, change, finding)


def read_change(repo: Path, commit: str | None):
    if commit:
        head = git(repo, "rev-parse", "--verify", f"{commit}^{{commit}}")
        base = git(repo, "rev-parse", f"{head.stdout.decode().strip()}^")
    else:
        base = git(repo, "rev-parse", "HEAD")
    base_rev = base.stdout.decode().strip()
    recipe = load_recipe(repo, base_rev)
    return recipe, Change(repo, commit, recipe.tests)


def evidence_for(repo: Path, recipe, change: Change, finding: str) -> dict:
    selected = change.test_paths or change.base_tests
    recipe.cmd_template, recipe.cmd = (
        recipe.cmd,
        recipe.cmd.replace("{tests}", " ".join(shlex.quote(p) for p in selected)),
    )
    result = {
        "schema": SCHEMA,
        "tool_sha256": tool_sha(),
        "created_at": now(),
        "finding": finding,
        "repo": repo.name,
        "commit": change.head,
        "base": change.base,
        "change_id": change.change_id,
        "mode": "commit" if change.head else "working-tree",
        "recipe_source": f"{change.base}:{RECIPE_FILE}",
        "recipe": {
            k: getattr(recipe, k)
            for k in ("cmd_template", "junit", "tests", "setup", "copy")
        }
        | {"timeout": recipe.timeout},
        "cmd": recipe.cmd,
        "test_paths": change.test_paths,
        "base_tests": change.base_tests,
        "reverted_paths": change.reverted,
    }
    if change.changed and change.reverted:
        result["with_fix"] = variant(change, recipe, only_tests=False)
        result["fix_reverted"] = variant(change, recipe, only_tests=True)
        result["proof_cases"] = proof_cases(result["with_fix"], result["fix_reverted"])
    problems = revert_problems(result) if change.changed else ["no changes found"]
    result["verdict"] = "fail" if problems else "pass"
    result["problems"] = problems
    return result


def evidence_static_problems(item: dict, ev: dict) -> list[str]:
    """Every check on the evidence file that needs no replay."""
    if ev.get("schema") != SCHEMA:
        return [f"evidence is not {SCHEMA} output"]
    problems = []
    if ev.get("tool_sha256") != tool_sha():
        problems.append("evidence came from a different review-gate version; rerun")
    if ev.get("finding") != item["id"]:
        problems.append(f"evidence is bound to finding {ev.get('finding')!r}")
    bound = item.get("change")
    if not bound:
        problems.append("finding needs 'change': the fix commit or change_id")
    elif bound not in {ev.get("commit"), ev.get("change_id")}:
        problems.append("evidence belongs to a different change")
    wanted = item.get("proof_tests")
    if not isinstance(wanted, list) or not wanted:
        problems.append("finding needs 'proof_tests': the test cases that prove it")
    return problems + revert_problems(ev)


def evidence_problems(item: dict, ev: dict, repo: Path, replay=None) -> list[str]:
    """Static checks, then a fresh replay; replay(commit) may supply it."""
    problems = evidence_static_problems(item, ev)
    if problems:
        return problems
    wanted = item["proof_tests"]
    # Only the commit and finding are taken from the evidence; the recipe is
    # read again from the repository.
    if replay is None:
        fresh = build_evidence(repo, ev.get("commit"), item["id"])
    else:
        fresh = replay(ev.get("commit"))
    if fresh["change_id"] != ev["change_id"]:
        problems.append("the change in --repo no longer matches the evidence")
    if fresh["verdict"] != "pass":
        problems.append(f"replay failed: {fresh['problems']}")
    elif not set(wanted) <= set(fresh["proof_cases"]):
        missing = sorted(set(wanted) - set(fresh["proof_cases"]))
        problems.append(f"replay does not prove the finding's tests: {missing}")
    return problems


def close_path(root: Path, task_id: str) -> Path:
    return root / "approvals" / f"{task_id}--close.json"


def block_summary(item: dict) -> dict:
    return {
        "id": item.get("id"),
        "status": item.get("status"),
        "change": item.get("change"),
        "proof_tests": item.get("proof_tests"),
        "reason": str(item.get("reason", "")),
    }


def close_payload(task_id: str, findings: list, records: dict) -> bytes:
    """What the user signs: every judgment record and how each BLOCK closes."""
    payload = {
        "schema": CLOSE_SCHEMA,
        "task_id": task_id,
        "records": [
            {"path": path, "sha256": sha256(Path(path).read_bytes()), "blocks": ids}
            for path, ids in sorted(records.items())
        ],
        "blocks": sorted(
            (
                block_summary(f)
                for f in findings
                if str(f.get("severity", "")).upper() == "BLOCK"
            ),
            key=lambda b: str(b["id"]),
        ),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def signature_valid(message: bytes, signature: str) -> bool:
    pub = TRUST_DIR / "approver.pub"
    if not pub.is_file() or not APPROVER.is_file():
        return False
    # The message goes over a pipe: a message file could be replaced by
    # another process running as the user before the verifier reads it.
    proc = subprocess.run(
        [str(APPROVER), "verify", "--pub", str(pub), "--message", "-",
         "--signature", signature],
        input=message,
        capture_output=True,
        env={"PATH": SYSTEM_PATH},
    )  # fmt: skip
    return proc.returncode == 0


def close_problems(root: Path, task_id: str, message: bytes) -> list[str]:
    path = close_path(root, task_id)
    if not path.is_file():
        return [
            f"the task needs the user's signed close ({path.name}); the user runs "
            "`review-gate close` and confirms the summary with Touch ID"
        ]
    try:
        receipt = json.loads(path.read_text())
    except json.JSONDecodeError:
        return ["close receipt is not JSON"]
    signature = receipt.get("signature")
    if not isinstance(signature, str):
        return ["close receipt has no signature"]
    if not signature_valid(message, signature):
        return [
            "close signature does not match the current judgment records and "
            "BLOCK closures; something changed after the user signed, or the "
            "receipt was not signed with the pinned key"
        ]
    return []


def finding_blocks(text: str) -> list[str]:
    ids, section, block_scalar = set(), None, False
    for line in text.splitlines():
        top = re.match(r"^([A-Za-z_]+):", line)
        if top:
            section, block_scalar = top.group(1), False
        elif section == "findings":
            m = BLOCK_ITEM.match(line)
            if m:
                ids.add(m.group(1))
            elif re.match(r"^\s*-\s*[>|][+-]?\s*$", line):
                block_scalar = True  # folded/literal item; text starts next line
            elif block_scalar and line.strip():
                m = re.match(r"^\s+BLOCK:?\s+([A-Z][A-Za-z0-9-]*\d)\b", line)
                if m:
                    ids.add(m.group(1))
                block_scalar = False
    return sorted(ids)


def task_records(task_id: str) -> list[Path]:
    """Judgment records whose task id starts with the findings task id."""
    found = []
    pattern = re.compile(r"^task_id:\s*['\"]?([^'\"\s]+)", re.M)
    for role in JUDGMENT_ROLES:
        for path in sorted(PEER_RECORDS.glob(f"*/agents/{role}/tasks/*.yaml")):
            try:
                m = pattern.search(path.read_text())
            except OSError:
                continue
            if m and m.group(1).startswith(task_id):
                found.append(path)
    return found


def record_blocks(task_id: str, extra: list[str]) -> dict[str, list[str]]:
    """BLOCK ids reported by every judgment record of the task."""
    paths = task_records(task_id) + [Path(p).resolve() for p in extra]
    out = {}
    for path in paths:
        try:
            out[str(path)] = finding_blocks(path.read_text())
        except OSError as exc:
            raise GateError(f"cannot read reviewer record {path}: {exc}") from exc
    return out


def gate(args: argparse.Namespace) -> dict:
    """Every check except the user's close signature."""
    path = Path(args.findings).resolve()
    doc = json.loads(path.read_text())
    findings, task_id = doc.get("findings"), doc.get("task_id")
    if not isinstance(findings, list) or not task_id:
        raise GateError("findings file needs 'task_id' and a 'findings' list")
    repo = Path(args.repo).resolve() if args.repo else None
    records = record_blocks(task_id, args.reviewer_record)
    failures, notes, seen, pending = [], [], set(), []
    if not records:
        failures.append(
            f"no judgment record found for task ids starting with {task_id!r}"
        )
    blocks = {
        f.get("id") for f in findings if str(f.get("severity", "")).upper() == "BLOCK"
    }
    for record, ids in records.items():
        for rid in ids:
            if rid not in blocks:
                failures.append(
                    f"{rid}: reported as BLOCK in {Path(record).name} but missing "
                    "or not a BLOCK in the findings file"
                )
    for item in findings:
        fid = item.get("id")
        sev = str(item.get("severity", "")).upper()
        status = item.get("status")
        if not fid or fid in seen:
            failures.append(f"finding without a unique id: {item}")
            continue
        seen.add(fid)
        if sev not in {"BLOCK", "WARN", "FYI"}:
            failures.append(f"{fid}: severity must be BLOCK, WARN, or FYI")
            continue
        if status not in {"open", "fixed"} | EXCEPTION_STATUSES:
            failures.append(f"{fid}: status must be open, fixed, rejected, or waived")
            continue
        if status in EXCEPTION_STATUSES and not str(item.get("reason", "")).strip():
            failures.append(f"{fid}: {status} without a reason")
            continue
        if sev != "BLOCK":
            if status == "open":
                notes.append(f"{fid}: {sev} still open")
            continue
        if status == "open":
            failures.append(f"{fid}: BLOCK is open")
        elif status in EXCEPTION_STATUSES:
            pass  # the user's close signature covers the status and reason
        elif repo is None:
            failures.append(f"{fid}: fixed BLOCK needs check --repo to replay evidence")
        else:
            ev_path = item.get("evidence")
            if not ev_path:
                failures.append(f"{fid}: fixed BLOCK needs revert-check evidence")
                continue
            try:
                ev = json.loads((path.parent / ev_path).resolve().read_text())
            except (OSError, json.JSONDecodeError) as exc:
                failures.append(f"{fid}: unreadable evidence: {exc}")
                continue
            static = evidence_static_problems(item, ev)
            if static:
                failures += [f"{fid}: {p}" for p in static]
            else:
                pending.append((item, ev, len(failures)))
    # Replay failures go back to each finding's place in the findings order.
    replayed = replay_all([p[:2] for p in pending], repo, getattr(args, "jobs", None))
    merged, start = [], 0
    for (_, _, pos), problems in zip(pending, replayed):
        merged += failures[start:pos] + problems
        start = pos
    failures = merged + failures[start:]
    return {
        "path": path,
        "task_id": task_id,
        "findings": findings,
        "records": records,
        "failures": failures,
        "notes": notes,
    }


def default_jobs() -> int:
    return max(1, (os.cpu_count() or 2) // 2)


def replay_all(pending: list, repo: Path | None, jobs: int | None) -> list:
    """Replay fixed-BLOCK evidence in parallel, once per distinct commit.

    Each replay builds fresh worktrees in its own sandbox, so runs do not
    share state. A commit's replay does not depend on the finding id, so
    findings that share a fix commit share one replay. Returns each
    finding's failures, in the order of pending.
    """
    if not pending:
        return []
    commits = list(dict.fromkeys(ev.get("commit") for _, ev in pending))
    jobs = max(1, jobs or default_jobs())
    total = len(commits)
    print(f"review-gate: replaying {total} change(s), {jobs} at a time",
          file=sys.stderr, flush=True)  # fmt: skip
    results: dict = {}
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        started = time.monotonic()
        futures = {pool.submit(build_evidence, repo, c, "replay"): c for c in commits}
        for done, fut in enumerate(as_completed(futures), 1):
            commit = futures[fut]
            try:
                results[commit] = fut.result()
                verdict = results[commit]["verdict"]
            except Exception as exc:  # raised again in findings order
                results[commit] = exc
                verdict = "error"
            print(f"review-gate: [{done}/{total}] {str(commit)[:12]} {verdict} "
                  f"({time.monotonic() - started:.0f}s)",
                  file=sys.stderr, flush=True)  # fmt: skip

    def replay(commit):
        result = results[commit]
        if isinstance(result, Exception):
            raise result
        return result

    return [
        [f"{item['id']}: {p}" for p in evidence_problems(item, ev, repo, replay)]
        for item, ev in pending
    ]


def check(args: argparse.Namespace) -> int:
    g = gate(args)
    failures = list(g["failures"])
    if not failures:
        message = close_payload(g["task_id"], g["findings"], g["records"])
        failures += close_problems(g["path"].parent, g["task_id"], message)
    untrusted = trust_problems()
    verdict = "fail" if failures else "pass-untrusted" if untrusted else "pass"
    report = {
        "findings_file": str(g["path"]),
        "task_id": g["task_id"],
        "reviewer_records": g["records"],
        "total": len(g["findings"]),
        "verdict": verdict,
        "failures": failures,
        "notes": g["notes"],
        "trusted": not untrusted,
        "trust_problems": untrusted,
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return {"pass": 0, "fail": 1}.get(verdict, 4)


def shown(value) -> str:
    """A field as plain visible text: control and format characters escaped.

    Escape sequences, carriage returns, and direction overrides in an editable
    field could otherwise redraw or reorder what the user reads before signing.
    """
    out = []
    for ch in str(value):
        if unicodedata.category(ch)[0] in "CZ" and ch != " ":
            out.append(ch.encode("unicode_escape").decode("ascii"))
        else:
            out.append(ch)
    return "".join(out)


def close_summary(message: bytes) -> str:
    """Render exactly the signed bytes, so the user sees every signed field."""
    payload = json.loads(message)
    records, blocks = payload["records"], payload["blocks"]
    lines = [
        f"Task {shown(payload['task_id'])}",
        "",
        f"Judgment records ({len(records)}):",
    ]
    for r in records:
        lines += [
            f"  {shown(r['path'])}",
            f"      sha256 {shown(r['sha256'])}",
            f"      BLOCK: {', '.join(shown(i) for i in r['blocks']) or 'none'}",
        ]
    lines += ["", f"How each BLOCK closes ({len(blocks)}):"]
    for b in blocks:
        lines.append(f"  {shown(b['id'])}: {shown(b['status'])}")
        lines.append(f"      change: {shown(b['change'] or '-')}")
        for t in b["proof_tests"] or ["-"]:
            lines.append(f"      proof test: {shown(t)}")
        lines.append(f"      reason: {shown(b['reason'] or '-')}")
    if not blocks:
        lines.append("  (no BLOCK)")
    lines += [
        "",
        "Sign only if no review is missing and each test really proves its BLOCK.",
    ]
    return "\n".join(lines)


def approver_key() -> Path:
    if APPROVER_KEY is not None:
        return APPROVER_KEY
    pub = TRUST_DIR / "approver.pub"
    if not pub.is_file():
        raise GateError(f"no pinned key at {pub}; run install-trusted.sh")
    fingerprint = hashlib.sha256(pub.read_bytes()).hexdigest()[:16]
    return KEY_DIR / f"approver-{fingerprint}.handle"


def close(args: argparse.Namespace) -> int:
    """Human-only: the Secure Enclave key signs only after Touch ID."""
    g = gate(args)
    if g["failures"]:
        failures = "\n  ".join(shown(f) for f in g["failures"])
        raise GateError(f"fix these before closing:\n  {failures}")
    key = approver_key()
    if not key.is_file():
        raise GateError(f"no approver key at {key}; run install-trusted.sh")
    message = close_payload(g["task_id"], g["findings"], g["records"])
    print(close_summary(message), file=sys.stderr)
    blocks = sum(str(f.get("severity", "")).upper() == "BLOCK" for f in g["findings"])
    prompt = (
        f"close review of {shown(g['task_id'])}: {len(g['records'])} records, "
        f"{blocks} BLOCKs"
    )
    proc = subprocess.run(
        [str(APPROVER), "sign", "--key", str(key), "--message", "-",
         "--reason", prompt],
        input=message,
        capture_output=True,
        env={"PATH": SYSTEM_PATH},
    )  # fmt: skip
    if proc.returncode != 0:
        raise GateError(f"not signed: {proc.stderr.decode(errors='replace').strip()}")
    receipt = {
        **json.loads(message),
        "closed_at": now(),
        "signature": proc.stdout.decode().strip(),
    }
    if not signature_valid(message, receipt["signature"]):
        raise GateError("the signature does not verify against the pinned key")
    out = close_path(g["path"].parent, g["task_id"])
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(receipt, indent=2) + "\n")
    print(f"recorded {out}")
    return 0


def ledger_append(entry: dict) -> None:
    LEDGER.parent.mkdir(parents=True, exist_ok=True)
    with LEDGER.open("a") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")


def ledger_rows() -> list[dict]:
    if not LEDGER.is_file():
        return []
    return [json.loads(line) for line in LEDGER.read_text().splitlines() if line]


def added_lines(repo: Path, base: str, head: str) -> list[tuple[str, int, str]]:
    diff = git(repo, "diff", "-U0", "--no-color", base, head).stdout.decode()
    out, path, lineno = [], None, 0
    for line in diff.splitlines():
        if line.startswith("+++ "):
            path = line[6:] if line.startswith("+++ b/") else None
        elif line.startswith("@@"):
            m = re.search(r"\+(\d+)", line)
            lineno = int(m.group(1)) if m else 0
        elif line.startswith("+") and path:
            out.append((path, lineno, line[1:]))
            lineno += 1
    return out


def regex_start(text: str, i: int) -> bool:
    """A JS '/' starts a regex literal after an operator, bracket, or keyword."""
    j = i - 1
    while j >= 0 and text[j] in " \t":
        j -= 1
    if j < 0 or text[j] in "\n(,=:[!&|?{};+-*%<>~^":
        return True
    if text[j] == ")":
        # After the condition of if, while, for, or with, a '/' starts a regex.
        depth, k = 0, j
        while k >= 0 and j - k < 4000:
            if text[k] == ")":
                depth += 1
            elif text[k] == "(":
                depth -= 1
                if depth == 0:
                    break
            k -= 1
        word = re.search(r"(\w+)\s*$", text[max(0, k - 40) : max(0, k)])
        return bool(word) and word.group(1) in {"if", "while", "for", "with"}
    word = re.search(r"(\w+)$", text[max(0, j - 40) : j + 1])
    return bool(word) and word.group(1) in {
        "return", "typeof", "case", "in", "of", "yield", "await", "else", "do",
        "void", "delete", "throw",
    }  # fmt: skip


NESTED_COMMENTS = {".rs", ".kt", ".swift", ".scala", ".sql"}


def block_comment_end(text: str, i: int, block: tuple, nested: bool) -> int:
    """Index after the block comment that starts at i."""
    start, stop = block
    depth, j = 1, i + len(start)
    while j < len(text):
        if nested and text.startswith(start, j):
            depth, j = depth + 1, j + len(start)
        elif text.startswith(stop, j):
            depth, j = depth - 1, j + len(stop)
            if depth == 0:
                return j
        else:
            j += 1
    return len(text)


# A character literal. In Rust and Scala a quote that does not start one is a
# lifetime, a label, or a symbol, and stays code.
CHAR_LITERAL = re.compile(
    r"'(?:[^'\\\n]|\\(?:x[0-9a-fA-F]{2}|u\{[0-9a-fA-F_]{1,8}\}|u+[0-9a-fA-F]{4}|.))'"
)
RUST_RAW = re.compile(r'[bc]?r(#*)"')
C_RAW = re.compile(r'(?:u8|[uUL])?R"([^ ()\\\t\n"]{0,16})\(')
CS_RAW = re.compile(r'(\$*)("{3,})')
CS_PREFIXED = re.compile(r'(\$@|@\$|@|\$)"')
# A PostgreSQL dollar tag follows identifier rules, so it may be non-ASCII.
SQL_DOLLAR = re.compile(r"\$([^\W\d]\w*)?\$")
SWIFT_RAW = re.compile(r'(#+)("""|"|/)')
PY_HOLE_PREFIXES = {"f", "rf", "fr", "t", "rt", "tr"}
# JSX may appear in every JS dialect except plain TypeScript, where '<T>x' is a
# type assertion.
JSX_SUFFIXES = JS_SUFFIXES - {".ts"}
JSX_NAME = r"(?:[^\W\d]|\$)[\w$.:-]*"
JSX_TAG = re.compile(rf"<({JSX_NAME})?")
JSX_ATTR = re.compile(JSX_NAME)
JSX_CLOSE = re.compile(rf"</\s*({JSX_NAME})?\s*>")
# Java translates Unicode escapes before it finds strings and comments.
JAVA_UNICODE = re.compile(r"\\u+([0-9a-fA-F]{4})")
# C splices lines and replaces trigraphs before it finds comments, so a splice
# after '/', '*', or '\\' may open or close a comment or escape a quote. Some
# compilers also splice a backslash, blanks, and a newline, or a bare CR.
C_SPLICE = re.compile(r"[/*\\]\\(?:\r\n?|\n)|\\[ \t\f\v]+(?:\r\n?|\n)|\?\?/")
# PostgreSQL dollar tags take non-ASCII bytes that Python \w does not cover.
SQL_UNICODE_TAG = re.compile(r"\$[0-9A-Za-z_\x80-\U0010ffff]*[\x80-\U0010ffff]")


def code_mask(text: str, suffix: str) -> list[bool]:
    """True where a character of a whole file is code, not string or comment.

    Strings with interpolation holes are masked whole, holes included; the
    holes are scanned only to find where the string really ends. A file with
    a construct whose lexing is uncertain is masked whole.
    """
    js, jsx = suffix in JS_SUFFIXES, suffix in JSX_SUFFIXES
    if suffix == ".java" and any(
        chr(int(m.group(1), 16)) in "\"'\\\n\r/*" for m in JAVA_UNICODE.finditer(text)
    ):
        return [False] * len(text)  # a quote or comment may hide in an escape
    if (suffix == ".c" and C_SPLICE.search(text)) or (
        suffix == ".sql" and SQL_UNICODE_TAG.search(text)
    ):
        return [False] * len(text)
    if suffix in HASH_COMMENT:
        line_comments, block = ("#",), None
    elif suffix == ".sql":
        line_comments, block = ("--",), ("/*", "*/")
    else:
        line_comments, block = ("//",), ("/*", "*/")
    # Rust and C# strings are treated conservatively as spanning lines until
    # their closing quote.
    spanning = {'"'} if suffix in {".rs", ".cs"} else set()
    if suffix == ".sql":
        spanning |= {"'", '"'}
    n = len(text)
    escape_end = -1  # end of the last SQL string that took backslash escapes
    unsure = False  # set when a construct cannot be lexed with confidence
    slash_holes = js or suffix == ".swift"

    def after_ident(k: int) -> bool:
        return k > 0 and (text[k - 1].isalnum() or text[k - 1] == "_")

    def hole_end(j: int, close: str = "}") -> int:
        """Index after an interpolation hole whose body starts at j."""
        nonlocal unsure
        opener = "(" if close == ")" else "{"
        depth = 1
        while j < n:
            # A '/' in a hole may start a regex literal or divide.
            if slash_holes and (
                (text[j] == "/" and not text.startswith(("//", "/*"), j))
                or (suffix == ".swift" and re.match(r"#+/", text[j : j + 9]))
            ):
                unsure = True
                return n
            end = skip(j)
            if end is not None:
                j = end
                continue
            if text[j] == opener:
                depth += 1
            elif text[j] == close:
                depth -= 1
                if depth == 0:
                    return j + 1
            j += 1
        return n

    def dollar_holes(j: int):
        return hole_end(j + 2) if text.startswith("${", j) else None

    def brace_holes(j: int):
        if text.startswith("{{", j) or text.startswith("}}", j):
            return j + 2
        return hole_end(j + 1) if text[j] == "{" else None

    def paren_holes(j: int):
        return hole_end(j + 2, ")") if text.startswith("\\(", j) else None

    def py_holes(raw: bool):
        def holes(j: int):
            if text[j] != "\\":
                return brace_holes(j)
            if not raw and text.startswith("\\N{", j):
                end = text.find("}", j)
                return n if end < 0 else end + 1
            # A backslash does not escape a brace in an f-string.
            return j + 1 if text.startswith("\\{", j) else None

        return holes

    def raw_brace_holes(width: int):
        # In a C# raw string, a run of fewer braces than its $ count is text.
        def holes(j: int):
            run = j
            while run < n and text[run] == "{":
                run += 1
            if run == j:
                return None
            return hole_end(run) if run - j >= width else run

        return holes

    def jsx_hole(j: int, code) -> int:
        end = hole_end(j + 1)
        if code is not None:
            code.append((j + 1, end - 1))
        return end

    def jsx_end(i: int, code=None):
        """Index after the JSX element at i, or None if it is not one.

        The holes of the element are code; their ranges go to code.
        """
        tag = JSX_TAG.match(text, i)
        name, j = tag.group(1) or "", tag.end()
        if name and text.startswith("<", j):  # type arguments: <Box<string>>
            depth = 0
            while j < n:
                depth += {"<": 1, ">": -1}.get(text[j], 0)
                j += 1
                if depth == 0:
                    break
        while True:  # attributes; their strings take no escapes
            while j < n and text[j].isspace():
                j += 1
            if j >= n:
                return None
            if text.startswith("/>", j):
                return j + 2 if name else None
            if text[j] == ">":
                j += 1
                break
            if not name:
                return None
            if text[j] == "{":
                j = jsx_hole(j, code)
                continue
            attr = JSX_ATTR.match(text, j)
            if not attr:
                return None
            j = attr.end()
            while j < n and text[j].isspace():
                j += 1
            if not text.startswith("=", j):
                continue
            j += 1
            while j < n and text[j].isspace():
                j += 1
            if j < n and text[j] in "'\"":
                end = text.find(text[j], j + 1)
                if end < 0:
                    return None
                j = end + 1
            elif j < n and text[j] == "{":
                j = jsx_hole(j, code)
            elif j < n and text[j] == "<" and (end := jsx_end(j, code)) is not None:
                j = end
            else:
                return None
        while j < n:  # children are text, elements, and holes
            if text.startswith("</", j):
                close = JSX_CLOSE.match(text, j)
                if close and (close.group(1) or "") == name:
                    return close.end()
                return None
            if text[j] == "<":
                end = jsx_end(j, code)
                if end is None:
                    return None
                j = end
            elif text[j] == "{":
                j = jsx_hole(j, code)
            else:
                j += 1
        return None

    def scala_holes(j: int):
        if text.startswith("$$", j) or text.startswith('$"', j):
            return j + 2
        return dollar_holes(j)

    def string_end(j, close, escapes=True, spans=True, holes=None, doubled=False,
                   escape="\\"):  # fmt: skip
        """Index after a string whose body starts at j and ends at close."""
        while j < n:
            if doubled and text.startswith(close * 2, j):
                j += 2 * len(close)
                continue
            if text.startswith(close, j):
                return j + len(close)
            if not spans and text[j] == "\n":
                return j + 1
            end = holes(j) if holes else None
            if end is not None:
                j = end
                continue
            if escapes and text.startswith(escape, j):
                crlf = text.startswith("\r\n", j + len(escape))
                j += len(escape) + (2 if crlf else 1)
                continue
            j += 1
        return n

    def extra_quotes(j: int) -> int:
        # A Kotlin or Scala raw string ends at the last quote of a run.
        while j < n and text[j] == '"':
            j += 1
        return j

    def skip(i: int, code=None):
        """Index after the string, comment, or JSX that starts at i, or None.

        The code ranges of the holes of a JSX element go to code.
        """
        nonlocal escape_end, unsure
        if any(text.startswith(c, i) for c in line_comments):
            end = text.find("\n", i)
            # A C line comment continues past a backslash-newline splice.
            while suffix == ".c" and end > i:
                k = end - 1 - (text[end - 1] == "\r")
                if text[k] != "\\":
                    break
                end = text.find("\n", end + 1)
            return n if end < 0 else end
        if block and text.startswith(block[0], i):
            return block_comment_end(text, i, block, suffix in NESTED_COMMENTS)
        ch, word = text[i], not after_ident(i)
        triple = text.startswith('"""', i)
        if suffix == ".rs" and word and (raw := RUST_RAW.match(text, i)):
            close = '"' + raw.group(1)
            end = text.find(close, raw.end())
            return n if end < 0 else end + len(close)
        if suffix == ".c" and word and (raw := C_RAW.match(text, i)):
            close = ")" + raw.group(1) + '"'
            end = text.find(close, raw.end())
            return n if end < 0 else end + len(close)
        if suffix in {".rs", ".scala"} and ch == "'":
            char = CHAR_LITERAL.match(text, i)
            return char.end() if char else None
        if suffix == ".sql" and word:
            dollar = SQL_DOLLAR.match(text, i)
            if dollar:
                end = text.find(dollar.group(0), dollar.end())
                return n if end < 0 else end + len(dollar.group(0))
        if suffix == ".go" and ch == "`":
            return string_end(i + 1, "`", escapes=False)
        if js and ch == "`":
            return string_end(i + 1, "`", holes=dollar_holes)
        if suffix == ".py" and ch in "'\"":
            k = i
            while k > 0 and i - k < 2 and text[k - 1].isalpha():
                k -= 1
            prefix = "" if after_ident(k) else text[k:i].lower()
            close = ch * 3 if text.startswith(ch * 3, i) else ch
            holes = py_holes("r" in prefix) if prefix in PY_HOLE_PREFIXES else None
            return string_end(i + len(close), close, spans=len(close) == 3, holes=holes)
        if suffix == ".kt" and ch == '"':
            if triple:
                end = string_end(i + 3, '"""', escapes=False, holes=dollar_holes)
                return extra_quotes(end)
            return string_end(i + 1, '"', spans=False, holes=dollar_holes)
        if suffix == ".scala" and ch == '"':
            k = i
            while k > 0 and (text[k - 1].isalnum() or text[k - 1] == "_"):
                k -= 1
            interpolated = k < i and not text[k].isdigit()
            holes = scala_holes if interpolated else None
            if triple:
                end = string_end(i + 3, '"""', escapes=False, holes=holes)
                return extra_quotes(end)
            end = string_end(i + 1, '"', spans=False, holes=holes)
            # Whether a backslash escapes a quote in an interpolated string
            # depends on the Scala version.
            if interpolated and "\\" in text[i:end]:
                unsure = True
            return end
        if suffix == ".swift" and word and (raw := SWIFT_RAW.match(text, i)):
            hashes, opener = raw.groups()
            if opener == "/":  # #/regex/#
                return string_end(raw.end(), "/" + hashes)
            escape = "\\" + hashes

            def raw_holes(j: int):
                if text.startswith(escape + "(", j):
                    return hole_end(j + len(escape) + 1, ")")
                return None

            return string_end(raw.end(), opener + hashes, holes=raw_holes,
                              escape=escape)  # fmt: skip
        if suffix == ".swift" and ch == '"':
            close = '"""' if triple else '"'
            return string_end(i + len(close), close, spans=triple, holes=paren_holes)
        if suffix == ".java" and triple:
            return string_end(i + 3, '"""')
        if suffix == ".cs" and (raw := CS_RAW.match(text, i)):
            dollars, close = raw.groups()
            holes = raw_brace_holes(len(dollars)) if dollars else None
            return string_end(raw.end(), close, escapes=False, holes=holes)
        if suffix == ".cs" and (prefixed := CS_PREFIXED.match(text, i)):
            kind = prefixed.group(1)
            verbatim = "@" in kind
            holes = brace_holes if "$" in kind else None
            return string_end(prefixed.end(), '"', escapes=not verbatim,
                              holes=holes, doubled=verbatim)  # fmt: skip
        if jsx and ch == "<":
            found = [] if code is not None else None
            end = jsx_end(i, found)
            expected = regex_start(text, i)
            k = i - 1
            while k >= 0 and text[k] in " \t\r\n":
                k -= 1
            # After a name or a closing bracket, '<' compares or opens type
            # arguments.
            operand = k >= 0 and (text[k].isalnum() or text[k] in "_$)]")
            looks = re.match(r"<(?:>|[^\W\d]|\$|[^\x00-\x7f])", text[i : i + 2])
            # JSX where it is not expected, or something that looks like JSX
            # that does not parse, is uncertain.
            if (end is not None and not expected) or (
                end is None and looks and (expected or not operand)
            ):
                unsure = True
                return n
            if end is not None:
                if code is not None:
                    code.extend(found)
                return end
        if slash_holes and ch == "/":
            # Whether this '/' starts a regex or divides decides how quotes
            # up to the last '/' on the line are read.
            stop = text.find("\n", i)
            rest = text[i + 1 : n if stop < 0 else stop]
            if re.search(r"['\"`]|/\*", rest[: max(rest.rfind("/"), 0)]):
                unsure = True
                return n
        if js and ch == "/" and regex_start(text, i):
            j = i + 1
            in_class = False
            while j < n and text[j] != "\n":
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == "[":
                    in_class = True
                elif text[j] == "]":
                    in_class = False
                elif text[j] == "/" and not in_class:
                    break
                j += 1
            return j + 1
        if ch in "'\"":
            # Standard SQL strings take a backslash literally; E'...' escapes.
            # A string right after an E string, or after only whitespace and
            # -- comments with a newline, continues it (PostgreSQL).
            gap = "x"
            if escape_end >= 0:
                gap = re.sub(r"--[^\n]*", "", text[escape_end:i])
            continued = gap == "" or (not gap.strip() and "\n" in gap)
            escapes = (
                suffix != ".sql"
                or (ch == "'" and continued)
                or (
                    i > 0
                    and text[i - 1] in "eE"
                    and not (i > 1 and (text[i - 2].isalnum() or text[i - 2] == "_"))
                )
            )
            end = string_end(i + 1, ch, escapes=escapes, spans=ch in spanning)
            escape_end = end if suffix == ".sql" and ch == "'" and escapes else -1
            return end
        return None

    mask = [False] * n

    def scan(i: int, stop: int) -> None:
        while i < stop:
            holes: list = []
            end = skip(i, holes)
            if end is None:
                mask[i] = True
                i += 1
                continue
            for start, close in holes:
                scan(start, close)
            i = max(end, i + 1)

    scan(0, n)
    return [False] * n if unsure else mask


def mutation_candidates(path: str, source: str, linenos: set[int], exclude: list[str]):
    """Mutations of code on the given 1-based lines of a whole file."""
    suffix = Path(path).suffix
    if suffix not in CODE_SUFFIXES or TEST_PATH.search(path):
        return []
    if any(re.search(p, path) for p in exclude):
        return []
    mask = code_mask(source, suffix)
    slash_regex = suffix in JS_SUFFIXES or suffix == ".swift"
    out, offset = [], 0
    for lineno, line in enumerate(source.splitlines(keepends=True), 1):
        text = line.rstrip("\r\n")
        code_slash = any(ch == "/" and mask[offset + i] for i, ch in enumerate(text))
        # A JS or Swift '/' may start a regex literal the mask cannot see; skip
        # the line.
        if lineno in linenos and not (slash_regex and code_slash):
            for pattern, repl in MUTATIONS:
                for m in re.finditer(pattern, text):
                    if all(mask[offset + m.start() : offset + m.end()]):
                        mutated = text[: m.start()] + repl + text[m.end() :]
                        label = f"{pattern} -> {repl}"
                        out.append((path, lineno, text, mutated, label))
        offset += len(line)
    return out


def verify_run(repo: Path, rev: str, args) -> dict:
    """Run the project tests on one revision in its own fresh worktree."""
    with Worktree(repo, rev, args.copy) as wt:
        report = wt.path / args.verify_junit
        if report.exists():
            report.unlink()
        run = wt.run(args.verify_cmd, args.timeout)
        cases = junit_cases(report)
    return {
        "exit_code": run["exit_code"],
        "cases": cases or {},
        "sandboxed": run["sandboxed"],
    }


def canary_seed(args: argparse.Namespace) -> int:
    repo = Path(args.repo).resolve()
    if bool(args.verify_cmd) != bool(args.verify_junit):
        raise GateError("--verify-cmd and --verify-junit go together")
    head = git(repo, "rev-parse", "--verify", f"{args.commit}^{{commit}}")
    head = head.stdout.decode().strip()
    base = git(repo, "rev-parse", f"{head}^").stdout.decode().strip()
    added: dict[str, set[int]] = {}
    for path, lineno, _ in added_lines(repo, base, head):
        added.setdefault(path, set()).add(lineno)
    candidates = []
    for path, linenos in sorted(added.items()):
        shown = git(repo, "show", f"{head}:{path}", check=False)
        if shown.returncode == 0:
            source = shown.stdout.decode(errors="replace")
            candidates += mutation_candidates(path, source, linenos, args.exclude)
    if not candidates:
        raise GateError("no mutable added code line in the commit")
    path, lineno, text, mutated, mutation = random.Random(args.seed).choice(candidates)
    fmt = "%an%x00%ae%x00%aI%x00%cn%x00%ce%x00%cI%x00%B"
    meta = git(repo, "log", "-1", f"--format={fmt}", head).stdout.decode()
    an, ae, ad, cn, ce, cd, msg = meta.split("\0", 6)
    env = {
        "GIT_AUTHOR_NAME": an,
        "GIT_AUTHOR_EMAIL": ae,
        "GIT_AUTHOR_DATE": ad,
        "GIT_COMMITTER_NAME": cn,
        "GIT_COMMITTER_EMAIL": ce,
        "GIT_COMMITTER_DATE": cd,
    }
    try:
        lines = git(repo, "show", f"{head}:{path}").stdout.decode()
    except UnicodeDecodeError as exc:
        raise GateError(f"{path} is not UTF-8") from exc
    lines = lines.splitlines(keepends=True)
    if lines[lineno - 1].rstrip("\r\n") != text:
        raise GateError(f"line drift at {path}:{lineno}")
    lines[lineno - 1] = mutated + lines[lineno - 1][len(text) :]
    blob = git(repo, "hash-object", "-w", "--no-filters", "--stdin",
               data="".join(lines).encode()).stdout.decode().strip()  # fmt: skip
    mode = git(repo, "ls-tree", head, "--", path).stdout.decode().split()[0]
    with tempfile.TemporaryDirectory() as tmp:
        index = Path(tmp) / "index"
        git(repo, "read-tree", head, index=index)
        git(repo, "update-index", "--cacheinfo", f"{mode},{blob},{path}",
            index=index)  # fmt: skip
        tree = git(repo, "write-tree", index=index).stdout.decode().strip()
    message = msg.strip().encode() or b"change"
    seeded = git(repo, "commit-tree", tree, "-p", base, env=env, data=message)
    seeded = seeded.stdout.decode().strip()
    # Only a seed that turns a passing project test case into a non-load failure,
    # each run in a fresh worktree, is a proven behavioral defect.
    verified, detected = False, []
    if args.verify_cmd:
        baseline = verify_run(repo, head, args)
        mutated_run = verify_run(repo, seeded, args)
        clean = (
            baseline["sandboxed"]
            and mutated_run["sandboxed"]
            and baseline["exit_code"] == 0
            and baseline["cases"]
            and all(s in ("pass", "skipped") for s in baseline["cases"].values())
        )
        detected = proof_cases(baseline, mutated_run) if clean else []
        verified = bool(detected)
    canary_id = sha256(f"{seeded}{now()}".encode())[:12]
    ledger_append(
        {
            "kind": "seed",
            "canary_id": canary_id,
            "created_at": now(),
            "repo": repo.name,
            "source_commit": head,
            "seeded_commit": seeded,
            "location": f"{path}:{lineno}",
            "mutation": mutation,
            "detected_by": detected,
            "behavior_verified": verified,
        }
    )
    print(
        json.dumps(
            {
                "canary_id": canary_id,
                "review_commit": seeded,
                "review_base": base,
                "behavior_verified": verified,
                "note": "Send review_base..review_commit to a fresh reviewer "
                "as an ordinary review. Do not mention the canary.",
            },
            indent=2,
        )
    )
    return 0


def score_key(r: dict) -> tuple:
    return (r["canary_id"], r["role"], r["model"])


def canary_score(args: argparse.Namespace) -> int:
    rows = ledger_rows()
    seeds = {r["canary_id"]: r for r in rows if r.get("kind") == "seed"}
    if args.canary_id not in seeds:
        raise GateError(f"unknown canary id: {args.canary_id}")
    entry = {
        "kind": "score",
        "canary_id": args.canary_id,
        "created_at": now(),
        "role": args.role,
        "model": args.model,
        "caught": args.caught == "yes",
        "other_findings": args.other_findings,
        "false_positives": args.false_positives,
    }
    scores = [r for r in rows if r.get("kind") == "score"]
    if any(score_key(r) == score_key(entry) for r in scores) and not args.supersede:
        raise GateError("this canary/role/model is already scored; use --supersede")
    ledger_append(entry)
    location = seeds[args.canary_id]["location"]
    print(json.dumps({"recorded": args.canary_id, "location": location}))
    return 0


def canary_report(args: argparse.Namespace) -> int:
    rows = ledger_rows()
    seeds = {r["canary_id"]: r for r in rows if r.get("kind") == "seed"}
    latest: dict[tuple, dict] = {}
    for r in rows:
        if r.get("kind") == "score":
            latest[score_key(r)] = r
    report: dict[str, dict] = {"verified": {}, "unverified": {}}
    for r in latest.values():
        tier = (
            "verified"
            if seeds.get(r["canary_id"], {}).get("behavior_verified")
            else "unverified"
        )
        g = report[tier].setdefault(
            f"{r['role']} / {r['model']}",
            {"runs": 0, "caught": 0, "false_positives": 0},
        )
        g["runs"] += 1
        g["caught"] += int(r["caught"])
        g["false_positives"] += int(r.get("false_positives") or 0)
    for tier in report.values():
        for g in tier.values():
            g["catch_rate"] = round(g["caught"] / g["runs"], 3)
    unscored = sorted(set(seeds) - {k[0] for k in latest})
    out = {"ledger": str(LEDGER), **report, "unscored": unscored}
    print(json.dumps(out, indent=2))
    return 0


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="command", required=True)

    rc = sub.add_parser("revert-check", help="fail-without-fix / pass-with-fix proof")
    rc.add_argument("--repo", default=".")
    rc.add_argument("--commit", help="fix commit; omit to use uncommitted changes")
    rc.add_argument("--finding", required=True, help="finding id this proof closes")
    rc.add_argument("--out", help="write evidence JSON here")
    rc.set_defaults(func=revert_check)

    ck = sub.add_parser("check", help="BLOCK closure gate")
    ck.add_argument("findings", help="findings JSON file")
    ck.add_argument("--repo", help="repository used to replay fixed-BLOCK evidence")
    ck.add_argument(
        "--reviewer-record",
        action="append",
        default=[],
        help="extra judgment record beyond those found by task id",
    )
    ck.add_argument(
        "--jobs", type=int, help="parallel replays (default: half the CPUs)"
    )
    ck.set_defaults(func=check)

    cl = sub.add_parser("close", help="human-only: sign the task's review summary")
    cl.add_argument("findings")
    cl.add_argument("--repo", help="repository used to replay fixed-BLOCK evidence")
    cl.add_argument("--reviewer-record", action="append", default=[])
    cl.add_argument(
        "--jobs", type=int, help="parallel replays (default: half the CPUs)"
    )
    cl.set_defaults(func=close)

    cn = sub.add_parser("canary", help="seeded-defect review measurement")
    cs = cn.add_subparsers(dest="canary_command", required=True)
    seed = cs.add_parser("seed")
    seed.add_argument("--repo", default=".")
    seed.add_argument("--commit", required=True)
    seed.add_argument("--seed", type=int)
    seed.add_argument("--exclude", action="append", default=[], help="path regex")
    seed.add_argument(
        "--verify-cmd", help="project tests; proves the seed is behavioral"
    )
    seed.add_argument("--verify-junit", help="JUnit report written by --verify-cmd")
    seed.add_argument("--copy", action="append", default=[])
    seed.add_argument("--timeout", type=int, default=900)
    seed.set_defaults(func=canary_seed)
    score = cs.add_parser("score")
    score.add_argument("canary_id")
    score.add_argument("--role", required=True)
    score.add_argument("--model", required=True)
    score.add_argument("--caught", choices=["yes", "no"], required=True)
    score.add_argument("--other-findings", type=int, default=0)
    score.add_argument("--false-positives", type=int, default=0)
    score.add_argument("--supersede", action="store_true")
    score.set_defaults(func=canary_score)
    rep = cs.add_parser("report")
    rep.set_defaults(func=canary_report)
    return p


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        return args.func(args)
    except GateError as exc:
        print(f"review-gate: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
