#!/usr/bin/env python3
"""PreToolUse guard: agents edit and commit only inside a linked git worktree.

Reads hook JSON on stdin. Blocks (exit 2) file edits (Claude Write/Edit/MultiEdit/
NotebookEdit, Codex apply_patch) and commit-creating shell commands (git commit,
cherry-pick, revert, am) whose target is the MAIN checkout of a git repo that has
at least one commit. Linked worktrees, non-git paths, empty repos, paths inside
.git/, and exempt repos are allowed. Any internal error fails open (exit 0).

Opt-out per repo: `git config harness.worktreeGuard false`, or list the repo
toplevel in config/worktree-guard-exempt.txt.
"""

import json
import os
import re
import shlex
import subprocess
import sys

EXEMPT_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), os.pardir, "config", "worktree-guard-exempt.txt"
)
# Linked worktrees each session touched; worktree-autocommit.py reads these.
SESSION_DIR = os.path.join(
    os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state"),
    "harness",
    "worktree-sessions",
)
SESSION_ID_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
GIT_TIMEOUT = 3

SHELL_TOOLS = {
    "bash",
    "shell",
    "shell_command",
    "exec_command",
    "functions.exec_command",
    "functions.exec",
    "exec",
    "run_shell_command",
    "terminal",
}
PATCH_TOOLS = {"apply_patch", "functions.apply_patch"}
EDIT_TOOLS = {"write", "edit", "multiedit", "notebookedit"}
COMMIT_CMDS = {"commit", "cherry-pick", "revert", "am"}
PATCH_RE = re.compile(
    r"^\*\*\* (?:Add File|Update File|Delete File|Move to):\s*(.+?)\s*$", re.M
)
SEP_CHARS = ";&|\n"

REASON = (
    "저장소 메인 체크아웃 `{top}` 은 보호됩니다. 여러 세션이 같은 체크아웃을 수정하면 충돌합니다. "
    "worktree 를 만들어 작업하세요: `wt -C {top} switch --create <branch> --no-cd` 후 "
    "`~/worktrees/{repo}/<branch>` 에서 수정/커밋하세요. 이 저장소만 해제하려면 "
    "`git config harness.worktreeGuard false`. / The main checkout `{top}` is protected: create a "
    "linked worktree with `wt -C {top} switch --create <branch> --no-cd` and work in "
    "`~/worktrees/{repo}/<branch>` (opt out: `git config harness.worktreeGuard false`)."
)


def git(cwd, *args):
    r = subprocess.run(
        ["git", "-C", cwd, *args],
        capture_output=True,
        text=True,
        timeout=GIT_TIMEOUT,
        env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"},
    )
    return r.returncode, r.stdout


def nearest_dir(path):
    p = os.path.abspath(path)
    while not os.path.isdir(p):
        parent = os.path.dirname(p)
        if parent == p:
            return None
        p = parent
    return p


def load_exempt():
    """Return (exact toplevels, prefixes). A line ending in `/**` exempts every repo under it."""
    exact, prefixes = set(), []
    try:
        with open(EXEMPT_FILE) as f:
            for line in f:
                line = line.split("#", 1)[0].strip()
                if line.endswith("/**"):
                    prefixes.append(
                        os.path.realpath(os.path.expanduser(line[:-3])) + os.sep
                    )
                elif line:
                    exact.add(os.path.realpath(os.path.expanduser(line)))
    except OSError:
        pass
    return exact, prefixes


def is_exempt(top):
    exact, prefixes = load_exempt()
    real = os.path.realpath(top)
    return real in exact or any(real.startswith(p) for p in prefixes)


def protected_toplevel(path):
    """Return the main-checkout toplevel if `path` is protected, else None."""
    if ".git" in os.path.abspath(path).split(os.sep):
        return None
    d = nearest_dir(path)
    if not d:
        return None
    rc, out = git(
        d, "rev-parse", "--show-toplevel", "--absolute-git-dir", "--git-common-dir"
    )
    lines = out.splitlines()
    if rc != 0 or len(lines) != 3:
        return None
    top, gitdir, common = lines
    if not os.path.isabs(common):
        common = os.path.join(d, common)
    if os.path.realpath(gitdir) != os.path.realpath(common):
        return None  # linked worktree
    if git(d, "rev-parse", "--verify", "-q", "HEAD")[0] != 0:
        return None  # no commits yet
    rc, val = git(top, "config", "--bool", "harness.worktreeGuard")
    if rc == 0 and val.strip() == "false":
        return None
    if is_exempt(top):
        return None
    return top


def linked_toplevel(path):
    """Return the toplevel if `path` sits in a linked (non-main) worktree, else None."""
    d = nearest_dir(path)
    if not d:
        return None
    rc, out = git(
        d, "rev-parse", "--show-toplevel", "--absolute-git-dir", "--git-common-dir"
    )
    lines = out.splitlines()
    if rc != 0 or len(lines) != 3:
        return None
    top, gitdir, common = lines
    if not os.path.isabs(common):
        common = os.path.join(d, common)
    if os.path.realpath(gitdir) == os.path.realpath(common):
        return None
    return os.path.realpath(top)


def record_session(session_id, tops):
    if not SESSION_ID_RE.match(session_id) or not tops:
        return
    path = os.path.join(SESSION_DIR, session_id + ".json")
    try:
        with open(path) as f:
            known = json.load(f)
        if not isinstance(known, list):
            known = []
    except (OSError, ValueError):
        known = []
    new = [t for t in tops if t not in known]
    if not new:
        return
    os.makedirs(SESSION_DIR, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(known + new, f)
    os.replace(tmp, path)


def resolve(path, cwd):
    p = os.path.expanduser(path)
    return p if os.path.isabs(p) else os.path.join(cwd, p)


def edit_targets(data, cwd):
    ti = data.get("tool_input") or data.get("input") or {}
    if isinstance(ti, str):
        ti = {"command": ti}
    paths = []
    for key in ("file_path", "notebook_path", "path"):
        if isinstance(ti.get(key), str) and ti[key]:
            paths.append(ti[key])
    # Codex apply_patch: patch text may sit in any string field (command/input/patch).
    for v in ti.values():
        if isinstance(v, list):
            v = "\n".join(str(x) for x in v)
        if isinstance(v, str) and "*** " in v:
            paths += PATCH_RE.findall(v)
    return [resolve(p, cwd) for p in paths]


def get_command(data):
    ti = data.get("tool_input") or data.get("input") or {}
    if isinstance(ti, str):
        return ti
    for key in ("command", "cmd", "script"):
        v = ti.get(key)
        if isinstance(v, list):
            return " ".join(str(x) for x in v)
        if isinstance(v, str):
            return v
    return ""


def split_segments(cmd):
    segs, buf, quote, i = [], [], None, 0
    while i < len(cmd):
        ch = cmd[i]
        if quote:
            buf.append(ch)
            if ch == "\\" and quote == '"' and i + 1 < len(cmd):
                i += 1
                buf.append(cmd[i])
            elif ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
            buf.append(ch)
        elif ch == "\\" and i + 1 < len(cmd):
            buf.append(ch)
            i += 1
            buf.append(cmd[i])
        elif ch in SEP_CHARS:
            segs.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
        i += 1
    segs.append("".join(buf))
    return [s for s in segs if s.strip()]


def commit_targets(cmd, cwd):
    """Directories in which a commit-creating git command would run."""
    out, cur = [], cwd
    for seg in split_segments(cmd):
        try:
            toks = shlex.split(seg, comments=False)
        except ValueError:
            toks = seg.split()
        while toks and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", toks[0]):
            toks.pop(0)
        if not toks:
            continue
        if toks[0] == "cd" and len(toks) >= 2:
            cur = resolve(toks[1], cur)
            continue
        if os.path.basename(toks[0]) != "git":
            continue
        target, i = cur, 1
        while i < len(toks) and toks[i].startswith("-"):
            if toks[i] == "-C" and i + 1 < len(toks):
                target = resolve(toks[i + 1], target)
                i += 2
            elif toks[i] in ("-c", "--git-dir", "--work-tree", "--namespace"):
                i += 2
            else:
                i += 1
        if i < len(toks) and toks[i] in COMMIT_CMDS:
            out.append(target)
    return out


def main():
    try:
        data = json.loads(sys.stdin.read() or "{}")
        if not isinstance(data, dict):
            return 0
        name = str(data.get("tool_name") or "").lower()
        cwd = str(data.get("cwd") or os.getcwd())
        if name in SHELL_TOOLS or name.endswith("bash"):
            targets = commit_targets(get_command(data), cwd)
        elif name in EDIT_TOOLS or name in PATCH_TOOLS:
            targets = edit_targets(data, cwd)
        else:
            return 0
        for t in targets:
            top = protected_toplevel(t)
            if top:
                print(
                    REASON.format(top=top, repo=os.path.basename(top)), file=sys.stderr
                )
                return 2
        session_id = str(data.get("session_id") or "")
        if session_id:
            try:
                tops = {linked_toplevel(t) for t in targets} - {None}
                record_session(session_id, sorted(tops))
            except Exception:
                pass
    except Exception:
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
