"""worktree-guard tests: run the hook as a subprocess against temp git repos."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

GUARD = str(Path(__file__).with_name("worktree-guard.py"))
# The hook runs through a wrapper that patches EXEMPT_FILE (no env var at runtime).
WRAPPER = (
    "import runpy, sys\n"
    "ns = runpy.run_path(sys.argv[1], run_name='guard')\n"
    "ns['main'].__globals__['EXEMPT_FILE'] = sys.argv[2]\n"
    "ns['main'].__globals__['SESSION_DIR'] = sys.argv[3]\n"
    "sys.exit(ns['main']())\n"
)
GIT_ENV = {
    **os.environ,
    "GIT_AUTHOR_NAME": "t",
    "GIT_AUTHOR_EMAIL": "t@t",
    "GIT_COMMITTER_NAME": "t",
    "GIT_COMMITTER_EMAIL": "t@t",
}


def sh(*args, cwd):
    subprocess.run(args, cwd=cwd, check=True, capture_output=True, env=GIT_ENV)


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = os.path.realpath(self.tmp.name)
        self.main = os.path.join(self.root, "main")
        self.linked = os.path.join(self.root, "linked")
        os.mkdir(self.main)
        sh("git", "init", "-q", cwd=self.main)
        Path(self.main, "a.txt").write_text("x")
        sh("git", "add", ".", cwd=self.main)
        sh("git", "commit", "-qm", "init", cwd=self.main)
        sh("git", "worktree", "add", "-q", "-b", "feat", self.linked, cwd=self.main)
        self.exempt = os.path.join(self.root, "exempt.txt")
        Path(self.exempt).write_text("")
        self.sessions = os.path.join(self.root, "sessions")

    def tearDown(self):
        self.tmp.cleanup()

    def run_guard(self, payload, raw=None):
        r = subprocess.run(
            [sys.executable, "-I", "-c", WRAPPER, GUARD, self.exempt, self.sessions],
            input=raw if raw is not None else json.dumps(payload),
            capture_output=True,
            text=True,
        )
        return r.returncode, r.stderr

    def tool(self, name, **ti):
        return {"tool_name": name, "cwd": self.main, "tool_input": ti}

    def blocked(self, payload):
        code, err = self.run_guard(payload)
        self.assertEqual(code, 2, payload)
        self.assertIn("wt -C", err)

    def allowed(self, payload):
        self.assertEqual(self.run_guard(payload)[0], 0, payload)

    def test_edit_main_blocked(self):
        self.blocked(self.tool("Edit", file_path=os.path.join(self.main, "a.txt")))
        self.blocked(self.tool("Write", file_path=os.path.join(self.main, "new/b.txt")))
        self.blocked(
            self.tool("NotebookEdit", notebook_path=os.path.join(self.main, "n.ipynb"))
        )

    def test_relative_path_uses_cwd(self):
        self.blocked(self.tool("Edit", file_path="a.txt"))

    def test_edit_linked_allowed(self):
        self.allowed(self.tool("Edit", file_path=os.path.join(self.linked, "a.txt")))

    def test_non_git_allowed(self):
        d = os.path.join(self.root, "plain")
        os.mkdir(d)
        self.allowed(self.tool("Write", file_path=os.path.join(d, "x.txt")))

    def test_empty_repo_allowed(self):
        d = os.path.join(self.root, "empty")
        os.mkdir(d)
        sh("git", "init", "-q", cwd=d)
        self.allowed(self.tool("Write", file_path=os.path.join(d, "x.txt")))

    def test_dot_git_allowed(self):
        p = os.path.join(self.main, ".git", "info", "exclude")
        self.allowed(self.tool("Edit", file_path=p))

    def test_git_config_optout(self):
        sh("git", "config", "harness.worktreeGuard", "false", cwd=self.main)
        self.allowed(self.tool("Edit", file_path=os.path.join(self.main, "a.txt")))

    def test_records_linked_worktree_per_session(self):
        payload = self.tool("Edit", file_path=os.path.join(self.linked, "n.txt"))
        payload["session_id"] = "s-1"
        self.allowed(payload)
        self.allowed(payload)
        rec = json.loads(Path(self.sessions, "s-1.json").read_text())
        self.assertEqual(rec, [self.linked])
        bad = self.tool("Edit", file_path=os.path.join(self.linked, "n.txt"))
        bad["session_id"] = "../escape"
        self.allowed(bad)
        self.assertFalse(os.path.exists(os.path.join(self.root, "escape.json")))

    def test_exempt_file(self):
        Path(self.exempt).write_text("# c\n%s  # note\n" % self.main)
        self.allowed(self.tool("Edit", file_path=os.path.join(self.main, "a.txt")))

    def test_nested_repo_judged_by_own_toplevel(self):
        Path(self.exempt).write_text(self.main + "\n")
        nested = os.path.join(self.main, "nested")
        os.mkdir(nested)
        sh("git", "init", "-q", cwd=nested)
        Path(nested, "n.txt").write_text("n")
        sh("git", "add", ".", cwd=nested)
        sh("git", "commit", "-qm", "n", cwd=nested)
        self.blocked(self.tool("Edit", file_path=os.path.join(nested, "n.txt")))

    def test_exempt_prefix_covers_nested_repos(self):
        nested = os.path.join(self.main, "runs", "r1")
        os.makedirs(nested)
        sh("git", "init", "-q", cwd=nested)
        Path(nested, "n.txt").write_text("n")
        sh("git", "add", ".", cwd=nested)
        sh("git", "commit", "-qm", "n", cwd=nested)
        Path(self.exempt).write_text(os.path.join(self.main, "runs") + "/**\n")
        self.allowed(self.tool("Edit", file_path=os.path.join(nested, "n.txt")))
        self.blocked(self.tool("Edit", file_path=os.path.join(self.main, "a.txt")))

    def test_codex_apply_patch(self):
        patch = "*** Begin Patch\n*** Update File: a.txt\n@@\n-x\n+y\n*** End Patch\n"
        self.blocked(self.tool("apply_patch", command=patch))
        self.blocked(self.tool("functions.apply_patch", input=patch))
        add = (
            "*** Begin Patch\n*** Add File: %s/n.txt\n+z\n*** End Patch\n" % self.linked
        )
        self.allowed(self.tool("apply_patch", command=add))
        move = (
            "*** Begin Patch\n*** Update File: %s/a.txt\n*** Move to: %s/m.txt\n*** End Patch\n"
            % (self.linked, self.main)
        )
        self.blocked(self.tool("apply_patch", command=move))

    def test_bash_commit(self):
        self.blocked(self.tool("Bash", command="git commit -m x"))
        self.blocked(self.tool("Bash", command="git add -A && git commit -m x"))
        self.blocked(self.tool("Bash", command="git cherry-pick abc"))
        self.blocked(self.tool("exec_command", cmd="git revert HEAD"))
        self.blocked(self.tool("Bash", command="git -c user.name=x commit -m x"))

    def test_bash_target_dir(self):
        self.allowed(self.tool("Bash", command="git -C %s commit -m x" % self.linked))
        self.blocked(self.tool("Bash", command="git -C %s commit -m x" % self.main))
        p = self.tool("Bash", command="cd %s && git commit -m x" % self.main)
        p["cwd"] = self.linked
        self.blocked(p)
        p = self.tool("Bash", command="cd %s && git commit -m x" % self.linked)
        self.allowed(p)

    def test_bash_other_git_allowed(self):
        self.allowed(self.tool("Bash", command="git status"))
        self.allowed(self.tool("Bash", command="git merge feat"))
        self.allowed(self.tool("Bash", command="wt list"))
        self.allowed(self.tool("Bash", command="echo git commit"))

    def test_other_tools_and_bad_input(self):
        self.allowed(self.tool("Read", file_path=os.path.join(self.main, "a.txt")))
        self.assertEqual(self.run_guard(None, raw="{not json")[0], 0)
        self.assertEqual(self.run_guard(None, raw="")[0], 0)
        self.assertEqual(self.run_guard(None, raw="[1]")[0], 0)


if __name__ == "__main__":
    unittest.main()
