"""review_gate tests against throwaway git repositories."""

import base64
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "review_gate", Path(__file__).with_name("review_gate.py")
)
rg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rg)

BUGGY = "def limit(n):\n    return n < 10\n"
FIXED = "def limit(n):\n    return n <= 10\n"
# A tiny runner that writes JUnit XML, like vitest/pytest reporters do.
RUNNER = """\
import sys
sys.path.insert(0, '.')
cases = []
def case(name, fn):
    try:
        fn()
        cases.append((name, ''))
    except AssertionError:
        cases.append((name, '<failure type="AssertionError"/>'))
    except RuntimeError as exc:
        cases.append((name, f'<failure type="Error" message="{{exc}}"/>'))
    except AttributeError as exc:
        cases.append((name, f'<failure type="AttributeError" message="{{exc}}"/>'))
    except ValueError:
        cases.append((name, '<failure message="assert limit(10)"/>'))
    except ImportError as exc:
        cases.append((name, f'<failure type="ImportError" message="{{exc}}"/>'))
    except Exception:
        cases.append((name, '<error/>'))
{body}
with open('junit.xml', 'w') as fh:
    fh.write('<testsuite>')
    for name, child in cases:
        fh.write(f'<testcase classname="calc" name="{{name}}">{{child}}</testcase>')
    fh.write('</testsuite>')
sys.exit(1 if any(child for _, child in cases) else 0)
"""
LIMIT_BODY = """\
def t_limit():
    from calc import limit
    assert limit(10)
case('test_limit', t_limit)
"""
TEST = RUNNER.format(body=LIMIT_BODY)
CMD = "python3 -I test_calc.py"
RECIPE = {"cmd": CMD, "junit": "junit.xml", "tests": ["test_*.py"]}
# The real signer, when built. Gate tests use VERIFY_STUB instead, so they do
# not depend on anything in HOME.
APPROVER = Path(
    os.environ.get(
        "REVIEW_GATE_TEST_APPROVER",
        Path.home() / ".local/state/review-gate-build/approver",
    )
)
OPENSSL = shutil.which("openssl")
VERIFY_STUB = f"""#!/bin/bash
# approver verify --pub P --message - --signature S, checked with openssl.
[[ $5 == - ]] || exit 3
sig=$(/usr/bin/mktemp)
printf %s "$7" | /usr/bin/base64 -d >"$sig"
{OPENSSL} dgst -sha256 -verify "$3" -signature "$sig" >/dev/null
status=$?
rm -f "$sig"
exit $status
"""
# approver sign/verify with an openssl key, for close tests without Touch ID.
# Like the real approver, both read the message from stdin (`--message -`).
SIGN_STUB = f"""#!/bin/bash
[[ $5 == - ]] || exit 3
if [[ $1 == sign ]]; then
  {OPENSSL} dgst -sha256 -sign {{key}} | /usr/bin/base64
  exit
fi
sig=$(/usr/bin/mktemp)
printf %s "$7" | /usr/bin/base64 -d >"$sig"
{OPENSSL} dgst -sha256 -verify "$3" -signature "$sig" >/dev/null
status=$?
rm -f "$sig"
exit $status
"""
# macOS cannot start a sandbox inside another one. When this suite itself runs
# under review-gate, the outer sandbox already confines writes, so the gate
# under test uses PASS_STUB in place of sandbox-exec.
PASS_STUB = """#!/bin/bash
[[ -n ${SANDBOX_LOG:-} ]] && printf '%s\\0' "$@" >"$SANDBOX_LOG"
shift 4
exec "$@"
"""
REAL_SANDBOX = Path("/usr/bin/sandbox-exec")
NESTED = (
    REAL_SANDBOX.is_file()
    and subprocess.run(
        [str(REAL_SANDBOX), "-p", "(version 1)(allow default)", "/usr/bin/true"],
        capture_output=True,
    ).returncode
    != 0
)


def sh(repo, *args):
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True
    ).stdout.strip()


def alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    # A zombie whose parent has not reaped it yet still counts as gone.
    state = subprocess.run(["/bin/ps", "-o", "stat=", "-p", str(pid)],
                           capture_output=True, text=True).stdout.strip()  # fmt: skip
    return bool(state) and not state.startswith("Z")


def run(argv):
    buf = StringIO()
    with redirect_stdout(buf), redirect_stderr(StringIO()):
        code = rg.main(argv)
    out = buf.getvalue()
    return code, json.loads(out) if out.strip().startswith("{") else out


class RepoCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        sh(self.repo, "init", "-q")
        sh(self.repo, "config", "user.email", "dev@example.com")
        sh(self.repo, "config", "user.name", "dev")
        (self.repo / ".gitignore").write_text("junit.xml\n.cache/\n")
        (self.repo / "calc.py").write_text(BUGGY)
        (self.repo / rg.RECIPE_FILE).write_text(json.dumps(RECIPE))
        sh(self.repo, "add", ".")
        sh(self.repo, "commit", "-qm", "base")
        rg.LEDGER = self.root / "ledger.jsonl"
        rg.TRUST_DIR = self.root / "trust"
        rg.APPROVER = self.stub("verify-stub", VERIFY_STUB)
        rg.APPROVER_KEY = self.root / "no-key"
        rg.PEER_RECORDS = self.root / "peer-records"
        rg.SANDBOX_EXEC = (
            self.stub("sandbox-stub", PASS_STUB) if NESTED else (REAL_SANDBOX)
        )

    def stub(self, name, body):
        path = self.root / name
        path.write_text(body)
        path.chmod(0o755)
        return path

    def tearDown(self):
        self.tmp.cleanup()

    def commit_fix(self, source=FIXED, test=TEST):
        (self.repo / "calc.py").write_text(source)
        (self.repo / "test_calc.py").write_text(test)
        sh(self.repo, "add", ".")
        sh(self.repo, "commit", "-qm", "fix limit")
        return sh(self.repo, "rev-parse", "HEAD")

    def recipe(self, **changes):
        (self.repo / rg.RECIPE_FILE).write_text(json.dumps({**RECIPE, **changes}))
        sh(self.repo, "commit", "-qam", "recipe")

    def revert(self, *extra, finding="B1"):
        out = self.root / f"{finding}.json"
        argv = ["revert-check", "--repo", str(self.repo), "--finding", finding,
                "--out", str(out), *extra]  # fmt: skip
        return run(argv)

    def worktrees(self):
        return len(sh(self.repo, "worktree", "list").splitlines())


class RevertCheckTest(RepoCase):
    def test_commit_fix_passes_when_case_fails_without_fix(self):
        head = self.commit_fix()
        code, out = self.revert("--commit", head)
        self.assertEqual(code, 0, out)
        self.assertEqual(out["proof_cases"], ["calc::test_limit"])
        self.assertEqual(out["reverted_paths"], ["calc.py"])
        self.assertEqual(self.worktrees(), 1)

    def test_test_that_passes_without_fix_fails_gate(self):
        (self.repo / "calc.py").write_text(FIXED)
        sh(self.repo, "commit", "-qam", "already fixed")
        head = self.commit_fix(source=FIXED + "# touch\n")
        code, out = self.revert("--commit", head)
        self.assertEqual(code, 1)

    def test_uncommitted_fix_and_untracked_test(self):
        (self.repo / "calc.py").write_text(FIXED)
        (self.repo / "test_calc.py").write_text(TEST)
        code, out = self.revert()
        self.assertEqual(code, 0, out)
        self.assertEqual(out["mode"], "working-tree")
        self.assertEqual((self.repo / "calc.py").read_text(), FIXED)

    def test_only_test_changes_is_rejected(self):
        (self.repo / "test_calc.py").write_text(TEST)
        sh(self.repo, "add", ".")
        sh(self.repo, "commit", "-qm", "tests only")
        self.assertEqual(self.revert("--commit", "HEAD")[0], 1)

    def test_b3_pathspec_matching_nothing_is_not_proof(self):
        self.recipe(tests=["not-a-test-*"])
        head = self.commit_fix()
        code, out = self.revert("--commit", head)
        self.assertEqual(code, 1)
        self.assertIn(
            "test pathspec matches no file in the base or the change", out["problems"]
        )

    def test_b3_error_inside_a_case_is_not_proof(self):
        (self.repo / "calc.py").write_text("def limit(n):\n    raise KeyError\n")
        sh(self.repo, "commit", "-qam", "raising version")
        head = self.commit_fix()
        code, out = self.revert("--commit", head)
        self.assertEqual(code, 1)
        self.assertEqual(out["fix_reverted"]["cases"], {"calc::test_limit": "error"})
        self.assertEqual(out["proof_cases"], [])

    def test_b3_crash_before_any_report_is_not_proof(self):
        test = "from calc import helper\n" + TEST
        source = FIXED + "def helper():\n    return 1\n"
        head = self.commit_fix(source=source, test=test)
        code, out = self.revert("--commit", head)
        self.assertEqual(code, 1)
        self.assertIn("no junit report in fix_reverted", out["problems"])

    def test_r3b3_import_error_reported_as_failure_is_not_proof(self):
        body = LIMIT_BODY.replace("import limit", "import limit, helper")
        source = FIXED + "def helper():\n    return 1\n"
        head = self.commit_fix(source=source, test=RUNNER.format(body=body))
        code, out = self.revert("--commit", head)
        self.assertEqual(code, 1)
        self.assertEqual(
            out["fix_reverted"]["cases"], {"calc::test_limit": "other-failure"}
        )

    def test_r4b2_exception_before_assertion_is_not_proof(self):
        buggy = "def limit(n):\n    raise RuntimeError('rejected')\n"
        (self.repo / "calc.py").write_text(buggy)
        sh(self.repo, "commit", "-qam", "raising version")
        head = self.commit_fix()
        code, out = self.revert("--commit", head)
        self.assertEqual(code, 1, out)
        self.assertEqual(
            out["fix_reverted"]["cases"], {"calc::test_limit": "other-failure"}
        )

    def test_r4b2_missing_attribute_is_not_proof(self):
        body = LIMIT_BODY.replace(
            "from calc import limit", "import calc; getattr(calc, 'helper')()"
        ).replace("assert limit(10)", "assert calc.limit(10)")
        source = FIXED + "def helper():\n    return 1\n"
        head = self.commit_fix(source=source, test=RUNNER.format(body=body))
        code, out = self.revert("--commit", head)
        self.assertEqual(code, 1, out)
        self.assertEqual(
            out["fix_reverted"]["cases"], {"calc::test_limit": "other-failure"}
        )

    def test_assertion_message_without_type_is_proof(self):
        # pytest-style reports carry the assertion in the message, not a type.
        body = (
            "def t_limit():\n"
            "    from calc import limit\n"
            "    if not limit(10):\n"
            "        raise ValueError\n"
            "case('test_limit', t_limit)\n"
        )
        head = self.commit_fix(test=RUNNER.format(body=body))
        code, out = self.revert("--commit", head)
        self.assertEqual(code, 0, out)
        self.assertEqual(out["fix_reverted"]["cases"], {"calc::test_limit": "failure"})

    def test_r5b3_bash_env_cannot_replace_the_recipe(self):
        hook = self.root / "hook.sh"
        hook.write_text(
            "grep -q 'touch' calc.py && echo '<testsuite><testcase classname=\"c\" "
            'name="t"/></testsuite>\' > junit.xml && exit 0\n'
            'echo \'<testsuite><testcase classname="c" name="t">'
            '<failure type="AssertionError"/></testcase></testsuite>\' > junit.xml\n'
            "exit 1\n"
        )
        (self.repo / "calc.py").write_text(FIXED)
        (self.repo / "test_calc.py").write_text(TEST)
        sh(self.repo, "add", ".")
        sh(self.repo, "commit", "-qm", "already fixed, with a real test")
        head = self.commit_fix(source=FIXED + "# touch\n")
        os.environ["BASH_ENV"] = str(hook)
        try:
            code, out = self.revert("--commit", head)
        finally:
            del os.environ["BASH_ENV"]
        self.assertEqual(code, 1, out)
        self.assertNotIn("c::t", out.get("proof_cases", []))

    def test_r5w2_existing_test_found_through_wildcard(self):
        (self.repo / "sub").mkdir()
        (self.repo / "sub" / "test_calc.py").write_text(
            TEST.replace("sys.path.insert(0, '.')", "sys.path.insert(0, '.')")
        )
        sh(self.repo, "add", ".")
        sh(self.repo, "commit", "-qm", "existing regression test")
        self.recipe(cmd="cp {tests} test_run.py && python3 -I test_run.py",
                    tests=["*test_calc.py"])  # fmt: skip
        (self.repo / "calc.py").write_text(FIXED)
        sh(self.repo, "commit", "-qam", "production-only fix")
        code, out = self.revert("--commit", "HEAD")
        self.assertEqual(out["base_tests"], ["sub/test_calc.py"])
        self.assertEqual(code, 0, out)

    def test_r5w3_refused_setup_leaves_no_worktree(self):
        shared = self.root / "shared"
        shared.mkdir()
        (self.repo / ".cache").mkdir()
        (self.repo / ".cache" / "store").symlink_to(shared)
        self.recipe(copy=[".cache"])
        head = self.commit_fix()
        self.assertEqual(self.revert("--commit", head)[0], 2)
        self.assertEqual(self.worktrees(), 1)

    def toggle_fix(self, path):
        """A comment-only change and a test that toggles state at path."""
        body = (
            "def t_state():\n"
            "    import os\n"
            f"    p = os.path.expandvars(os.path.expanduser({path!r}))\n"
            "    old = open(p).read() if os.path.exists(p) else '0'\n"
            "    os.makedirs(os.path.dirname(p), exist_ok=True)\n"
            "    open(p, 'w').write('1' if old == '0' else '0')\n"
            "    assert old == '0'\n"
            "case('test_state', t_state)\n"
        )
        return self.commit_fix(source=BUGGY + "# comment only\n",
                               test=RUNNER.format(body=body))  # fmt: skip

    def with_env(self, **values):
        saved = {k: os.environ.get(k) for k in values}
        os.environ.update(values)

        def restore():
            for k, v in saved.items():
                os.environ.pop(k) if v is None else os.environ.__setitem__(k, v)

        self.addCleanup(restore)

    def test_r10b1_caller_path_cannot_replace_the_interpreter(self):
        (self.repo / "calc.py").write_text(FIXED)
        (self.repo / "test_calc.py").write_text(TEST)
        sh(self.repo, "add", ".")
        sh(self.repo, "commit", "-qm", "already fixed, with a real test")
        head = self.commit_fix(source=FIXED + "# touch\n")
        fake = self.root / "fakebin"
        fake.mkdir()
        case = '<testcase classname="calc" name="test_limit"'
        (fake / "python3").write_text(
            "#!/bin/bash\n"
            f"grep -q touch calc.py && echo '<testsuite>{case}/></testsuite>' "
            "> junit.xml && exit 0\n"
            f'echo \'<testsuite>{case}><failure type="AssertionError"/>'
            "</testcase></testsuite>' > junit.xml\nexit 1\n"
        )
        (fake / "python3").chmod(0o755)
        self.with_env(PATH=f"{fake}:{os.environ['PATH']}")
        code, out = self.revert("--commit", head)
        self.assertEqual(code, 1, out)
        self.assertNotIn("calc::test_limit", out.get("proof_cases", []))
        self.assertEqual(out["fix_reverted"]["exit_code"], 0)

    def test_r10b1_command_path_is_pinned_or_fixed(self):
        self.assertEqual(rg.command_path(), rg.DEFAULT_PATH)
        rg.TRUST_DIR.mkdir()
        (rg.TRUST_DIR / "path").write_text("/opt/tools/bin:/usr/bin\n")
        self.assertEqual(rg.command_path(), "/opt/tools/bin:/usr/bin")
        self.assertTrue(any("path" in p for p in rg.trust_problems()))

    def test_r10b2_home_state_is_private_per_variant(self):
        home = self.root / "home"
        (home / ".cache").mkdir(parents=True)
        (home / ".cache" / "state").write_text("0")
        self.with_env(HOME=str(home))
        head = self.toggle_fix("~/.cache/state")
        code, out = self.revert("--commit", head)
        self.assertEqual(code, 1, out)
        self.assertEqual(out["fix_reverted"]["exit_code"], 0)
        self.assertEqual((home / ".cache" / "state").read_text(), "0")

    def test_r10b2_tmpdir_state_is_private_per_variant(self):
        tmp = self.root / "shared-tmp"
        tmp.mkdir()
        (tmp / "rg-state").write_text("0")
        self.with_env(TMPDIR=f"{tmp}/")
        head = self.toggle_fix("$TMPDIR/rg-state")
        code, out = self.revert("--commit", head)
        self.assertEqual(code, 1, out)
        self.assertEqual(out["fix_reverted"]["exit_code"], 0)
        self.assertEqual((tmp / "rg-state").read_text(), "0")

    def test_r10b2_commands_run_in_the_write_sandbox(self):
        log = self.root / "sandbox-args"
        rg.SANDBOX_EXEC = self.stub("sandbox-log-stub", PASS_STUB)
        self.with_env(SANDBOX_LOG=str(log))
        rg.CMD_ENV = (*rg.CMD_ENV, "SANDBOX_LOG")
        self.addCleanup(setattr, rg, "CMD_ENV", rg.CMD_ENV[:-1])
        code, out = self.revert("--commit", self.commit_fix())
        self.assertTrue(log.is_file(), "the test command did not run in the sandbox")
        args = log.read_text().split("\0")
        self.assertEqual(args[0], "-D")
        root = Path(args[1].removeprefix("ROOT="))
        self.assertTrue(root.name.startswith("review-gate-"), args[1])
        self.assertEqual(args[2], "-p")
        self.assertIn("(deny file-write*)", args[3])
        self.assertIn('(subpath (param "ROOT"))', args[3])
        self.assertIn("(deny network*)", args[3])
        self.assertEqual(code, 0, out)
        self.assertTrue(out["with_fix"]["sandboxed"])

    def test_r12b1_sandbox_denies_ipc_services_and_other_processes(self):
        log = self.root / "sandbox-args"
        rg.SANDBOX_EXEC = self.stub("sandbox-log-stub", PASS_STUB)
        self.with_env(SANDBOX_LOG=str(log))
        rg.CMD_ENV = (*rg.CMD_ENV, "SANDBOX_LOG")
        self.addCleanup(setattr, rg, "CMD_ENV", rg.CMD_ENV[:-1])
        code, out = self.revert("--commit", self.commit_fix())
        self.assertEqual(code, 0, out)
        profile = log.read_text().split("\0")[3]
        for rule in (
            "(deny ipc-posix* ipc-sysv* mach-lookup mach-register)",
            "(deny process-info*)",
            "(allow process-info* (target same-sandbox))",
            "(deny signal)",
            "(allow signal (target same-sandbox))",
            '(deny file-read* (regex #"/review-gate-[^/]+(/|$)"))',
        ):
            self.assertIn(rule, profile)
        self.assertNotIn('(subpath "/dev")', profile)
        self.assertTrue(out["with_fix"]["sandboxed"])

    def test_r14b1_sandbox_denies_outside_fifos_and_devices(self):
        log = self.root / "sandbox-args"
        rg.SANDBOX_EXEC = self.stub("sandbox-log-stub", PASS_STUB)
        self.with_env(SANDBOX_LOG=str(log))
        rg.CMD_ENV = (*rg.CMD_ENV, "SANDBOX_LOG")
        self.addCleanup(setattr, rg, "CMD_ENV", rg.CMD_ENV[:-1])
        code, out = self.revert("--commit", self.commit_fix())
        self.assertEqual(code, 0, out)
        profile = log.read_text().split("\0")[3]
        deny = ("(deny file-read* file-write* "
                "(vnode-type FIFO CHARACTER-DEVICE BLOCK-DEVICE TTY))")  # fmt: skip
        self.assertIn(deny, profile)
        # Filters in one rule are alternatives, so every path a later rule
        # allows must itself be safe to share.
        later = profile[profile.index(deny) + len(deny) :]
        allowed = set(re.findall(r'\((?:literal|subpath) ("[^"]*"|\(param "ROOT"\))\)',
                                 later))  # fmt: skip
        self.assertTrue(allowed)
        self.assertLessEqual(allowed, {
            '(param "ROOT")', '"/dev/fd"', '"/dev/null"', '"/dev/zero"',
            '"/dev/random"', '"/dev/urandom"', '"/dev/dtracehelper"',
        })  # fmt: skip
        self.assertNotIn("vnode-type", later)
        self.assertTrue(out["with_fix"]["sandboxed"])

    def test_r10b2_run_without_the_sandbox_is_not_proof(self):
        rg.SANDBOX_EXEC = self.root / "missing-sandbox-exec"
        code, out = self.revert("--commit", self.commit_fix())
        self.assertEqual(code, 1, out)
        self.assertIn("with_fix ran without the write sandbox", out["problems"])

    @unittest.skipIf(NESTED or not REAL_SANDBOX.is_file(), "needs a real sandbox")
    def test_r10b2_writes_outside_the_variant_are_denied(self):
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "state").write_text("0")
        code, out = self.revert("--commit", self.toggle_fix(str(outside / "state")))
        self.assertEqual(code, 1, out)
        self.assertEqual((outside / "state").read_text(), "0")
        self.assertNotIn("calc::test_state", out.get("proof_cases", []))

    def test_r9b1_linked_state_file_cannot_forge_proof(self):
        (self.repo / ".cache").mkdir()
        (self.repo / ".cache" / "state").write_text("0")
        self.recipe(link=[".cache/state"])
        code, out = self.revert("--commit", self.toggle_fix(".cache/state"))
        self.assertNotEqual(code, 0, out)
        self.assertFalse(isinstance(out, dict) and out.get("proof_cases"), out)
        self.assertEqual((self.repo / ".cache" / "state").read_text(), "0")

    def fake_bin(self, name, body):
        """Put a program named name first on the caller's PATH."""
        fake = self.root / "fakebin"
        fake.mkdir(exist_ok=True)
        (fake / name).write_text("#!/bin/bash\n" + body)
        (fake / name).chmod(0o755)
        self.with_env(PATH=f"{fake}:{os.environ['PATH']}")

    def test_r11_copy_helper_does_not_come_from_the_caller_path(self):
        marker = self.root / "fake-cp-ran"
        self.fake_bin("cp", f'touch {marker}\nexec /bin/cp "$@"\n')
        (self.repo / ".cache").mkdir()
        (self.repo / ".cache" / "state").write_text("0")
        self.recipe(copy=[".cache"])
        code, out = self.revert("--commit", self.commit_fix())
        self.assertEqual(code, 0, out)
        self.assertFalse(marker.exists(), "cp was taken from the caller's PATH")

    def test_r11_repo_config_cannot_run_code_outside_the_sandbox(self):
        (self.repo / ".gitattributes").write_text("*.py filter=evil\n")
        sh(self.repo, "add", ".gitattributes")
        sh(self.repo, "commit", "-qm", "attributes")
        head = self.commit_fix()
        # The same fix again, uncommitted, for the working-tree mode.
        sh(self.repo, "reset", "-q", "--hard", "HEAD~1")
        (self.repo / "calc.py").write_text(FIXED)
        (self.repo / "test_calc.py").write_text(TEST)
        ran = self.root / "ran"
        ran.mkdir()
        hook = self.repo / ".git" / "hooks" / "post-checkout"
        hook.write_text(f"#!/bin/sh\ntouch {ran}/hook\n")
        hook.chmod(0o755)
        for key, value in (
            ("filter.evil.clean", f"sh -c 'touch {ran}/clean; cat'"),
            ("filter.evil.smudge", f"sh -c 'touch {ran}/smudge; cat'"),
            ("core.fsmonitor", f"{ran}/fsmonitor-hook"),
            ("diff.external", f"sh -c 'touch {ran}/extdiff'"),
        ):
            sh(self.repo, "config", key, value)
        (ran / "fsmonitor-hook").write_text(f"#!/bin/sh\ntouch {ran}/fsmonitor\n")
        (ran / "fsmonitor-hook").chmod(0o755)
        code, out = self.revert("--commit", head)
        self.assertEqual(code, 0, out)
        code, out = self.revert()
        self.assertEqual(code, 0, out)
        self.assertEqual(sorted(p.name for p in ran.iterdir()), ["fsmonitor-hook"])

    @unittest.skipIf(NESTED or not REAL_SANDBOX.is_file(), "needs a real sandbox")
    def test_r11_loopback_service_cannot_share_state(self):
        import http.server
        import threading

        state = {"value": "0"}

        class Toggle(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                old = state["value"]
                state["value"] = "1" if old == "0" else "0"
                self.send_response(200)
                self.end_headers()
                self.wfile.write(old.encode())

            def log_message(self, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Toggle)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        port = server.server_address[1]
        body = (
            "def t_service():\n"
            "    import urllib.request\n"
            f"    url = 'http://127.0.0.1:{port}/toggle'\n"
            "    old = urllib.request.urlopen(url, timeout=5).read().decode()\n"
            "    assert old == '0'\n"
            "case('test_service', t_service)\n"
        )
        head = self.commit_fix(source=BUGGY + "# comment only\n",
                               test=RUNNER.format(body=body))  # fmt: skip
        code, out = self.revert("--commit", head)
        self.assertEqual(code, 1, out)
        self.assertNotIn("calc::test_service", out.get("proof_cases", []))
        self.assertEqual(state["value"], "0")

    def test_r11_leftover_process_is_killed(self):
        body = (
            "def t_spawn():\n"
            "    import subprocess\n"
            "    child = subprocess.Popen(['/bin/sleep', '120'],\n"
            "                             stdout=subprocess.DEVNULL,\n"
            "                             stderr=subprocess.DEVNULL)\n"
            "    print(f'CHILD={child.pid}', flush=True)\n"
            "case('test_spawn', t_spawn)\n"
        )
        (self.repo / "calc.py").write_text(FIXED)
        (self.repo / "test_calc.py").write_text(RUNNER.format(body=body))
        sh(self.repo, "add", ".")
        sh(self.repo, "commit", "-qm", "spawner")
        head = self.commit_fix(source=FIXED + "# touch\n",
                               test=RUNNER.format(body=body))  # fmt: skip
        _, out = self.revert("--commit", head)
        pids = [int(line.split("=", 1)[1])
                for run in ("with_fix", "fix_reverted")
                for line in out[run]["tail"].splitlines()
                if line.startswith("CHILD=")]  # fmt: skip
        self.assertEqual(len(pids), 2, out)
        for pid in pids:
            with self.assertRaises(ProcessLookupError, msg=f"pid {pid} survived"):
                os.kill(pid, 0)

    @unittest.skipIf(NESTED or not REAL_SANDBOX.is_file(), "needs a real sandbox")
    def test_r14b1_outside_fifo_cannot_share_state(self):
        outside = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, outside, True)
        fifo = outside / "state"
        os.mkfifo(fifo)
        keeper = os.open(fifo, os.O_RDWR | os.O_NONBLOCK)
        self.addCleanup(os.close, keeper)
        os.write(keeper, b"0101")
        body = (
            "def t_fifo():\n"
            "    import os\n"
            f"    fd = os.open({str(fifo)!r}, os.O_RDONLY | os.O_NONBLOCK)\n"
            "    assert os.read(fd, 1) == b'0'\n"
            "def t_inner_fifo():\n"
            "    import os\n"
            "    p = os.path.join(os.environ['TMPDIR'], 'inner')\n"
            "    os.mkfifo(p)\n"
            "    fd = os.open(p, os.O_RDWR | os.O_NONBLOCK)\n"
            "    os.write(fd, b'x')\n"
            "    assert os.read(fd, 1) == b'x'\n"
            "case('test_fifo', t_fifo)\n"
            "case('test_inner_fifo', t_inner_fifo)\n"
        )
        head = self.commit_fix(source=BUGGY + "# comment only\n",
                               test=RUNNER.format(body=body))  # fmt: skip
        for _ in range(2):
            code, out = self.revert("--commit", head)
            self.assertEqual(code, 1, out)
            self.assertNotIn("calc::test_fifo", out.get("proof_cases", []))
            self.assertEqual(out["with_fix"]["cases"]["calc::test_inner_fifo"], "pass")

    @unittest.skipIf(NESTED or not REAL_SANDBOX.is_file(), "needs a real sandbox")
    def test_r12b1_named_semaphore_cannot_share_state(self):
        import ctypes
        import uuid

        name = ("/rg" + uuid.uuid4().hex[:20]).encode()
        libc = ctypes.CDLL(None, use_errno=True)
        libc.sem_unlink.argtypes = [ctypes.c_char_p]
        self.addCleanup(libc.sem_unlink, name)
        body = (
            "def t_sem():\n"
            "    import ctypes, errno, os\n"
            "    lib = ctypes.CDLL(None, use_errno=True)\n"
            "    lib.sem_open.restype = ctypes.c_void_p\n"
            "    lib.sem_open.argtypes = [ctypes.c_char_p, ctypes.c_int]\n"
            "    lib.sem_trywait.argtypes = [ctypes.c_void_p]\n"
            "    lib.sem_post.argtypes = [ctypes.c_void_p]\n"
            f"    sem = lib.sem_open({name!r}, os.O_CREAT,\n"
            "                       ctypes.c_uint(0o600), ctypes.c_uint(1))\n"
            "    if sem in (None, ctypes.c_void_p(-1).value):\n"
            "        raise OSError(ctypes.get_errno(), 'sem_open')\n"
            "    got = lib.sem_trywait(sem)\n"
            "    if got != 0:\n"
            "        lib.sem_post(sem)\n"
            "    assert got == 0\n"
            "case('test_sem', t_sem)\n"
        )
        head = self.commit_fix(source=BUGGY + "# comment only\n",
                               test=RUNNER.format(body=body))  # fmt: skip
        for _ in range(2):
            code, out = self.revert("--commit", head)
            self.assertEqual(code, 1, out)
            self.assertNotIn("calc::test_sem", out.get("proof_cases", []))

    def test_r14b2_trust_anchor_link_into_a_user_directory_is_untrusted(self):
        from types import SimpleNamespace
        from unittest import mock

        tree = {
            "/": (0, 0o40755, None),
            "/anchor": (0, 0o40755, None),
            "/anchor/approver": (0, 0o120755, "/mutable/verify"),
            "/mutable": (501, 0o40755, None),
            "/mutable/verify": (0, 0o100755, None),
            "/usr": (0, 0o40755, None),
            "/usr/bin": (0, 0o40755, None),
            "/usr/bin/true": (0, 0o100755, None),
        }

        def fake_lstat(p):
            if str(p) not in tree:
                raise FileNotFoundError(2, "missing", str(p))
            uid, mode, _ = tree[str(p)]
            return SimpleNamespace(st_uid=uid, st_mode=mode, st_flags=0)

        def fake_resolve(p, *args, **kwargs):
            real = Path("/")
            for name in Path(p).parts[1:]:
                real = real / name
                while tree.get(str(real), (0, 0, None))[2]:
                    real = Path(tree[str(real)][2])
            return real

        def fake_stat(p, *args, **kwargs):
            return fake_lstat(fake_resolve(p))

        # One virtual filesystem for every way of looking at it, so the
        # result does not depend on which calls an implementation makes.
        anchor = Path("/anchor/approver")
        with mock.patch.object(rg.os, "lstat", fake_lstat), \
                mock.patch.object(rg.os, "stat", fake_stat), \
                mock.patch.object(rg.os, "readlink", lambda p: tree[str(p)][2]), \
                mock.patch.object(Path, "stat", fake_stat), \
                mock.patch.object(Path, "resolve", fake_resolve), \
                mock.patch.object(rg, "acl_write_grants", lambda p: []):  # fmt: skip
            bad = "/mutable is not root-owned and write-protected"
            self.assertIn(bad, rg.root_owned_problems(anchor))
            tree["/mutable/verify"] = (0, 0o120755, "/usr/bin/true")
            self.assertIn(bad, rg.root_owned_problems(anchor))
            tree["/mutable"] = (0, 0o40755, None)
            self.assertEqual(rg.root_owned_problems(anchor), [])

    def test_r13b1_user_owned_sticky_directory_is_not_protection(self):
        from types import SimpleNamespace
        from unittest import mock

        tree = {
            "/": (0, 0o40755),
            "/owned": (501, 0o41777),
            "/owned/bin": (0, 0o40755),
            "/owned/bin/python3": (0, 0o100755),
        }

        def fake_lstat(p):
            uid, mode = tree[str(p)]
            return SimpleNamespace(st_uid=uid, st_mode=mode, st_flags=0)

        with mock.patch.object(rg.os, "lstat", fake_lstat):
            problems = rg.protected_problems(Path("/owned/bin/python3"))
            self.assertIn("/owned/bin can be replaced: /owned is writable", problems)
            tree["/owned"] = (0, 0o41777)
            self.assertEqual(rg.protected_problems(Path("/owned/bin/python3")), [])

    def test_r13b2_acl_write_grants_are_writable(self):
        self.addCleanup(setattr, rg, "SYSTEM_UID_LIMIT", rg.SYSTEM_UID_LIMIT)
        rg.SYSTEM_UID_LIMIT = os.getuid() + 1
        bin_dir = self.root.resolve() / "acl-bin"
        bin_dir.mkdir()
        tool = bin_dir / "python3"
        tool.write_text("#!/bin/sh\n")
        tool.chmod(0o555)

        def acl(target, rule):
            subprocess.run(["/bin/chmod", "+a", rule, str(target)], check=True)

        try:
            acl(tool, "everyone deny delete")
            self.assertEqual(rg.pinned_dir_problems(bin_dir), [])
            acl(tool, "everyone allow write,append")
            self.assertEqual(tool.stat().st_mode & 0o777, 0o555)
            self.assertIn(f"{tool} is not system-owned and write-protected",
                          rg.pinned_dir_problems(bin_dir))  # fmt: skip
            subprocess.run(["/bin/chmod", "-N", str(tool)], check=True)
            acl(bin_dir, "everyone allow add_file,delete_child")
            self.assertIn(f"{tool} can be replaced: {bin_dir} is writable",
                          rg.pinned_dir_problems(bin_dir))  # fmt: skip
        finally:
            subprocess.run(["/bin/chmod", "-N", str(tool), str(bin_dir)])

    def test_r12b2_programs_in_pinned_dirs_are_checked(self):
        # Count this user as a system account, so only modes and link hops
        # decide; system directories are the positive control.
        self.addCleanup(setattr, rg, "SYSTEM_UID_LIMIT", rg.SYSTEM_UID_LIMIT)
        rg.SYSTEM_UID_LIMIT = os.getuid() + 1
        bin_dir = self.root.resolve() / "pinned"
        bin_dir.mkdir()
        (bin_dir / "ok").write_text("#!/bin/sh\n")
        (bin_dir / "ok").chmod(0o755)
        self.assertEqual(rg.pinned_dir_problems(bin_dir), [])
        (bin_dir / "python3").write_text("#!/bin/sh\n")
        (bin_dir / "python3").chmod(0o777)
        apps = self.root.resolve() / "apps"
        apps.mkdir()
        apps.chmod(0o777)
        (apps / "node").write_text("#!/bin/sh\n")
        (apps / "node").chmod(0o755)
        (bin_dir / "node").symlink_to(apps / "node")
        problems = rg.pinned_dir_problems(bin_dir)
        self.assertIn(
            f"{bin_dir / 'python3'} is not system-owned and write-protected", problems
        )
        self.assertTrue(any(f"{apps / 'node'} can be replaced" in p for p in problems),
                        problems)  # fmt: skip
        rg.TRUST_DIR.mkdir()
        (rg.TRUST_DIR / "path").write_text(f"{bin_dir}:/usr/bin\n")
        self.assertTrue(
            any(p.startswith("pinned PATH:") and "python3" in p
                for p in rg.trust_problems())
        )  # fmt: skip
        rg.SYSTEM_UID_LIMIT = 500
        for system in ("/usr/bin", "/bin", "/usr/sbin", "/sbin"):
            self.assertEqual(rg.pinned_dir_problems(Path(system)), [], system)

    @unittest.skipIf(NESTED, "the sweep needs a sandbox of its own")
    def test_r12w1_detached_descendant_is_killed_and_cannot_stall(self):
        import shlex
        import time

        payload = (
            "import subprocess; p = subprocess.Popen(['/bin/sleep', '30'], "
            "start_new_session=True); print(p.pid, flush=True)"
        )
        with rg.Worktree(self.repo, "HEAD") as wt:
            start = time.monotonic()
            result = wt.run("/usr/bin/python3 -I -c " + shlex.quote(payload), 60)
            elapsed = time.monotonic() - start
        pid = int(result["output"].split()[0])
        self.addCleanup(lambda: os.kill(pid, 9) if alive(pid) else None)
        self.assertLess(elapsed, 20, "a detached descendant stalled the run")
        self.assertFalse(alive(pid), f"detached pid {pid} survived")

    def test_r11_user_writable_pinned_path_is_untrusted(self):
        rg.TRUST_DIR.mkdir()
        (rg.TRUST_DIR / "path").write_text(f"{self.root}:/usr/bin\n")
        problems = rg.trust_problems()
        self.assertTrue(
            any(p.startswith("pinned PATH:") and str(self.root) in p for p in problems),
            problems,
        )
        (rg.TRUST_DIR / "path").write_text("/usr/bin:/bin\n")
        self.assertFalse(any(p.startswith("pinned PATH:") for p in rg.trust_problems()))

    def test_r9b1_link_recipe_is_refused(self):
        head = self.marker_fix(link=[".cache"])
        code, out = self.revert("--commit", head)
        self.assertEqual(code, 2, out)
        self.assertFalse((self.repo / ".cache" / "marker").exists())

    def test_r9b1_copied_file_state_is_isolated(self):
        (self.repo / ".cache").mkdir()
        (self.repo / ".cache" / "state").write_text("0")
        self.recipe(copy=[".cache/state"])
        body = (
            "def t_state():\n"
            "    old = open('.cache/state').read()\n"
            "    open('.cache/state', 'w').write('1' if old == '0' else '0')\n"
            "    assert old == '0'\n"
            "case('test_state', t_state)\n"
        )
        head = self.commit_fix(source=BUGGY + "# comment only\n",
                               test=RUNNER.format(body=body))  # fmt: skip
        code, out = self.revert("--commit", head)
        self.assertEqual(code, 1, out)
        self.assertEqual(out["fix_reverted"]["exit_code"], 0)
        self.assertEqual((self.repo / ".cache" / "state").read_text(), "0")

    def test_r7b1_absolute_link_inside_copied_state_is_refused(self):
        store = self.repo / ".cache" / "store"
        store.mkdir(parents=True)
        (self.repo / ".cache" / "alias").symlink_to(store.resolve())
        body = (
            "def t_marker():\n"
            "    import os\n"
            "    p = '.cache/alias/marker'\n"
            "    existed = os.path.exists(p)\n"
            "    os.remove(p) if existed else open(p, 'w').write('x')\n"
            "    assert not existed\n"
            "case('test_marker', t_marker)\n"
        )
        self.recipe(copy=[".cache"])
        head = self.commit_fix(source=BUGGY + "# comment only\n",
                               test=RUNNER.format(body=body))  # fmt: skip
        code, out = self.revert("--commit", head)
        self.assertEqual(code, 2, out)
        self.assertFalse((store / "marker").exists())
        self.assertEqual(self.worktrees(), 1)

    def test_r8b1_copy_path_that_is_a_committed_symlink_is_refused(self):
        store = self.root / "store"
        store.mkdir()
        (self.repo / ".gitignore").write_text("junit.xml\n")
        (self.repo / ".cache").symlink_to(store)
        sh(self.repo, "add", ".")
        sh(self.repo, "commit", "-qm", "cache link")
        body = (
            "def t_marker():\n"
            "    import os\n"
            "    p = '.cache/marker'\n"
            "    existed = os.path.exists(p)\n"
            "    os.remove(p) if existed else open(p, 'w').write('x')\n"
            "    assert not existed\n"
            "case('test_marker', t_marker)\n"
        )
        self.recipe(copy=[".cache"])
        head = self.commit_fix(source=BUGGY + "# comment only\n",
                               test=RUNNER.format(body=body))  # fmt: skip
        code, out = self.revert("--commit", head)
        self.assertEqual(code, 2, out)
        self.assertFalse((store / "marker").exists())
        self.assertEqual(self.worktrees(), 1)

    def test_r8b1_tracked_copy_path_and_linked_parent_are_refused(self):
        (self.repo / "state").mkdir()
        (self.repo / "state" / "keep").write_text("x")
        sh(self.repo, "add", ".")
        sh(self.repo, "commit", "-qm", "tracked state")
        self.recipe(copy=["state"])
        head = self.commit_fix()
        self.assertEqual(self.revert("--commit", head)[0], 2)
        outside = self.root / "outside"
        (outside / "inner").mkdir(parents=True)
        (self.repo / "vendor").symlink_to(outside)
        self.recipe(copy=["vendor/inner"])
        head = self.commit_fix(source=FIXED + "# again\n")
        self.assertEqual(self.revert("--commit", head)[0], 2)

    def test_relative_link_inside_copied_state_is_allowed(self):
        (self.repo / ".cache" / "store").mkdir(parents=True)
        (self.repo / ".cache" / "alias").symlink_to("store")
        self.recipe(copy=[".cache"])
        head = self.commit_fix()
        self.assertEqual(self.revert("--commit", head)[0], 0)

    def test_r3b4_empty_directory_in_copied_state_does_not_leak(self):
        (self.repo / ".cache").mkdir()
        self.recipe(copy=[".cache"])
        body = (
            "def t_marker():\n"
            "    import os\n"
            "    assert not os.path.isdir('.cache/marker')\n"
            "    os.mkdir('.cache/marker')\n"
            "case('test_marker', t_marker)\n"
        )
        head = self.commit_fix(source=BUGGY + "# comment only\n",
                               test=RUNNER.format(body=body))  # fmt: skip
        code, out = self.revert("--commit", head)
        self.assertEqual(code, 1, out)
        self.assertEqual(out["fix_reverted"]["exit_code"], 0)
        self.assertFalse((self.repo / ".cache" / "marker").exists())

    def test_r3b4_copy_with_escaping_symlink_is_refused(self):
        shared = self.root / "shared"
        shared.mkdir()
        (self.repo / ".cache").mkdir()
        (self.repo / ".cache" / "store").symlink_to(shared)
        self.recipe(copy=[".cache"])
        head = self.commit_fix()
        code, _ = self.revert("--commit", head)
        self.assertEqual(code, 2)

    def marker_fix(self, **recipe):
        (self.repo / ".cache").mkdir()
        self.recipe(**recipe)
        body = (
            "def t_marker():\n"
            "    import os\n"
            "    assert not os.path.exists('.cache/marker')\n"
            "    open('.cache/marker', 'w').write('x')\n"
            "case('test_marker', t_marker)\n"
        )
        return self.commit_fix(source=BUGGY + "# comment only\n",
                               test=RUNNER.format(body=body))  # fmt: skip

    def test_b4_copied_state_is_isolated_per_variant(self):
        head = self.marker_fix(copy=[".cache"])
        code, out = self.revert("--commit", head)
        self.assertEqual(code, 1, out)
        # Both isolated variants pass, so a comment-only change proves nothing.
        self.assertEqual(out["fix_reverted"]["exit_code"], 0)
        self.assertFalse((self.repo / ".cache" / "marker").exists())

    def test_recipe_comes_from_the_base_not_the_fix(self):
        (self.repo / "calc.py").write_text(FIXED)
        (self.repo / "test_calc.py").write_text(TEST)
        fake = {**RECIPE, "cmd": "echo '<testsuite/>' > junit.xml"}
        (self.repo / rg.RECIPE_FILE).write_text(json.dumps(fake))
        sh(self.repo, "add", ".")
        sh(self.repo, "commit", "-qm", "fix and swap recipe")
        code, out = self.revert("--commit", "HEAD")
        self.assertEqual(code, 0, out)
        self.assertEqual(out["cmd"], CMD)

    def test_missing_recipe_is_an_error(self):
        sh(self.repo, "rm", "-q", rg.RECIPE_FILE)
        sh(self.repo, "commit", "-qm", "drop recipe")
        head = self.commit_fix()
        self.assertEqual(self.revert("--commit", head)[0], 2)

    def test_tests_placeholder_lists_changed_tests(self):
        self.recipe(cmd="python3 -I {tests}")
        head = self.commit_fix()
        code, out = self.revert("--commit", head)
        self.assertEqual(code, 0, out)
        self.assertEqual(out["cmd"], "python3 -I test_calc.py")


class CheckTest(RepoCase):
    def findings(self, items, task="t1"):
        path = self.root / "findings.json"
        path.write_text(json.dumps({"task_id": task, "findings": items}))
        return str(path)

    def fixed_item(self, change, finding="B1"):
        return {"id": finding, "severity": "BLOCK", "status": "fixed",
                "change": change, "evidence": "B1.json",
                "proof_tests": ["calc::test_limit"]}  # fmt: skip

    def real_evidence(self):
        head = self.commit_fix()
        self.assertEqual(self.revert("--commit", head)[0], 0)
        return head

    def record(self, text=""):
        path = self.root / "reviewer-record.yaml"
        path.write_text(text)
        return str(path)

    def peer_record(self, task_id, findings, role="reviewer", name="r.yaml"):
        tasks = rg.PEER_RECORDS / "scope" / "agents" / role / "tasks"
        tasks.mkdir(parents=True, exist_ok=True)
        items = "".join(f'- "{f}"\n' for f in findings)
        (tasks / name).write_text(
            f"task_id: {task_id}\nfindings:\n{items}decisions:\n"
            '- "BLOCK X9-B9 is quoted here only as prose"\n'
        )

    def check(self, items, *extra, record=""):
        return run(["check", self.findings(items), "--repo", str(self.repo),
                    "--reviewer-record", self.record(record), *extra])  # fmt: skip

    def sign_close(self, items, record="", task="t1", signature=None):
        """Sign the close summary as the user would, with a test key."""
        self.findings(items, task)
        records = rg.record_blocks(task, [self.record(record)])
        message = rg.close_payload(task, items, records)
        if signature is None:
            trust = self.root / "trust"
            key = self.root / "k.ec"
            if not key.exists():
                trust.mkdir(exist_ok=True)
                subprocess.run([OPENSSL, "ecparam", "-name", "prime256v1",
                                "-genkey", "-noout", "-out", str(key)],
                               check=True)  # fmt: skip
                subprocess.run([OPENSSL, "ec", "-in", str(key), "-pubout", "-out",
                                str(trust / "approver.pub")], check=True,
                               capture_output=True)  # fmt: skip
            sig = subprocess.run([OPENSSL, "dgst", "-sha256", "-sign", str(key)],
                                 input=message, capture_output=True,
                                 check=True).stdout  # fmt: skip
            signature = base64.b64encode(sig).decode()
        out = rg.close_path(self.root, task)
        out.parent.mkdir(exist_ok=True)
        out.write_text(json.dumps({**json.loads(message), "signature": signature}))

    def test_open_block_fails(self):
        code, _ = self.check([{"id": "B1", "severity": "BLOCK", "status": "open"}])
        self.assertEqual(code, 1)

    def test_bound_real_evidence_still_needs_the_users_close(self):
        head = self.real_evidence()
        code, out = self.check([self.fixed_item(head)])
        self.assertEqual(code, 1)
        self.assertEqual(len(out["failures"]), 1, out)
        self.assertIn("signed close", out["failures"][0])

    @unittest.skipUnless(OPENSSL, "openssl missing")
    def test_bound_real_evidence_replays_and_passes(self):
        head = self.real_evidence()
        items = [self.fixed_item(head), {"id": "W1", "severity": "WARN",
                                         "status": "open"}]  # fmt: skip
        self.sign_close(items)
        code, out = self.check(items)
        self.assertEqual(out["verdict"], "pass-untrusted", out)
        self.assertEqual(code, 4)
        self.assertFalse(out["trusted"])
        self.assertEqual(out["notes"], ["W1: WARN still open"])

    def test_shared_fix_commit_replays_once(self):
        head = self.real_evidence()
        self.assertEqual(self.revert("--commit", head, finding="B2")[0], 0)
        items = [self.fixed_item(head),
                 {**self.fixed_item(head, "B2"), "evidence": "B2.json"}]  # fmt: skip
        calls = []
        real = rg.build_evidence

        def counted(repo, commit, finding):
            calls.append(commit)
            return real(repo, commit, finding)

        rg.build_evidence = counted
        try:
            code, out = self.check(items, "--jobs", "2")
        finally:
            rg.build_evidence = real
        self.assertEqual(calls, [head])
        self.assertEqual(len(out["failures"]), 1, out)
        self.assertIn("signed close", out["failures"][0])

    def test_parallel_replay_failures_keep_findings_order(self):
        head = self.real_evidence()
        self.assertEqual(self.revert("--commit", head, finding="B2")[0], 0)
        items = [{**self.fixed_item(head, "B2"), "evidence": "B2.json",
                  "proof_tests": ["calc::other"]},
                 {**self.fixed_item(head), "proof_tests": ["calc::missing"]}]  # fmt: skip
        code, out = self.check(items, "--jobs", "4")
        self.assertEqual(code, 1)
        ids = [f.split(":")[0] for f in out["failures"]]
        self.assertEqual(ids, ["B2", "B1"], out)

    def test_replay_and_static_failures_keep_findings_order(self):
        head = self.real_evidence()
        items = [{**self.fixed_item(head), "proof_tests": ["calc::missing"]},
                 {"id": "B2", "severity": "BLOCK", "status": "open"},
                 {**self.fixed_item(head, "B3"), "evidence": "none.json"}]  # fmt: skip
        code, out = self.check(items)
        self.assertEqual(code, 1)
        ids = [f.split(":")[0] for f in out["failures"]]
        self.assertEqual(ids, ["B1", "B2", "B3"], out)

    def two_fix_commits(self):
        """A fast fix, then a slow fix that leaves a detached child behind."""
        first = self.real_evidence()
        cap = ("def t_cap():\n    import subprocess, time\n"
               "    subprocess.Popen(['sleep', '30'], start_new_session=True)\n"
               "    time.sleep(3)\n    from calc import cap\n"
               "    assert cap(9) == 5\ncase('test_cap', t_cap)\n")  # fmt: skip
        (self.repo / "calc.py").write_text(FIXED + "def cap(n):\n    return n\n")
        sh(self.repo, "commit", "-qam", "add cap with a bug")
        second = self.commit_fix(
            FIXED + "def cap(n):\n    return min(n, 5)\n",
            RUNNER.format(body=LIMIT_BODY + cap),
        )
        self.assertEqual(self.revert("--commit", second, finding="B2")[0], 0)
        items = [self.fixed_item(first),
                 {**self.fixed_item(second, "B2"), "evidence": "B2.json",
                  "proof_tests": ["calc::test_cap"]}]  # fmt: skip
        return first, second, items

    def test_distinct_commits_replay_at_the_same_time(self):
        first, second, items = self.two_fix_commits()
        lock = threading.Lock()
        active, peak = [0], [0]
        real = rg.evidence_for

        def tracked(*a):
            with lock:
                active[0] += 1
                peak[0] = max(peak[0], active[0])
            try:
                return real(*a)
            finally:
                with lock:
                    active[0] -= 1

        rg.evidence_for = tracked
        err = StringIO()
        try:
            with redirect_stdout(StringIO()) as out, redirect_stderr(err):
                code = rg.main(["check", self.findings(items), "--repo",
                                str(self.repo), "--reviewer-record",
                                self.record(), "--jobs", "2"])  # fmt: skip
        finally:
            rg.evidence_for = real
        report = json.loads(out.getvalue())
        self.assertEqual(peak[0], 2, err.getvalue())
        # The fast replay's sandbox sweep ran while the slow one was running,
        # and the slow one still proves its test.
        lines = [l for l in err.getvalue().splitlines() if "] " in l]
        self.assertIn(first[:12], lines[0])
        self.assertIn(second[:12], lines[1])
        self.assertEqual(code, 1)
        self.assertEqual(len(report["failures"]), 1, report)
        self.assertIn("signed close", report["failures"][0])

    def test_replay_error_in_one_worker_stops_the_gate(self):
        first, second, items = self.two_fix_commits()
        real = rg.evidence_for

        def failing(repo, recipe, change, finding):
            if change.head == second:
                raise rg.GateError("boom in worker")
            return real(repo, recipe, change, finding)

        rg.evidence_for = failing
        err = StringIO()
        try:
            with redirect_stdout(StringIO()) as out, redirect_stderr(err):
                code = rg.main(["check", self.findings(items), "--repo",
                                str(self.repo), "--reviewer-record",
                                self.record(), "--jobs", "2"])  # fmt: skip
        finally:
            rg.evidence_for = real
        self.assertEqual(code, 2)
        self.assertEqual(out.getvalue(), "")
        self.assertIn("boom in worker", err.getvalue())

    def test_fixed_block_must_name_proving_tests(self):
        head = self.real_evidence()
        item = self.fixed_item(head)
        self.assertEqual(self.check([{**item, "proof_tests": []}])[0], 1)
        code, out = self.check([{**item, "proof_tests": ["calc::other"]}])
        self.assertEqual(code, 1)
        self.assertTrue(any("does not prove" in f for f in out["failures"]), out)

    def test_fixed_block_without_repo_fails(self):
        head = self.real_evidence()
        code, _ = run(["check", self.findings([self.fixed_item(head)]),
                       "--reviewer-record", self.record()])  # fmt: skip
        self.assertEqual(code, 1)

    def test_b1_stripped_evidence_fails(self):
        head = self.real_evidence()
        ev = json.loads((self.root / "B1.json").read_text())
        for key in ("cmd", "recipe", "created_at"):
            ev.pop(key, None)
        for run_ in (ev["with_fix"], ev["fix_reverted"]):
            for key in ("timed_out", "present_tests", "cases"):
                run_.pop(key)
        (self.root / "B1.json").write_text(json.dumps(ev))
        code, out = self.check([self.fixed_item(head)])
        self.assertEqual(code, 1)
        self.assertTrue(any("missing or invalid field" in f for f in out["failures"]))

    def test_b1_forged_passing_evidence_fails_on_replay(self):
        (self.repo / "calc.py").write_text(FIXED + "# touch\n")
        sh(self.repo, "commit", "-qam", "fixed without a real test")
        head = self.commit_fix(source=FIXED + "# touch 2\n")
        self.revert("--commit", head)
        ev = json.loads((self.root / "B1.json").read_text())
        ev["fix_reverted"]["exit_code"] = 1
        ev["fix_reverted"]["cases"] = {"calc::test_limit": "failure"}
        ev["proof_cases"], ev["problems"], ev["verdict"] = (
            ["calc::test_limit"],
            [],
            "pass",
        )
        (self.root / "B1.json").write_text(json.dumps(ev))
        code, out = self.check([self.fixed_item(head)])
        self.assertEqual(code, 1)
        self.assertTrue(any("replay failed" in f for f in out["failures"]), out)

    def test_b1_evidence_for_another_change_or_finding_fails(self):
        head = self.real_evidence()
        self.assertEqual(self.check([self.fixed_item("0" * 40)])[0], 1)
        self.assertEqual(self.check([self.fixed_item(head, finding="B9")])[0], 1)

    def test_b1_repo_drift_after_evidence_fails(self):
        (self.repo / "calc.py").write_text(FIXED)
        (self.repo / "test_calc.py").write_text(TEST)
        _, ev = self.revert()
        (self.repo / "calc.py").write_text(BUGGY)
        code, _ = self.check([self.fixed_item(ev["change_id"])])
        self.assertEqual(code, 1)

    def test_b2_self_asserted_rejection_fails(self):
        code, _ = self.check(
            [{"id": "B1", "severity": "BLOCK", "status": "rejected",
              "reason": "false positive", "user_approved": True}])  # fmt: skip
        self.assertEqual(code, 1)

    def test_r3b1_forged_recipe_in_evidence_is_ignored_on_replay(self):
        (self.repo / "calc.py").write_text(FIXED + "# touch\n")
        sh(self.repo, "commit", "-qam", "fixed without a real test")
        head = self.commit_fix(source=FIXED + "# touch 2\n")
        self.revert("--commit", head)
        ev = json.loads((self.root / "B1.json").read_text())
        case = 'classname="calc" name="test_limit"'
        forged = (
            f"grep -q 'touch 2' calc.py && echo '<testsuite><testcase {case}/>"
            f"</testsuite>' > junit.xml || {{ echo '<testsuite><testcase {case}>"
            '<failure type="AssertionError"/></testcase></testsuite>\' '
            "> junit.xml; exit 1; }"
        )
        ev["cmd"] = forged
        ev["recipe"]["cmd_template"] = forged
        proof = "calc::test_limit"
        ev["fix_reverted"].update(exit_code=1, cases={proof: "failure"})
        ev["with_fix"].update(exit_code=0, cases={proof: "pass"})
        ev["proof_cases"], ev["problems"], ev["verdict"] = [proof], [], "pass"
        (self.root / "B1.json").write_text(json.dumps(ev))
        code, out = self.check([self.fixed_item(head)])
        self.assertEqual(code, 1)
        self.assertTrue(any("replay failed" in f for f in out["failures"]), out)

    def test_r3b2_block_missing_from_findings_fails(self):
        record = 'findings:\n- "BLOCK R9-B1: real problem"\n- "WARN R9-W1: minor"\n'
        code, out = self.check([], record=record)
        self.assertEqual(code, 1)
        self.assertIn("R9-B1", out["failures"][0])
        downgraded = [{"id": "R9-B1", "severity": "WARN", "status": "open"}]
        self.assertEqual(self.check(downgraded, record=record)[0], 1)

    def test_r3b2_hand_written_receipt_fails(self):
        item = {"id": "B1", "severity": "BLOCK", "status": "waived", "reason": "x"}
        fake = base64.b64encode(b"not a signature").decode()
        self.sign_close([item], signature=fake)
        code, out = self.check([item])
        self.assertEqual(code, 1)
        self.assertIn("close signature does not match", out["failures"][0])

    @unittest.skipUnless(OPENSSL, "openssl missing")
    def test_signed_close_passes_and_any_edit_fails(self):
        item = {"id": "B1", "severity": "BLOCK", "status": "waived",
                "reason": "interface change; old code cannot run new test"}  # fmt: skip
        self.sign_close([item])
        code, out = self.check([item])
        self.assertEqual(out["verdict"], "pass-untrusted", out)
        self.assertEqual(self.check([{**item, "reason": "changed"}])[0], 1)
        self.assertEqual(self.check([{**item, "status": "rejected"}])[0], 1)
        self.assertEqual(self.check([{**item, "severity": "WARN"}])[0], 1)
        self.assertEqual(self.check([item], record="decisions: []\n")[0], 1)

    @unittest.skipUnless(OPENSSL, "openssl missing")
    def test_r5b1_record_deleted_or_added_after_close_fails(self):
        self.peer_record("t1-review1", ["BLOCK R9-B1: x"], name="a.yaml")
        self.peer_record("t1-review2", [], name="b.yaml")
        item = {"id": "R9-B1", "severity": "BLOCK", "status": "waived",
                "reason": "x"}  # fmt: skip
        self.sign_close([item])
        self.assertEqual(self.check([item])[0], 4)
        tasks = rg.PEER_RECORDS / "scope" / "agents" / "reviewer" / "tasks"
        (tasks / "a.yaml").unlink()
        self.assertEqual(self.check([item])[0], 1)
        self.assertEqual(self.check([])[0], 1)
        self.peer_record("t1-review1", ["BLOCK R9-B1: x"], name="a.yaml")
        self.assertEqual(self.check([item])[0], 4)
        self.peer_record("t1-review3", [], name="c.yaml")
        self.assertEqual(self.check([item])[0], 1)

    @unittest.skipUnless(OPENSSL, "openssl missing")
    @unittest.skipUnless(OPENSSL, "openssl missing")
    def test_r5b2_relabeled_proof_after_close_fails(self):
        self.peer_record("t1-review1", ["BLOCK R9-B1: limit", "BLOCK R9-B2: other"])
        head = self.real_evidence()
        signed = [{**self.fixed_item(head, finding="R9-B1")},
                  {"id": "R9-B2", "severity": "BLOCK", "status": "waived",
                   "reason": "not a defect"}]  # fmt: skip
        ev = json.loads((self.root / "B1.json").read_text())
        (self.root / "B1.json").write_text(json.dumps({**ev, "finding": "R9-B1"}))
        self.sign_close(signed)
        self.assertEqual(self.check(signed)[0], 4)
        # Move the genuine proof to the other BLOCK; replay alone accepts it.
        (self.root / "B1.json").write_text(json.dumps({**ev, "finding": "R9-B2"}))
        moved = [{**signed[1], **self.fixed_item(head, finding="R9-B2")},
                 {**signed[0], "status": "waived", "reason": "not a defect",
                  "evidence": None}]  # fmt: skip
        code, out = self.check(moved)
        self.assertEqual(code, 1)
        self.assertEqual(len(out["failures"]), 1, out)
        self.assertIn("close signature does not match", out["failures"][0])

    def close_for_real(self, items):
        """Run close with an openssl signer standing in for Touch ID.

        close sees a clean trust check, as the installed checker would.
        """
        key, trust = self.root / "k.ec", self.root / "trust"
        trust.mkdir(exist_ok=True)
        subprocess.run([OPENSSL, "ecparam", "-name", "prime256v1", "-genkey",
                        "-noout", "-out", str(key)], check=True)  # fmt: skip
        subprocess.run([OPENSSL, "ec", "-in", str(key), "-pubout", "-out",
                        str(trust / "approver.pub")], check=True,
                       capture_output=True)  # fmt: skip
        rg.APPROVER = self.stub("sign-stub", SIGN_STUB.format(key=key))
        rg.APPROVER_KEY = key
        path = self.findings(items)
        real_trust = rg.trust_problems
        rg.trust_problems = lambda: []
        try:
            with redirect_stdout(StringIO()), redirect_stderr(StringIO()) as err:
                code = rg.main(["close", path, "--repo", str(self.repo),
                                "--reviewer-record", self.record()])  # fmt: skip
        finally:
            rg.trust_problems = real_trust
        self.assertEqual(code, 0, err.getvalue())

    @unittest.skipUnless(OPENSSL, "openssl missing")
    def test_check_replays_again_after_a_signed_close(self):
        head = self.real_evidence()
        items = [self.fixed_item(head)]
        self.close_for_real(items)
        calls = []
        real = rg.build_evidence

        def counted(repo, commit, finding):
            calls.append(commit)
            return real(repo, commit, finding)

        rg.build_evidence = counted
        try:
            code, out = self.check(items)
        finally:
            rg.build_evidence = real
        self.assertEqual(out["verdict"], "pass-untrusted", out)
        self.assertEqual(calls, [head])

    @unittest.skipUnless(OPENSSL, "openssl missing")
    def test_signer_gets_the_message_on_stdin_not_a_file(self):
        head = self.real_evidence()
        items = [self.fixed_item(head)]
        log = self.root / "argv.log"
        self.close_for_real(items)
        rg.APPROVER = self.stub(
            "argv-stub",
            f"""#!/bin/bash
printf '%s\\n' "$@" >>{log}
exec {self.root / "sign-stub"} "$@"
""",
        )
        code, out = self.check(items)
        self.assertEqual(out["verdict"], "pass-untrusted", out)
        argv = log.read_text().splitlines()
        self.assertEqual(argv[argv.index("--message") + 1], "-")

    @unittest.skipUnless(OPENSSL, "openssl missing")
    def test_s1b2_swapped_message_file_cannot_pass_an_edited_closure(self):
        item = {"id": "B1", "severity": "BLOCK", "status": "waived",
                "reason": "signed reason"}  # fmt: skip
        self.sign_close([item])
        records = rg.record_blocks("t1", [self.record()])
        old = self.root / "old.msg"
        old.write_bytes(rg.close_payload("t1", [item], records))
        # Simulates another process winning the race: a message file handed
        # to the verifier is replaced with the signed bytes before it is read.
        rg.APPROVER = self.stub(
            "swap-verify",
            f"""#!/bin/bash
msg=$(/usr/bin/mktemp)
if [[ $5 == - ]]; then cat >"$msg"; else cp {old} "$5"; cp "$5" "$msg"; fi
sig=$(/usr/bin/mktemp)
printf %s "$7" | /usr/bin/base64 -d >"$sig"
exec {OPENSSL} dgst -sha256 -verify "$3" -signature "$sig" "$msg" >/dev/null
""",
        )
        code, out = self.check([{**item, "reason": "edited after signing"}])
        self.assertEqual(code, 1, out)
        self.assertIn("close signature does not match", out["failures"][0])

    def test_close_without_an_empty_task_signature_fails(self):
        code, out = self.check([])
        self.assertEqual(code, 1)
        self.assertIn("signed close", out["failures"][0])

    def test_r4b1_discovered_record_cannot_be_bypassed(self):
        self.peer_record("t1-review2", ["BLOCK R9-B1: real problem", "WARN R9-W1: x"])
        # An empty substitute record does not hide the discovered one.
        code, out = self.check([], record="")
        self.assertEqual(code, 1)
        self.assertTrue(any(f.startswith("R9-B1:") for f in out["failures"]), out)
        self.assertFalse(any("X9-B9" in f for f in out["failures"]), out)
        items = [{"id": "R9-B1", "severity": "BLOCK", "status": "open"}]
        self.assertEqual(self.check(items)[0], 1)

    def test_r4b1_security_records_count_and_other_tasks_do_not(self):
        self.peer_record("t1-sec", ["BLOCK S1-B1: x"], role="security", name="s.yaml")
        self.peer_record("other-task", ["BLOCK O1-B1: x"], name="o.yaml")
        code, out = self.check([], record="")
        self.assertEqual([f.split(":")[0] for f in out["failures"]], ["S1-B1"])

    def test_r5b1_folded_yaml_block_item_is_counted(self):
        tasks = rg.PEER_RECORDS / "scope" / "agents" / "reviewer" / "tasks"
        tasks.mkdir(parents=True)
        (tasks / "f.yaml").write_text(
            "task_id: t1-review\nfindings:\n- >-\n  BLOCK R9-B1: problem\n"
            "  continues here\n- |\n  WARN R9-W1: minor\n"
        )
        code, out = self.check([], record="")
        self.assertEqual([f.split(":")[0] for f in out["failures"]], ["R9-B1"])

    def test_no_judgment_record_at_all_fails(self):
        path = self.findings([])
        code, out = run(["check", path, "--repo", str(self.repo)])
        self.assertEqual(code, 1)
        self.assertIn("no judgment record found", out["failures"][0])

    def test_r9b2_summary_escapes_control_characters(self):
        hostile = "\x1b[2J\x1b[HSAFE: no BLOCK\r\x08\u202e"
        items = [{"id": "B1" + hostile, "severity": "BLOCK", "status": "waived",
                  "change": hostile, "proof_tests": [hostile],
                  "reason": hostile + " 한국어 사유"}]  # fmt: skip
        records = rg.record_blocks("t1", [self.record()])
        text = rg.close_summary(rg.close_payload("t1" + hostile, items, records))
        for ch in "\x1b\r\x08\u202e":
            self.assertNotIn(ch, text)
        self.assertIn("\\x1b[2J", text)
        self.assertIn("\\u202e", text)
        self.assertIn("한국어 사유", text)
        self.assertTrue(all(c == "\n" or c.isprintable() for c in text))

    def test_close_refuses_without_a_key(self):
        path = self.findings([{"id": "B1", "severity": "BLOCK", "status": "rejected",
                               "reason": "x"}])  # fmt: skip
        code, _ = run(["close", path, "--reviewer-record", self.record()])
        self.assertEqual(code, 2)
        self.assertFalse((self.root / "approvals").exists())

    def test_close_refuses_while_the_gate_fails(self):
        path = self.findings([{"id": "B1", "severity": "BLOCK", "status": "open"}])
        buf = StringIO()
        with redirect_stdout(StringIO()), redirect_stderr(buf):
            code = rg.main(["close", path, "--reviewer-record", self.record()])
        self.assertEqual(code, 2)
        self.assertIn("B1: BLOCK is open", buf.getvalue())

    def test_r6b1_summary_shows_every_signed_field(self):
        for scope in ("s1", "s2"):
            tasks = rg.PEER_RECORDS / scope / "agents" / "reviewer" / "tasks"
            tasks.mkdir(parents=True)
            (tasks / "same.yaml").write_text(
                f'task_id: t1-{scope}\nfindings:\n- "BLOCK {scope.upper()}-B1: x"\n'
            )
        change = "a" * 40
        items = [{"id": "S1-B1", "severity": "BLOCK", "status": "fixed",
                  "change": change, "proof_tests": ["m::test_x"],
                  "reason": "fixed in the parser"},
                 {"id": "S2-B1", "severity": "BLOCK", "status": "waived",
                  "reason": "needs hardware we do not have"}]  # fmt: skip
        records = rg.record_blocks("t1", [])
        self.assertEqual(len(records), 2)
        message = rg.close_payload("t1", items, records)
        text = rg.close_summary(message)
        for path in records:
            self.assertIn(path, text)
            self.assertIn(hashlib.sha256(Path(path).read_bytes()).hexdigest(), text)
        for needle in (change, "m::test_x", "fixed in the parser",
                       "needs hardware we do not have", "S2-B1: waived"):  # fmt: skip
            self.assertIn(needle, text)


class CanaryTest(RepoCase):
    def seed(self, head, *extra):
        code, seeded = run(["canary", "seed", "--repo", str(self.repo),
                            "--commit", head, "--seed", "1", *extra])  # fmt: skip
        return code, seeded

    def test_seed_verified_score_report(self):
        head = self.commit_fix()
        code, seeded = self.seed(
            head, "--verify-cmd", CMD, "--verify-junit", "junit.xml"
        )
        self.assertEqual(code, 0, seeded)
        self.assertTrue(seeded["behavior_verified"])
        show = sh(self.repo, "show", f"{seeded['review_commit']}:calc.py")
        self.assertIn("n < 10", show)
        self.assertEqual(self.worktrees(), 1)
        run(["canary", "score", seeded["canary_id"], "--role", "reviewer",
             "--model", "m", "--caught", "yes"])  # fmt: skip
        _, rep = run(["canary", "report"])
        self.assertEqual(rep["verified"]["reviewer / m"]["catch_rate"], 1.0)
        self.assertEqual(rep["unverified"], {})

    def test_w2_unverified_seed_is_reported_separately(self):
        _, seeded = self.seed(self.commit_fix())
        self.assertFalse(seeded["behavior_verified"])
        run(["canary", "score", seeded["canary_id"], "--role", "reviewer",
             "--model", "m", "--caught", "no"])  # fmt: skip
        _, rep = run(["canary", "report"])
        self.assertEqual(rep["verified"], {})
        self.assertEqual(rep["unverified"]["reviewer / m"]["runs"], 1)

    def test_r3w2_multiline_comments_and_java_tests_are_not_mutated(self):
        source = 'def one():\n    """n <= 10\n    a <= b\n    """\n    return 1\n'
        head = self.commit_fix(source=source)
        self.assertEqual(self.seed(head)[0], 2)
        java = "class FooTest {\n  boolean t() { return 1 <= 2; }\n}\n"
        (self.repo / "FooTest.java").write_text(java)
        sh(self.repo, "add", ".")
        sh(self.repo, "commit", "-qm", "java test")
        self.assertEqual(self.seed("HEAD")[0], 2)

    def test_r3w2_stateful_verify_without_behavior_change_is_unverified(self):
        body = (
            "def t_marker():\n"
            "    import os\n"
            "    assert not os.path.exists('.marker')\n"
            "    open('.marker', 'w').write('x')\n"
            "case('test_marker', t_marker)\n"
        )
        (self.repo / ".gitignore").write_text("junit.xml\n.cache/\n.marker\n")
        head = self.commit_fix(source=BUGGY + "UNUSED = 1 <= 2\n",
                               test=RUNNER.format(body=body))  # fmt: skip
        code, seeded = self.seed(
            head, "--verify-cmd", CMD, "--verify-junit", "junit.xml"
        )
        self.assertEqual(code, 0, seeded)
        self.assertFalse(seeded["behavior_verified"])

    def test_r4w1_shared_state_cannot_verify_a_canary(self):
        (self.repo / ".cache").mkdir()
        body = (
            "def t_marker():\n"
            "    import os\n"
            "    assert not os.path.exists('.cache/marker')\n"
            "    open('.cache/marker', 'w').write('x')\n"
            "case('test_marker', t_marker)\n"
        )
        head = self.commit_fix(source=BUGGY + "UNUSED = 1 <= 2\n",
                               test=RUNNER.format(body=body))  # fmt: skip
        code, seeded = self.seed(
            head, "--verify-cmd", CMD, "--verify-junit", "junit.xml", "--copy", ".cache"
        )
        self.assertEqual(code, 0, seeded)
        self.assertFalse(seeded["behavior_verified"])

    def test_r11_canary_seed_does_not_use_the_caller_git(self):
        head = self.commit_fix()
        marker = self.root / "fake-git-ran"
        fake = self.root / "fakebin"
        fake.mkdir()
        (fake / "git").write_text(
            f'#!/bin/bash\ntouch {marker}\nexec /usr/bin/git "$@"\n'
        )
        (fake / "git").chmod(0o755)
        saved = os.environ["PATH"]
        os.environ["PATH"] = f"{fake}:{saved}"
        try:
            code, seeded = self.seed(
                head, "--verify-cmd", CMD, "--verify-junit", "junit.xml"
            )
        finally:
            os.environ["PATH"] = saved
        self.assertEqual(code, 0, seeded)
        self.assertTrue(seeded["behavior_verified"])
        self.assertFalse(marker.exists(), "git was taken from the caller's PATH")
        show = sh(self.repo, "show", f"{seeded['review_commit']}:calc.py")
        self.assertIn("n < 10", show)

    def test_r10b2_home_state_cannot_verify_a_canary(self):
        home = self.root / "home"
        (home / ".cache").mkdir(parents=True)
        (home / ".cache" / "state").write_text("0")
        saved = os.environ["HOME"]
        os.environ["HOME"] = str(home)
        self.addCleanup(os.environ.__setitem__, "HOME", saved)
        body = (
            "def t_state():\n"
            "    import os\n"
            "    p = os.path.expanduser('~/.cache/state')\n"
            "    old = open(p).read() if os.path.exists(p) else '0'\n"
            "    os.makedirs(os.path.dirname(p), exist_ok=True)\n"
            "    open(p, 'w').write('1' if old == '0' else '0')\n"
            "    assert old == '0'\n"
            "case('test_state', t_state)\n"
        )
        head = self.commit_fix(source=BUGGY + "UNUSED = 1 <= 2\n",
                               test=RUNNER.format(body=body))  # fmt: skip
        code, seeded = self.seed(
            head, "--verify-cmd", CMD, "--verify-junit", "junit.xml"
        )
        self.assertEqual(code, 0, seeded)
        self.assertFalse(seeded["behavior_verified"])
        self.assertEqual((home / ".cache" / "state").read_text(), "0")

    def test_w2_inline_comments_strings_and_test_files_are_not_mutated(self):
        source = "def one():\n    return 1  # n <= 10\n\nMSG = 'a <= b'\n"
        head = self.commit_fix(source=source, test=TEST + "assert 1 <= 2\n")
        code, _ = self.seed(head)
        self.assertEqual(code, 2)

    def test_w2_seed_metadata_matches_the_original(self):
        head = self.commit_fix()
        _, seeded = self.seed(head)
        commit = seeded["review_commit"]
        self.assertEqual(sh(self.repo, "log", "-1", "--format=%an %ae", commit),
                         "dev dev@example.com")  # fmt: skip
        self.assertEqual(sh(self.repo, "log", "-1", "--format=%B", commit), "fix limit")
        self.assertEqual(sh(self.repo, "rev-parse", f"{commit}^"),
                         sh(self.repo, "rev-parse", f"{head}^"))  # fmt: skip

    def test_w3_duplicate_score_is_rejected_unless_superseded(self):
        _, seeded = self.seed(self.commit_fix())
        base = ["canary", "score", seeded["canary_id"], "--role", "reviewer",
                "--model", "m"]  # fmt: skip
        self.assertEqual(run([*base, "--caught", "yes"])[0], 0)
        self.assertEqual(run([*base, "--caught", "yes"])[0], 2)
        self.assertEqual(run([*base, "--caught", "no", "--supersede"])[0], 0)
        _, rep = run(["canary", "report"])
        group = rep["unverified"]["reviewer / m"]
        self.assertEqual((group["runs"], group["caught"]), (1, 0))


class MaskTest(unittest.TestCase):
    def cands(self, path, source):
        lines = set(range(1, source.count("\n") + 2))
        return rg.mutation_candidates(path, source, lines, [])

    def lines(self, path, source):
        return [c[1] for c in self.cands(path, source)]

    def test_r20w1_jsx_that_neither_parses_nor_is_expected_skips_the_file(self):
        for src in (
            "const e = /* note */ <A\u0301>\ntrue and false\n</A\u0301>;\n",
            'const e = /* note */ <Box a\u0301="value">\ntrue and false\n</Box>;\n',
        ):
            self.assertEqual(self.lines("a.tsx", src + "const ok = c <= d;\n"), [])
        src = "const ok = a<b && c <= d;\nconst x = f<T>(y) || z;\n"
        self.assertEqual(self.lines("a.tsx", src), [1, 1, 2])

    def test_r20w2_an_ambiguous_top_level_slash_skips_the_file(self):
        for head in ('if (true) /* note */ /`/.test("x");', 'if (")") /`/.test("x");'):
            src = f"{head}\nconst s = `a <= b`;\nconst ok = c <= d;\n"
            self.assertEqual(self.lines("a.js", src), [], head)
        src = "const r = /x/ * 2 /* note */;\nconst ok = c <= d;\n"
        self.assertEqual(self.lines("a.js", src), [])
        src = "const h = w / 2; // it's half\nconst ok = c <= d;\n"
        self.assertEqual(self.lines("a.js", src), [2])

    def test_r20w3_c_cr_and_blank_splices_skip_the_file(self):
        for src in (
            "/\\\r* a <= b */\rint ok(void) { return c <= d; }\r",
            "/\\ \n* a <= b */\nint ok(void) { return c <= d; }\n",
            'const char *s = "x\\\t\na <= b";\nint ok(void) { return c <= d; }\n',
        ):
            self.assertEqual(self.lines("a.c", src), [], repr(src))
        src = "int ok(void) { return c <= d; } /* a \\ b */\n"
        self.assertEqual(self.lines("a.c", src), [1])

    def test_r19w1_a_slash_in_a_template_hole_skips_the_file(self):
        for cond in ('if (")")', "if (true) /* note */", "if (false) {} else"):
            src = (
                f'const s = `${{(() => {{ {cond} /}}}}`/.test("x"); return 1; }})()}}\n'
                "a <= b`;\nconst ok = c <= d;\n"
            )
            self.assertEqual(self.lines("a.js", src), [], cond)
        src = "const s = `${f(a) / 2}`;\nconst t = `x <= y`;\nconst ok = c <= d;\n"
        self.assertEqual(self.lines("a.js", src), [])
        src = "const s = `${f(a) /* n */}`;\nconst t = `x <= y`;\nconst ok = c <= d;\n"
        self.assertEqual(self.lines("a.js", src), [3])
        src = 'let s = """\n\\( /[)"""]/.description )\na <= b\n"""\nlet ok = c <= d\n'
        self.assertEqual(self.lines("a.swift", src), [])
        src = "const s = `${a}`;\nconst ok = c <= d;\n"
        self.assertEqual(self.lines("a.js", src), [2])

    def test_r19w2_jsx_the_lexer_cannot_place_skips_the_file(self):
        src = (
            "const e = /* note */ <div>\ntrue and false\n</div>;\nconst ok = c <= d;\n"
        )
        self.assertEqual(self.lines("a.tsx", src), [])
        src = "function* f() { yield <div>\ntrue and false\n</div>; }\n"
        src += "const ok = c <= d;\n"
        self.assertEqual(self.lines("a.tsx", src), [4])
        for tag in ("Box<string>", "박스"):
            name = tag.split("<")[0]
            src = f"const e = <{tag}>\ntrue and false\n</{name}>;\nconst ok = c <= d;\n"
            self.assertEqual(self.lines("a.tsx", src), [4], tag)
        src = "const f = <T,>(x: T, y: T) => x <= y;\n"
        self.assertEqual(self.lines("a.tsx", src), [])
        src = "const [a, b] = useState<string>(x);\nconst ok = c <= d;\n"
        self.assertEqual(self.lines("a.tsx", src), [2])

    def test_r19w3_c_splices_near_comments_skip_the_file(self):
        for src in (
            "/\\\n* a <= b */\nint ok(void) { return c <= d; }\n",
            "/\\\r\n/ a <= b\r\nint ok(void) { return c <= d; }\r\n",
            "/??/\n* a <= b */\nint ok(void) { return c <= d; }\n",
        ):
            self.assertEqual(self.lines("a.c", src), [], repr(src))
        src = "#define M(x) \\\n  (x)\nint ok(void) { return c <= d; }\n"
        self.assertEqual(self.lines("a.c", src), [3])

    def test_r19w4_scala_interpolated_backslash_skips_the_file(self):
        src = 'val p = raw"C:\\"; val s = "a <= b"\nval ok = c <= d\n'
        self.assertEqual(self.lines("a.scala", src), [])
        src = 'val s = s"a \\" x <= y"\nval ok = c <= d\n'
        self.assertEqual(self.lines("a.scala", src), [])
        src = 'val p = "C:\\\\"; val s = "a <= b"\nval ok = c <= d\n'
        self.assertEqual(self.lines("a.scala", src), [2])

    def test_r19w5_sql_non_ascii_dollar_tags_skip_the_file(self):
        for tag in ("e\u0301", "\U0001f4b0", "a\u00e9", "태그"):
            src = f"SELECT ${tag}$a <= b${tag}$;\nSELECT c <= d;\n"
            self.assertEqual(self.lines("a.sql", src), [], ascii(tag))
        self.assertEqual(self.lines("a.sql", "SELECT 'é', c <= d;\n"), [1])

    def test_r18w1_backslash_crlf_continues_a_string_or_c_comment(self):
        src = 'const char *s = "x\\\r\na <= b";\r\nint ok = c <= d;\r\n'
        self.assertEqual(self.lines("a.c", src), [3])
        src = 'const s = "x\\\r\na <= b";\r\nconst ok = c <= d;\r\n'
        self.assertEqual(self.lines("a.js", src), [3])
        src = 's = "x\\\r\na <= b"\r\nok = c <= d\r\n'
        self.assertEqual(self.lines("a.py", src), [3])
        src = "// note \\\r\na <= b\nint ok = c <= d;\n"
        self.assertEqual(self.lines("a.c", src), [3])
        src = 'const char *s = "x\\\\";\r\nint ok = c <= d;\r\n'
        self.assertEqual(self.lines("a.c", src), [2])

    def test_r18w2_fstring_backslash_does_not_escape_a_brace(self):
        for prefix in ("f", "rf"):
            src = "s = " + prefix + '"\\{\'" <= "\'} tail"\nok = c <= d\n'
            self.assertEqual(self.lines("a.py", src), [2], prefix)
        src = 's = f"\\N{BULLET} a <= b"\nok = c <= d\n'
        self.assertEqual(self.lines("a.py", src), [2])

    def test_r18w3_csharp_raw_interpolation_holes(self):
        src = 'var s = $"""{ """a <= b""" }""";\nvar ok = c <= d;\n'
        self.assertEqual(self.lines("a.cs", src), [2])
        src = 'var s = $$"""{{ """a <= b""" }}""";\nvar ok = c <= d;\n'
        self.assertEqual(self.lines("a.cs", src), [2])
        src = 'var s = $$"""{x} a <= b""";\nvar ok = c <= d;\n'
        self.assertEqual(self.lines("a.cs", src), [2])

    def test_r18w4_regex_after_an_if_condition(self):
        src = (
            'const s = `${(() => { if (true) /}}`/.test("x"); return 1; })()}\n'
            "a <= b`;\nconst ok = c <= d;\n"
        )
        self.assertNotIn(2, self.lines("a.js", src))
        src = "if (x) /`/.test(s);\nconst ok = c <= d;\nconst t = `a <= b`;\n"
        self.assertNotIn(3, self.lines("a.js", src))

    def test_r18w5_jsx_text_and_attributes_are_not_code(self):
        src = 'const e = <div title="x\\" data-label="a <= b" />;\nconst ok = c <= d;\n'
        self.assertEqual(self.lines("a.tsx", src), [2])
        src = "const e = <div>\na >= b and true\n</div>;\nconst ok = c <= d;\n"
        self.assertEqual(self.lines("a.jsx", src), [4])
        src = "const e = <>{a && <b c={d || e}>x or y</b>}</>;\nconst ok = c <= d;\n"
        got = [(c[1], c[4]) for c in self.cands("a.js", src)]
        self.assertEqual(got, [(1, "&& -> ||"), (1, "\\|\\| -> &&"), (2, "<= -> <")])
        src = "const f = <T>(x: T, y: T) => x <= y;\n"
        self.assertEqual(self.lines("a.ts", src), [1])
        src = "if (a < b && c <= d) {}\n"
        self.assertEqual(len(self.cands("a.jsx", src)), 2)

    def test_r18w6_java_unicode_escapes_skip_the_file(self):
        src = (
            "final class P { String s = \\u0022a <= b\\u0022;"
            " boolean f(int c, int d) { return c <= d; } }\n"
        )
        self.assertEqual(self.lines("P.java", src), [])
        src = 'final class P { String s = "\\u0041"; boolean f() { return c <= 1; } }\n'
        self.assertEqual(self.lines("P.java", src), [1])

    def test_r18w7_sql_dollar_tags_may_be_non_ascii(self):
        src = "SELECT $태그$a <= b$태그$;\nSELECT c <= d;\n"
        self.assertNotIn(1, self.lines("a.sql", src))
        src = "SELECT $tag$a <= b$tag$;\nSELECT c <= d;\n"
        self.assertEqual(self.lines("a.sql", src), [2])
        self.assertEqual(self.lines("a.sql", "SELECT $1 WHERE c <= d;\n"), [1])

    def test_r17w1_go_raw_strings_take_a_backslash_literally(self):
        src = "p := `dir\\`\nok := a <= b\nq := `y <= z`\n"
        self.assertEqual(self.lines("a.go", src), [2])
        self.assertEqual(self.lines("a.go", 's := "x\\"" + `y`\nok := a <= b\n'), [2])

    def test_mw2_js_template_holes_may_hold_backticks(self):
        src = 'const s = `${"`"}\na <= b`;\nconst ok = c <= d;\n'
        self.assertEqual(self.lines("a.js", src), [3])
        src = "const t = `${ {a: 1}.a } x`; ok = a <= b;\n"
        self.assertEqual(self.lines("a.ts", src), [1])

    def test_mw3_rust_prefixed_raw_strings_and_lifetimes(self):
        src = 'let p = br"C:\\";\nlet ok = a <= b;\nlet q = "x";\n'
        self.assertEqual(self.lines("a.rs", src), [2])
        src = 'let p = cr"C:\\";\nlet ok = a <= b;\n'
        self.assertEqual(self.lines("a.rs", src), [2])
        life = "fn f<'a>(x: &'a u8, y: &'a u8) -> bool { x <= y }\n"
        self.assertEqual(self.lines("a.rs", life), [1])
        self.assertEqual(self.lines("a.rs", "let c = '\"'; let ok = a <= b;\n"), [1])
        src = "let c = b'\\''; let s = \"a <= b\";\n"
        self.assertEqual(self.lines("a.rs", src), [])

    def test_mw4_csharp_verbatim_raw_and_interpolated_strings(self):
        src = 'var p = @"C:\\";\nvar ok = a <= b;\nvar q = "x";\n'
        self.assertEqual(self.lines("a.cs", src), [2])
        raw = 'var r = """\n"a <= b"\n""";\nvar ok = c <= d;\n'
        self.assertEqual(self.lines("a.cs", raw), [4])
        hole = 'var s = $@"{\'"\'}\na <= b";\nvar ok = c <= d;\n'
        self.assertEqual(self.lines("a.cs", hole), [3])
        self.assertEqual(self.lines("a.cs", 'var d = @"say ""hi"" a <= b";\n'), [])

    def test_mw5_python_fstring_holes_may_reuse_the_quote(self):
        src = 's = f"""{\'"""\'}\na <= b\n"""\nok = c <= d\n'
        self.assertEqual(self.lines("a.py", src), [4])
        src = 's = f"{d["k"]} a <= b"; ok = c <= d\n'
        self.assertEqual(self.lines("a.py", src), [1])
        self.assertEqual(self.lines("a.py", 's = f"{{a <= b}}"\nok = c <= d\n'), [2])
        self.assertEqual(self.lines("a.py", 'elf = "{" ; ok = a <= b\n'), [1])

    def test_mw6_kotlin_template_holes_and_raw_quote_runs(self):
        src = 'val s = "${"\\""} a <= b"\nval ok = c <= d\n'
        self.assertEqual(self.lines("a.kt", src), [2])
        self.assertEqual(self.lines("a.kt", 'val s = """a""""; val ok = c <= d\n'), [1])

    def test_mw7_swift_raw_strings_holes_and_regex_literals(self):
        src = 'let p = #"C:\\"#; let ok = a <= b\n'
        self.assertEqual(self.lines("a.swift", src), [1])
        hole = 'let s = "\\(c == "\\"" ? 1 : 2) a <= b"\nlet ok = c <= d\n'
        self.assertEqual(self.lines("a.swift", hole), [2])
        self.assertEqual(self.lines("a.swift", "let r = /a <= b/\n"), [])
        src = "let r = #/a <= b/#\nlet ok = c <= d\n"
        self.assertEqual(self.lines("a.swift", src), [2])
        self.assertEqual(self.lines("a.swift", "let ok = c <= d\n"), [1])

    def test_mw8_scala_interpolated_strings_and_symbols(self):
        src = 'val s = s"a \\" x <= y"\nval ok = c <= d\n'
        self.assertNotIn(1, self.lines("a.scala", src))
        src = "val k = 'sym; val ok = a <= b; val c = 'x'\n"
        self.assertEqual(self.lines("a.scala", src), [1])
        hole = 'val s = s"${\'"\'} a <= b"\nval ok = c <= d\n'
        self.assertEqual(self.lines("a.scala", hole), [2])
        src = 'val p = "C:\\"" ; val ok = a <= b\n'
        self.assertEqual(self.lines("a.scala", src), [1])

    def test_mw9_c_raw_strings(self):
        src = 'const char *p = R"(say "hi)"; int ok = a <= b;\n'
        self.assertEqual(self.lines("a.c", src), [1])
        src = 'const char *s = "R(";\nint ok = a <= b;\n'
        self.assertEqual(self.lines("a.c", src), [2])

    def test_r16w1_escaped_triple_quote_does_not_end_the_string(self):
        src = 'VALUE = """escaped \\"""\na <= b\n"""\n'
        compile(src, "a.py", "exec")
        self.assertEqual(self.cands("a.py", src), [])
        raw = 'VALUE = r"""raw \\"""\na <= b\n"""\n'
        compile(raw, "a.py", "exec")
        self.assertEqual(self.cands("a.py", raw), [])
        code = 'VALUE = """x \\\\"""\nOK = a <= b\n'
        compile(code, "a.py", "exec")
        self.assertEqual(len(self.cands("a.py", code)), 1)
        kotlin = 'val v = """raw \\"""\nval ok = a <= b\n'
        self.assertEqual(len(self.cands("a.kt", kotlin)), 1)

    def test_r15w2_sql_e_string_continuation_keeps_escapes(self):
        src = "SELECT E'a'\n'\\'' AS quote, 'a <= b' AS text;\n"
        self.assertEqual(self.cands("a.sql", src), [])
        commented = "SELECT E'a'  -- c\n'\\'' AS quote, 'a <= b';\n"
        self.assertEqual(self.cands("a.sql", commented), [])
        self.assertEqual(self.cands("a.sql", "SELECT E'it''\\'s', 'a <= b';\n"), [])
        code = "SELECT E'x' WHERE a <= b AND '\\' = 'y';\n"
        self.assertEqual(len(self.cands("a.sql", code)), 1)

    def test_r14w1_sql_backslash_escapes_only_in_e_strings(self):
        slash = "SELECT '\\' AS slash, 'a <= b' AS text;\n"
        self.assertEqual(self.cands("a.sql", slash), [])
        self.assertEqual(self.cands("a.sql", "SELECT E'it\\'s', 'a <= b';\n"), [])
        self.assertEqual(len(self.cands("a.sql", "SELECT 'it''s' WHERE a <= b;\n")), 1)
        self.assertEqual(len(self.cands("a.sql", "SELECT E'\\\\' WHERE a <= b;\n")), 1)

    def test_r13w1_sql_strings_span_lines_and_comments_nest(self):
        self.assertEqual(self.cands("a.sql", "SELECT 'hello\n a <= b\n';\n"), [])
        nested = "/* outer\n /* inner */\n a <= b\n */\nSELECT 1;\n"
        self.assertEqual(self.cands("a.sql", nested), [])
        self.assertEqual(len(self.cands("a.sql", "SELECT 'x' WHERE a <= b;\n")), 1)

    def test_r12w2_sql_dollar_quotes_are_strings(self):
        self.assertEqual(self.cands("a.sql", "SELECT $$a <= b$$;\n"), [])
        tagged = "SELECT $fn$a <= b\n c <= d$fn$ WHERE x <= 1;\n"
        self.assertEqual(
            [c[3] for c in self.cands("a.sql", tagged)],
            [" c <= d$fn$ WHERE x < 1;"],
        )
        self.assertEqual(len(self.cands("a.sql", "SELECT a$1 <= b;\n")), 1)

    def test_code_mask(self):
        cands = self.cands("a.ts", "if (a <= b) log('x <= y') // c <= d\n")
        self.assertEqual([c[3] for c in cands], ["if (a < b) log('x <= y') // c <= d"])
        block = "/* a <= b\n c <= d */\nx = `t <= u\n v <= w`\n"
        self.assertEqual(self.cands("a.js", block), [])
        multi = {
            "a.kt": 'val s = """\na <= b\n"""\n',
            "a.swift": 'let s = """\na <= b\n"""\n',
            "a.java": 'String s = """\na <= b\n""";\n',
            "a.go": "s := `\na <= b\n`\n",
            "a.rs": 'let s = r#"\na <= b\n"#;\nlet t = "x\na <= b\n";\n',
        }
        multi["b.js"] = "const re = /a <= b/;\nif (x) y = /c[/]<= d/g;\n"
        multi["e.js"] = "if (ready) /a <= b/.test(s);\n"
        multi["a.php"] = "<?php\n# a <= b\n"
        multi["r.cpp"] = 'const char* s = R"(inner " quote\na <= b\n)";\n'
        multi["n.rs"] = "/* outer\n /* nested */\n a <= b\n */\nfn f() {}\n"
        multi["a.rb"] = "PATTERN = /a <= b/\n"
        multi["c.sh"] = "cat <<EOF\na <= b\nEOF\n"
        for path, source in multi.items():
            self.assertEqual(self.cands(path, source), [], path)
        self.assertEqual(len(self.cands("a.rs", 'let s = "x";\nif a <= b {}\n')), 1)
        self.assertEqual(self.cands("d.js", "const r = a / b <= c / d;\n"), [])
        self.assertEqual(len(self.cands("d.js", "if (a <= b) {}\n")), 1)
        self.assertEqual(len(self.cands("n.c", "/* a /* b */\nif (a <= b) {}\n")), 1)
        for path in ("src/a.test.ts", "test_x.py", "x_test.go", "FooTest.kt",
                     "README.md", "src/__tests__/a.ts"):  # fmt: skip
            self.assertEqual(self.cands(path, "a <= b\n"), [], path)


INSTALLER = Path(__file__).resolve().parent / "install-trusted.sh"
STUB_INSTALL = """#!/bin/bash
args=()
while [[ $# -gt 0 ]]; do
  case $1 in -o|-g) shift 2 ;; *) args+=("$1"); shift ;; esac
done
exec /usr/bin/install "${args[@]}"
"""
STUB_APPROVER = """#!/bin/bash
# Stands in for a Secure Enclave key: each init makes a new numbered key,
# and public prints the public key of a handle it made, or fails.
case $1 in
  init)
    n=$(( $(cat "$COUNT" 2>/dev/null || echo 0) + 1 ))
    echo $n >"$COUNT"
    echo "enclave-handle-$n" >"$3"
    echo "enclave-public-$n" >"$5" ;;
  public)
    /usr/bin/grep -qx 'enclave-handle-[0-9]*' "$3" || exit 1
    /usr/bin/sed 's/handle/public/' "$3" ;;
esac
"""


@unittest.skipUnless(INSTALLER.is_file(), "install-trusted.sh missing")
class InstallTest(unittest.TestCase):
    """Every run must end with the pinned key's file in place: the file the
    checker signs with must hold the handle that matches the pin."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.home, self.prefix = root / "home", root / "prefix"
        self.keys = self.home / ".config" / "review-gate"
        self.keys.mkdir(parents=True)
        self.etc = self.prefix / "etc" / "review-gate"
        self.count = root / "count"
        for name, body in (("install", STUB_INSTALL), ("approver", STUB_APPROVER)):
            (root / name).write_text(body)
            (root / name).chmod(0o755)
        self.env = {
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "HOME": str(self.home),
            "TMPDIR": f"{root}/",
            "COUNT": str(self.count),
            "REVIEW_GATE_PREFIX": str(self.prefix),
            "REVIEW_GATE_SUDO": "env",
            "REVIEW_GATE_INSTALL": str(root / "install"),
            "REVIEW_GATE_APPROVER_BUILD": str(root / "approver"),
        }
        self.legacy = self.keys / "approver.handle"
        self.public = self.keys / ("approver" + ".pub")

    def tearDown(self):
        subprocess.run(["/usr/bin/chflags", "-R", "nouchg", self.tmp.name])
        self.keys.chmod(0o700)
        self.tmp.cleanup()

    def run_installer(self, *args, **env):
        return subprocess.run(["/bin/bash", str(INSTALLER), *args],
                              env={**self.env, **env},
                              capture_output=True, text=True)  # fmt: skip

    def install(self, *args):
        proc = self.run_installer(*args)
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def script(self, name, body):
        path = Path(self.tmp.name) / name
        path.write_text(body.replace("REAL", self.env["REVIEW_GATE_INSTALL"]))
        path.chmod(0o755)
        return str(path)

    def pinned(self):
        return (self.etc / "approver.pub").read_text()

    def key_file(self, n):
        public = f"enclave-public-{n}\n".encode()
        return self.keys / f"approver-{hashlib.sha256(public).hexdigest()[:16]}.handle"

    def assert_pair(self, n):
        self.assertEqual(self.pinned(), f"enclave-public-{n}\n")
        self.assertEqual(self.key_file(n).read_text(), f"enclave-handle-{n}\n")

    def test_r6b2_first_install_ignores_a_planted_key(self):
        self.legacy.write_text("planted handle\n")
        self.public.write_text("software key\n")
        self.install()
        self.assert_pair(1)
        self.assertEqual(self.public.read_text(), "enclave-public-1\n")
        self.assertEqual(self.legacy.read_text(), "planted handle\n")

    def test_r10b1_install_pins_the_command_path(self):
        self.install()
        pinned = self.etc / "path"
        self.assertEqual(pinned.read_text(), "/usr/bin:/bin:/usr/sbin:/sbin\n")
        wrapper = (self.prefix / "bin" / "review-gate").read_text()
        self.assertIn("env -u DEVELOPER_DIR -u TOOLCHAINS -u SDKROOT", wrapper)
        self.install("--path", "/opt/tools/bin:/usr/bin")
        self.assertEqual(pinned.read_text(), "/opt/tools/bin:/usr/bin\n")
        self.install()
        self.assertEqual(pinned.read_text(), "/opt/tools/bin:/usr/bin\n")
        self.assertEqual(self.run_installer("--path", "bin").returncode, 2)

    def test_reinstall_keeps_the_pinned_key_and_rotate_replaces_it(self):
        self.install()
        self.public.write_text("software key\n")
        self.install()
        self.assert_pair(1)
        self.assertEqual(self.count.read_text().strip(), "1")
        self.assertTrue((self.prefix / "bin" / "review-gate").is_file())
        self.install("--rotate-key")
        self.assert_pair(2)
        self.assertEqual(self.key_file(1).read_text(), "enclave-handle-1\n")

    def test_failed_sudo_on_reinstall_keeps_the_pair(self):
        self.install()
        proc = self.run_installer(REVIEW_GATE_SUDO="/usr/bin/false")
        self.assertNotEqual(proc.returncode, 0)
        self.assert_pair(1)

    def test_failed_sudo_on_rotate_keeps_the_pair(self):
        self.install()
        proc = self.run_installer("--rotate-key", REVIEW_GATE_SUDO="/usr/bin/false")
        self.assertNotEqual(proc.returncode, 0)
        self.assert_pair(1)
        self.assertEqual([p.name for p in self.keys.glob(".approver.*")], [])

    def test_failed_sudo_before_any_pin_does_not_enroll(self):
        proc = self.run_installer(REVIEW_GATE_SUDO="/usr/bin/false")
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertFalse(self.count.exists())  # no new key was made

    def test_unreadable_pin_is_not_treated_as_missing(self):
        self.install()
        # Stands in for root, who can search the directory whatever its mode:
        # run the real test with the directory opened, then close it again.
        root_sudo = self.script(
            "root-sudo",
            f"""#!/bin/bash
if [[ $1 == test ]]; then
  /bin/chmod 755 {self.etc}; /bin/test "${{@:2}}"; rc=$?; /bin/chmod 600 {self.etc}
  exit $rc
fi
exec "$@"
""",
        )
        self.etc.chmod(0o600)
        try:
            proc = self.run_installer(REVIEW_GATE_SUDO=root_sudo)
        finally:
            self.etc.chmod(0o755)
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assert_pair(1)

    def test_a_planted_link_at_the_new_key_path_is_replaced_not_followed(self):
        self.install()
        self.key_file(2).symlink_to(self.key_file(1))
        self.install("--rotate-key")
        self.assert_pair(2)
        self.assertFalse(self.key_file(2).is_symlink())
        self.assertEqual(self.key_file(1).read_text(), "enclave-handle-1\n")

    def test_a_directory_at_the_new_key_path_stops_before_the_pin(self):
        self.install()
        self.key_file(2).mkdir()
        proc = self.run_installer("--rotate-key")
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertEqual(list(self.key_file(2).iterdir()), [])
        self.assert_pair(1)

    def test_a_planted_key_file_does_not_shadow_the_legacy_key(self):
        self.legacy_install()
        self.key_file(1).write_text("planted handle\n")
        self.install()
        self.assert_checker_reads_the_pin()
        self.assertEqual(self.pinned(), "enclave-public-1\n")

    def test_a_planted_key_link_does_not_shadow_the_legacy_key(self):
        self.legacy_install()
        wrong = self.keys / "wrong"
        wrong.write_text("enclave-handle-7\n")
        self.key_file(1).symlink_to(wrong)
        self.install()
        self.assert_checker_reads_the_pin()
        self.assertFalse(self.key_file(1).is_symlink())
        self.assertEqual(wrong.read_text(), "enclave-handle-7\n")

    def linked_legacy_install(self):
        self.legacy_install()
        target = self.keys / "legacy-target.handle"
        self.legacy.rename(target)
        self.legacy.symlink_to(target)

    def test_a_linked_legacy_key_is_moved_on_upgrade(self):
        self.linked_legacy_install()
        self.install()
        self.assert_checker_reads_the_pin()
        self.assertFalse(self.key_file(1).is_symlink())

    def test_a_failed_legacy_key_check_changes_nothing_when_rotating(self):
        self.legacy_install()
        stub = self.env["REVIEW_GATE_APPROVER_BUILD"]
        approver = self.script(
            "public-fails",
            "#!/bin/bash\n[[ $1 == public && $3 == */approver.handle ]] && exit 1\n"
            f'exec {stub} "$@"\n',
        )
        no_mv = self.script(
            "no-mv-sudo", '#!/bin/bash\n[[ $1 == mv ]] && exit 1\nexec "$@"\n'
        )
        proc = self.run_installer(
            "--rotate-key", REVIEW_GATE_SUDO=no_mv, REVIEW_GATE_APPROVER_BUILD=approver
        )
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertIn("Could not check", proc.stderr)
        self.assertNotIn("does not match", proc.stderr)
        self.assertEqual(self.checker.read_text(), "older checker\n")
        self.assertEqual(self.pinned(), "enclave-public-1\n")
        self.assertEqual(self.legacy.read_text(), "enclave-handle-1\n")

    def test_a_check_that_fails_once_is_not_called_a_mismatch(self):
        for args in ((), ("--rotate-key",)):
            with self.subTest(args=args):
                self.legacy_install()
                marker = Path(self.tmp.name) / f"failed-once{len(args)}"
                stub = self.env["REVIEW_GATE_APPROVER_BUILD"]
                approver = self.script(
                    f"public-fails-once{len(args)}",
                    f"#!/bin/bash\nif [[ $1 == public && $3 == */approver.handle && ! -e {marker} ]];"
                    f' then touch {marker}; exit 1; fi\nexec {stub} "$@"\n',
                )
                proc = self.run_installer(*args, REVIEW_GATE_APPROVER_BUILD=approver)
                self.assertEqual(proc.returncode, 2, proc.stderr)
                self.assertIn("Could not check", proc.stderr)
                self.assertNotIn("does not match", proc.stderr)
                self.assertEqual(self.checker.read_text(), "older checker\n")
                self.assertEqual(self.pinned(), "enclave-public-1\n")

    def test_a_wrong_legacy_key_must_be_moved_before_rotating(self):
        self.legacy_install()
        self.legacy.write_text("enclave-handle-7\n")
        proc = self.run_installer("--rotate-key")
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertIn("does not match the pinned key", proc.stderr)
        self.assertEqual(self.checker.read_text(), "older checker\n")
        self.legacy.rename(self.keys / "moved-away.handle")
        self.install("--rotate-key")
        self.assert_checker_reads_the_pin()

    def test_a_linked_legacy_key_survives_a_refused_pin_rename(self):
        self.linked_legacy_install()
        no_mv = self.script(
            "no-mv-sudo", '#!/bin/bash\n[[ $1 == mv ]] && exit 1\nexec "$@"\n'
        )
        proc = self.run_installer("--rotate-key", REVIEW_GATE_SUDO=no_mv)
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(self.pinned(), "enclave-public-1\n")
        self.assert_checker_reads_the_pin()

    def test_a_wrong_key_file_and_no_legacy_key_asks_for_rotate(self):
        self.install()
        self.key_file(1).write_text("enclave-handle-7\n")
        proc = self.run_installer()
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertIn("--rotate-key", proc.stderr)

    def test_a_planted_pin_copy_path_cannot_redirect_the_pin(self):
        for kind in ("symlink", "hardlink"):
            with self.subTest(kind=kind):
                self.install("--rotate-key")
                n = int(self.pinned().strip().split("-")[-1])
                new = self.etc / "approver.pub.new"
                new.unlink(missing_ok=True)
                if kind == "symlink":
                    new.symlink_to(self.etc / "approver.pub")
                else:
                    os.link(self.etc / "approver.pub", new)
                self.install("--rotate-key")
                self.assert_pair(n + 1)
                self.assertFalse(new.exists() or new.is_symlink())

    def test_linked_public_copy_cannot_overwrite_a_key(self):
        self.install()
        self.public.unlink()
        self.public.symlink_to(self.key_file(1))
        self.install("--rotate-key")
        self.assert_pair(2)
        self.assertEqual(self.key_file(1).read_text(), "enclave-handle-1\n")
        self.assertFalse(self.public.is_symlink())

    def test_locked_key_dir_after_the_pin_keeps_a_working_pair(self):
        self.install()
        lock = self.script(
            "lock-install",
            f"""#!/bin/bash
REAL "$@" || exit
[[ ${{@: -1}} == */approver.pub.new ]] && /bin/chmod 500 {self.keys}
exit 0
""",
        )
        proc = self.run_installer("--rotate-key", REVIEW_GATE_INSTALL=lock)
        self.assertNotEqual(proc.returncode, 0)
        self.assert_pair(2)

    def test_immutable_old_key_does_not_block_rotation(self):
        self.install()
        subprocess.run(["/usr/bin/chflags", "uchg", str(self.key_file(1))], check=True)
        self.install("--rotate-key")
        self.assert_pair(2)

    def test_pin_copy_error_after_writing_still_switches(self):
        self.install()
        late = self.script(
            "late-error",
            """#!/bin/bash
REAL "$@" || exit
[[ ${@: -1} == */approver.pub.new ]] && exit 1
exit 0
""",
        )
        proc = self.run_installer("--rotate-key", REVIEW_GATE_INSTALL=late)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assert_pair(2)

    TORN = """#!/bin/bash
if [[ ${@: -1} == */approver.pub.new ]]; then echo torn >"${@: -1}"; exit 1; fi
exec REAL "$@"
"""

    def test_torn_pin_copy_leaves_the_old_pair(self):
        self.install()
        torn = self.script("torn", self.TORN)
        proc = self.run_installer("--rotate-key", REVIEW_GATE_INSTALL=torn)
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assert_pair(1)

    def test_torn_first_pin_leaves_no_pin_and_a_retry_enrolls(self):
        torn = self.script("torn", self.TORN)
        proc = self.run_installer(REVIEW_GATE_INSTALL=torn)
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertFalse((self.etc / "approver.pub").exists())
        self.install()
        self.assert_pair(2)

    def test_refused_pin_rename_keeps_the_old_pair(self):
        self.install()
        no_mv = self.script(
            "no-mv-sudo",
            """#!/bin/bash
[[ $1 == mv ]] && exit 1
exec "$@"
""",
        )
        proc = self.run_installer("--rotate-key", REVIEW_GATE_SUDO=no_mv)
        self.assertNotEqual(proc.returncode, 0)
        self.assert_pair(1)

    def legacy_install(self):
        # An older install: the key at approver.handle and an older checker.
        self.install()
        self.key_file(1).rename(self.legacy)
        self.checker = self.prefix / "libexec" / "review-gate" / "review_gate.py"
        self.checker.write_text("older checker\n")

    def assert_checker_reads_the_pin(self):
        source = INSTALLER.parent / "review_gate.py"
        self.assertEqual(self.checker.read_bytes(), source.read_bytes())
        n = self.pinned().strip().split("-")[-1]
        self.assert_pair(int(n))

    def failing_shasum(self, only=""):
        # A shasum that fails for paths ending in `only` (all paths if empty).
        shim = Path(self.tmp.name) / "shim-bin"
        shim.mkdir()
        (shim / "shasum").write_text(
            f'#!/bin/bash\n[[ ${{@: -1}} == *{only} ]] && exit 1\nexec /usr/bin/shasum "$@"\n'
        )
        (shim / "shasum").chmod(0o755)
        return f"{shim}:{self.env['PATH']}"

    def test_a_failed_hash_of_the_new_key_stops_before_the_pin(self):
        self.legacy_install()
        path = self.failing_shasum("review-gate-install.*/approver.pub")
        proc = self.run_installer("--rotate-key", PATH=path)
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(self.pinned(), "enclave-public-1\n")
        self.assert_checker_reads_the_pin()
        self.assertFalse((self.keys / "approver-.handle").exists())

    def test_a_failed_hash_of_the_pin_stops_before_the_checker(self):
        self.legacy_install()
        proc = self.run_installer(PATH=self.failing_shasum())
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(self.checker.read_text(), "older checker\n")
        self.assertEqual(self.legacy.read_text(), "enclave-handle-1\n")
        self.assertFalse((self.keys / "approver-.handle").exists())

    def test_upgrade_stopped_at_the_checker_copy_keeps_the_old_pin(self):
        self.legacy_install()
        stop = self.script(
            "stop-checker",
            """#!/bin/bash
[[ ${@: -1} == */review_gate.py ]] && exit 1
exec REAL "$@"
""",
        )
        proc = self.run_installer("--rotate-key", REVIEW_GATE_INSTALL=stop)
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(self.checker.read_text(), "older checker\n")
        self.assertEqual(self.pinned(), "enclave-public-1\n")
        self.assertEqual(self.legacy.read_text(), "enclave-handle-1\n")
        self.assertEqual(self.key_file(1).read_text(), "enclave-handle-1\n")

    def test_upgrade_rotation_that_stops_after_the_pin_has_the_new_checker(self):
        self.legacy_install()
        lock = self.script(
            "lock-install",
            f"""#!/bin/bash
REAL "$@" || exit
[[ ${{@: -1}} == */approver.pub.new ]] && /bin/chmod 500 {self.keys}
exit 0
""",
        )
        proc = self.run_installer("--rotate-key", REVIEW_GATE_INSTALL=lock)
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(self.pinned(), "enclave-public-2\n")
        self.assert_checker_reads_the_pin()

    def test_upgrade_rotation_refused_at_the_pin_keeps_a_working_old_key(self):
        self.legacy_install()
        no_mv = self.script(
            "no-mv-sudo", '#!/bin/bash\n[[ $1 == mv ]] && exit 1\nexec "$@"\n'
        )
        proc = self.run_installer("--rotate-key", REVIEW_GATE_SUDO=no_mv)
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(self.pinned(), "enclave-public-1\n")
        self.assert_checker_reads_the_pin()

    def test_legacy_key_gets_its_fingerprint_name(self):
        self.install()
        self.key_file(1).rename(self.legacy)
        self.install()
        self.assert_pair(1)

    def test_pinned_key_without_its_file_asks_for_rotate(self):
        self.install()
        self.key_file(1).unlink()
        proc = self.run_installer()
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertIn("--rotate-key", proc.stderr)
        self.install("--rotate-key")
        self.assert_pair(2)

    def test_checker_signs_with_the_pinned_keys_file(self):
        saved = rg.TRUST_DIR, rg.KEY_DIR, rg.APPROVER_KEY
        self.addCleanup(lambda: setattr_all(saved))
        rg.TRUST_DIR, rg.KEY_DIR, rg.APPROVER_KEY = self.etc, self.keys, None
        self.install()
        self.assertEqual(rg.approver_key(), self.key_file(1))
        self.install("--rotate-key")
        self.assertEqual(rg.approver_key(), self.key_file(2))


def setattr_all(saved):
    rg.TRUST_DIR, rg.KEY_DIR, rg.APPROVER_KEY = saved


if __name__ == "__main__":
    unittest.main()
