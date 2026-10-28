"""chatgpt-guard tests: run the hook as a subprocess with sample JSON."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

GUARD = str(Path(__file__).with_name("chatgpt-guard.py"))


def run(command, tool="Bash"):
    payload = json.dumps({"tool_name": tool, "tool_input": {"command": command}})
    r = subprocess.run(
        [sys.executable, "-I", GUARD], input=payload, capture_output=True, text=True
    )
    return r.returncode, r.stderr


class GuardTests(unittest.TestCase):
    def blocked(self, cmd, tool="Bash"):
        code, err = run(cmd, tool)
        self.assertEqual(code, 2, cmd)
        self.assertIn("gpt-chat", err)

    def allowed(self, cmd, tool="Bash"):
        self.assertEqual(run(cmd, tool)[0], 0, cmd)

    def test_blocks_direct_access(self):
        self.blocked(
            'ego-browser nodejs -e \'await task.page("p1").goto("https://chatgpt.com/")\''
        )
        self.blocked(
            "ego-browser nodejs <<'EOF'\nawait page.goto('https://chat.openai.com')\nEOF"
        )
        self.blocked("curl -s https://chatgpt.com/backend-api/conversations")
        self.blocked("agent-browser open https://auth.openai.com/log-in")
        self.blocked(
            'osascript -e \'tell app "Safari" to open location "https://chatgpt.com"\''
        )
        self.blocked("npx playwright open chatgpt.com")
        self.blocked("open https://chatgpt.com")
        self.blocked("echo hi; curl https://chatgpt.com")
        self.blocked("gpt-chat status; curl https://chatgpt.com/c/x")  # chained bypass
        self.blocked("curl https://chatgpt.com", tool="exec_command")

    def test_blocks_script_file_mentioning_chatgpt(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "x.mjs")
            Path(p).write_text('await page.goto("https://chatgpt.com/")')
            self.blocked(f"ego-browser nodejs < {p}")
            self.blocked(f"ego-browser nodejs -e \"await import('file://{p}')\"")

    def test_allows_gpt_chat(self):
        self.allowed("gpt-chat send 'hello'")
        self.allowed(
            "./scripts/gpt-chat read https://chatgpt.com/c/abcdefgh12"
        )
        self.allowed(
            "HERDR_PANE_ID=w1:p1 gpt-chat send - <<'EOF'\nwhy does curl https://chatgpt.com fail?\nEOF"
        )
        self.allowed('gpt-chat send "compare ego-browser and chatgpt.com apis"')

    def test_allows_unrelated(self):
        self.allowed("ego-browser nodejs -e 'await page.goto(\"https://example.com\")'")
        self.allowed("curl https://example.com")
        self.allowed("rg chatgpt.com docs/")
        self.allowed("git log --oneline")
        self.allowed("cat notes/chatgpt.com.md")
        self.allowed("echo opening chatgpt.com later")
        self.allowed(
            "cat > doc.md <<'EOF'\nDon't use ego-browser or curl for chatgpt.com; use gpt-chat\nEOF"
        )

    def test_ignores_other_tools_and_bad_input(self):
        self.allowed("curl https://chatgpt.com", tool="Read")
        r = subprocess.run(
            [sys.executable, "-I", GUARD],
            input="not json",
            capture_output=True,
            text=True,
        )
        self.assertEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main()
