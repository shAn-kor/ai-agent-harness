"""role_lessons tests in a throwaway lesson root."""

import importlib.util
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "role_lessons", Path(__file__).with_name("role_lessons.py")
)
rl = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rl)


def run(argv):
    buf = StringIO()
    with redirect_stdout(buf):
        rl.main(argv)
    return buf.getvalue().strip()


class RoleLessonsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        rl.ROOT = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def propose(self):
        return run(
            [
                "propose",
                "--role",
                "reviewer",
                "--lesson",
                "Check auth on every new route.",
                "--evidence",
                "records/r1.yaml",
            ]
        )

    def test_promotion_requires_user_approval(self):
        cid = self.propose()
        with self.assertRaises(SystemExit):
            run(["promote", cid])
        self.assertFalse((rl.ROOT / "reviewer.md").exists())
        run(["promote", cid, "--approved-by-user"])
        text = (rl.ROOT / "reviewer.md").read_text()
        self.assertIn("Check auth on every new route.", text)
        self.assertIn("records/r1.yaml", text)

    def test_candidate_needs_evidence_and_known_role(self):
        with self.assertRaises(SystemExit):
            run(["propose", "--role", "reviewer", "--lesson", "x"])
        with self.assertRaises(SystemExit):
            run(["propose", "--role", "boss", "--lesson", "x", "--evidence", "e"])

    def test_rejected_candidate_cannot_be_promoted(self):
        cid = self.propose()
        run(["reject", cid])
        with self.assertRaises(SystemExit):
            run(["promote", cid, "--approved-by-user"])
        self.assertEqual(run(["list"]), "[]")


if __name__ == "__main__":
    unittest.main()
