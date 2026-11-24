"""Tests for gitpython_rce_check.py (stdlib unittest only).

Run:  python3 -m unittest discover -s tests -v
  or:  python3 tests/run_tests.py
"""
import io
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import gitpython_rce_check as chk


def write(tmp, name, text):
    p = Path(tmp) / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


class TestVersionGate(unittest.TestCase):
    def test_3130_vulnerable(self):
        state, _ = chk.version_status("3.1.30")
        self.assertEqual(state, "vulnerable")

    def test_3162_vulnerable(self):
        state, _ = chk.version_status("3.1.62")
        self.assertEqual(state, "vulnerable")

    def test_320_fixed_boundary(self):
        state, _ = chk.version_status("3.2.0")
        self.assertEqual(state, "fixed")

    def test_321_fixed(self):
        state, _ = chk.version_status("3.2.1")
        self.assertEqual(state, "fixed")

    def test_300_vulnerable(self):
        state, _ = chk.version_status("3.0.0")
        self.assertEqual(state, "vulnerable")

    def test_not_installed_unknown(self):
        state, detail = chk.version_status(None)
        self.assertEqual(state, "unknown")
        self.assertIn("not installed", detail)

    def test_parse_version_ignores_suffix(self):
        self.assertEqual(chk.parse_version("3.2.0.post1"), (3, 2, 0))
        self.assertEqual(chk.parse_version("3.1.30"), (3, 1, 30))


class TestAstScan(unittest.TestCase):
    def scan(self, tmp, files):
        for name, text in files.items():
            write(tmp, name, text)
        return chk.scan_directory(tmp)

    def test_tainted_param_pull_is_dangerous(self):
        with tempfile.TemporaryDirectory() as tmp:
            findings, skipped = self.scan(tmp, {
                "deploy.py": "def deploy(repo, user_input):\n"
                             "    repo.remotes.origin.pull(user_input)\n",
            })
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["status"], "DANGEROUS")
            self.assertEqual(findings[0]["call"], "Remote.pull")
            self.assertEqual(findings[0]["line"], 2)

    def test_tainted_param_checkout_is_dangerous(self):
        with tempfile.TemporaryDirectory() as tmp:
            findings, _ = self.scan(tmp, {
                "sync.py": "def go(repo, branch_name):\n"
                           "    repo.head.checkout(branch_name)\n",
            })
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["call"], "Head.checkout")
            self.assertEqual(findings[0]["status"], "DANGEROUS")

    def test_sys_argv_assignment_is_dangerous(self):
        with tempfile.TemporaryDirectory() as tmp:
            findings, _ = self.scan(tmp, {
                "cli.py": "import sys\n"
                          "refspec = sys.argv[1]\n"
                          "def go(repo):\n"
                          "    repo.remotes.origin.pull(refspec)\n",
            })
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["status"], "DANGEROUS")

    def test_os_environ_is_dangerous(self):
        with tempfile.TemporaryDirectory() as tmp:
            findings, _ = self.scan(tmp, {
                "env.py": "import os\n"
                          "def go(repo):\n"
                          "    repo.remotes.origin.pull(os.environ['REF'])\n",
            })
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["status"], "DANGEROUS")

    def test_constant_string_never_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            findings, _ = self.scan(tmp, {
                "safe.py": "def go(repo):\n"
                           "    repo.remotes.origin.pull(\"main\")\n"
                           "    repo.head.checkout(\"main\")\n",
            })
            self.assertEqual(findings, [])

    def test_constant_local_assignment_not_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            findings, _ = self.scan(tmp, {
                "safe.py": "def go(repo):\n"
                           "    branch = \"main\"\n"
                           "    repo.head.checkout(branch)\n",
            })
            self.assertEqual(findings, [])

    def test_untainted_param_is_review_not_dangerous(self):
        with tempfile.TemporaryDirectory() as tmp:
            findings, _ = self.scan(tmp, {
                "x.py": "def go(repo, tag):\n"
                        "    repo.remotes.origin.pull(tag)\n",
            })
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["status"], "REVIEW")

    def test_multi_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            findings, _ = self.scan(tmp, {
                "a.py": "def f(repo, user_input):\n"
                        "    repo.remotes.origin.pull(user_input)\n",
                "sub/b.py": "def g(repo, branch):\n"
                            "    repo.head.checkout(branch)\n",
                "c.py": "def h(repo):\n"
                        "    repo.remotes.origin.pull(\"main\")\n",
            })
            self.assertEqual(len(findings), 2)
            self.assertEqual({f["file"] for f in findings}, {"a.py", "sub/b.py"})

    def test_empty_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            findings, skipped = chk.scan_directory(tmp)
            self.assertEqual(findings, [])
            self.assertEqual(skipped, [])

    def test_syntax_error_file_skipped_no_crash(self):
        with tempfile.TemporaryDirectory() as tmp:
            findings, skipped = self.scan(tmp, {
                "broken.py": "def oops(:\n",
                "good.py": "def f(repo, user_input):\n"
                           "    repo.remotes.origin.pull(user_input)\n",
            })
            self.assertEqual(skipped, ["broken.py"])
            self.assertEqual(len(findings), 1)

    def test_non_py_files_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            findings, _ = self.scan(tmp, {
                "notes.txt": "repo.remotes.origin.pull(user_input)\n",
            })
            self.assertEqual(findings, [])


class TestExitCodesAndDemo(unittest.TestCase):
    def test_safe_repo_exit_0(self):
        with tempfile.TemporaryDirectory() as tmp:
            write(tmp, "sync.py", "def go(repo):\n"
                  "    repo.remotes.origin.pull(\"main\")\n")
            code = chk.main([tmp, "--gitpython-version", "3.2.0"])
            self.assertEqual(code, 0)

    def test_vuln_version_exit_1(self):
        with tempfile.TemporaryDirectory() as tmp:
            write(tmp, "sync.py", "def go(repo):\n"
                  "    repo.remotes.origin.pull(\"main\")\n")
            code = chk.main([tmp, "--gitpython-version", "3.1.30"])
            self.assertEqual(code, 1)

    def test_dangerous_call_exit_1_even_with_fixed_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            write(tmp, "d.py", "def f(repo, user_input):\n"
                  "    repo.remotes.origin.pull(user_input)\n")
            code = chk.main([tmp, "--gitpython-version", "3.2.0"])
            self.assertEqual(code, 1)

    def test_not_a_directory_exit_2(self):
        self.assertEqual(chk.main(["/nonexistent-dir-xyz"]), 2)

    def test_demo_deterministic(self):
        buf1, buf2 = io.StringIO(), io.StringIO()
        self.assertEqual(chk.run_demo(buf1), 1)
        self.assertEqual(chk.run_demo(buf2), 1)
        self.assertEqual(buf1.getvalue(), buf2.getvalue())
        self.assertIn("deploy.py:42", buf1.getvalue())
        self.assertIn("deploy.py:57", buf1.getvalue())
        self.assertIn("VULNERABLE", buf1.getvalue())
        self.assertIn("PASS", buf1.getvalue())

    def test_demo_matches_fixture_scan(self):
        base = Path(__file__).resolve().parent.parent / "fixtures"
        findings, _ = chk.scan_directory(base / "vuln-repo")
        dangerous = [f for f in findings if f["status"] == "DANGEROUS"]
        self.assertEqual(len(dangerous), 3)
        self.assertEqual({(f["line"], f["call"]) for f in dangerous},
                         {(42, "Remote.pull"), (57, "Head.checkout"),
                          (70, "Remote.pull")})
        safe_findings, _ = chk.scan_directory(base / "safe-repo")
        self.assertEqual(safe_findings, [])


if __name__ == "__main__":
    unittest.main()
