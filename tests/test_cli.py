"""Unit tests for the CLI interface commands and flags."""

import io
import json
import unittest
from contextlib import redirect_stdout
from regex_bench.cli import main


class TestCLI(unittest.TestCase):
    def test_help(self):
        f = io.StringIO()
        with self.assertRaises(SystemExit) as cm:
            with redirect_stdout(f):
                main(["--help"])
        self.assertEqual(cm.exception.code, 0)
        self.assertIn("regex-bench", f.getvalue())

    def test_version(self):
        f = io.StringIO()
        with self.assertRaises(SystemExit) as cm:
            with redirect_stdout(f):
                main(["--version"])
        self.assertEqual(cm.exception.code, 0)
        self.assertIn("regex-bench", f.getvalue())

    def test_analyze_cmd_json(self):
        f = io.StringIO()
        with redirect_stdout(f):
            code = main(["analyze", "(a+)+$", "--no-dynamic", "--json"])
        self.assertEqual(code, 0)
        data = json.loads(f.getvalue())
        self.assertEqual(data["pattern"], "(a+)+$")
        self.assertIn(data["risk_level"], ["HIGH", "CATASTROPHIC"])

    def test_bench_cmd_json(self):
        f = io.StringIO()
        with redirect_stdout(f):
            code = main(["bench", "[a-z]+", "hello", "world", "-n", "10", "--json"])
        self.assertEqual(code, 0)
        data = json.loads(f.getvalue())
        self.assertEqual(len(data["items"]), 2)
        self.assertIn("ops_per_second", data["items"][0]["stats"])

    def test_inspect_cmd_json(self):
        f = io.StringIO()
        with redirect_stdout(f):
            code = main(["inspect", r"(\d+)-(\d+)", "123-456", "--json"])
        self.assertEqual(code, 0)
        data = json.loads(f.getvalue())
        self.assertTrue(data["matched"])
        self.assertEqual(len(data["matches"][0]["groups"]), 2)

    def test_test_cmd_success(self):
        f = io.StringIO()
        with redirect_stdout(f):
            code = main(["test", r"^\d+$", "12345", "--no-color"])
        self.assertEqual(code, 0)
        self.assertIn("PASSED", f.getvalue())

    def test_test_cmd_failure(self):
        f = io.StringIO()
        with redirect_stdout(f):
            code = main(["test", r"^\d+$", "abc", "--no-color"])
        self.assertEqual(code, 1)
        self.assertIn("FAILED", f.getvalue())

    def test_run_cmd(self):
        f = io.StringIO()
        with redirect_stdout(f):
            code = main(["run", "examples/email_suite.json", "--no-color"])
        self.assertEqual(code, 0)
        self.assertIn("ALL TESTS PASSED", f.getvalue())


if __name__ == "__main__":
    unittest.main()
