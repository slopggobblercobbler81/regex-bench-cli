"""Unit tests for test suite execution and assertions."""

import json
import tempfile
import unittest
from pathlib import Path
from regex_bench.tester import TestSuiteRunner, run_test_suite


class TestSuiteRunnerTests(unittest.TestCase):
    def setUp(self):
        self.runner = TestSuiteRunner()

    def test_all_passing_suite(self):
        suite = {
            "name": "Math operations",
            "pattern": r"^(\d+)\s*([+\-*/])\s*(\d+)$",
            "tests": [
                {
                    "name": "addition",
                    "input": "12 + 34",
                    "should_match": True,
                    "groups": ["12", "+", "34"],
                },
                {
                    "name": "invalid",
                    "input": "12 plus 34",
                    "should_match": False,
                },
            ],
        }
        report = self.runner.run_suite_data(suite)
        self.assertTrue(report.all_passed)
        self.assertEqual(report.passed_count, 2)
        self.assertEqual(report.failed_count, 0)

    def test_failing_match_assertion(self):
        suite = {
            "name": "Failure test",
            "pattern": r"^[a-z]+$",
            "tests": [
                {
                    "name": "expected false got true",
                    "input": "abc",
                    "should_match": False,
                }
            ],
        }
        report = self.runner.run_suite_data(suite)
        self.assertFalse(report.all_passed)
        self.assertEqual(report.failed_count, 1)
        self.assertIn("Match mismatch", report.results[0].failure_reasons[0])

    def test_group_mismatch_assertion(self):
        suite = {
            "name": "Group mismatch",
            "pattern": r"^(\w+):(\w+)$",
            "tests": [
                {
                    "name": "wrong group 2",
                    "input": "key:val",
                    "should_match": True,
                    "groups": ["key", "wrong"],
                }
            ],
        }
        report = self.runner.run_suite_data(suite)
        self.assertFalse(report.all_passed)
        self.assertEqual(report.failed_count, 1)
        self.assertIn("Group #2 mismatch", report.results[0].failure_reasons[0])

    def test_named_group_assertion(self):
        suite = {
            "name": "Named groups",
            "pattern": r"^(?P<id>\d+)$",
            "tests": [
                {
                    "name": "correct id",
                    "input": "42",
                    "should_match": True,
                    "named_groups": {"id": "42"},
                },
                {
                    "name": "wrong id expected",
                    "input": "42",
                    "should_match": True,
                    "named_groups": {"id": "99"},
                },
            ],
        }
        report = self.runner.run_suite_data(suite)
        self.assertFalse(report.all_passed)
        self.assertEqual(report.passed_count, 1)
        self.assertEqual(report.failed_count, 1)

    def test_run_suite_from_file(self):
        suite_data = {
            "name": "File suite",
            "pattern": r"^\d+$",
            "tests": [{"name": "num", "input": "123", "should_match": True}],
        }
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
            json.dump(suite_data, tf)
            tf_path = tf.name

        try:
            report = run_test_suite(tf_path)
            self.assertTrue(report.all_passed)
            self.assertEqual(report.total_tests, 1)
        finally:
            Path(tf_path).unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
