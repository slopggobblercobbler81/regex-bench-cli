"""Unit tests for ReDoS analyzer and catastrophic backtracking heuristics."""

import unittest
from regex_bench.analyzer import (
    ComplexityType,
    ReDoSAnalyzer,
    ReDoSRiskLevel,
    analyze_redos,
)


class TestReDoSAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = ReDoSAnalyzer(timeout_per_trial=0.3)

    def test_safe_pattern(self):
        res = self.analyzer.analyze(r"^[a-zA-Z0-9_-]+$", dynamic_verify=False)
        self.assertEqual(res.risk_level, ReDoSRiskLevel.SAFE)
        self.assertEqual(res.risk_score, 0)
        self.assertEqual(res.findings, [])

    def test_nested_quantifiers_detection(self):
        res = self.analyzer.analyze(r"(a+)+$", dynamic_verify=False)
        self.assertIn(res.risk_level, (ReDoSRiskLevel.HIGH, ReDoSRiskLevel.CATASTROPHIC))
        types = [f.vuln_type for f in res.findings]
        self.assertIn("nested_quantifiers", types)

    def test_overlapping_alternation_detection(self):
        res = self.analyzer.analyze(r"(a|a)+$", dynamic_verify=False)
        types = [f.vuln_type for f in res.findings]
        self.assertIn("overlapping_alternation_in_repeat", types)
        self.assertIn(res.risk_level, (ReDoSRiskLevel.HIGH, ReDoSRiskLevel.CATASTROPHIC))

    def test_adjacent_quantifiers_detection(self):
        res = self.analyzer.analyze(r".*.*$", dynamic_verify=False)
        types = [f.vuln_type for f in res.findings]
        self.assertIn("adjacent_overlapping_quantifiers", types)
        self.assertGreaterEqual(res.risk_score, 50)

    def test_dynamic_verification_timeout(self):
        res = self.analyzer.analyze(r"(a+)+$", dynamic_verify=True)
        self.assertEqual(res.risk_level, ReDoSRiskLevel.CATASTROPHIC)
        self.assertTrue(res.dynamic_verified)
        self.assertEqual(res.estimated_complexity, ComplexityType.EXPONENTIAL)
        self.assertTrue(len(res.timing_points) > 0)
        self.assertTrue(any(tp.timed_out for tp in res.timing_points) or res.dynamic_growth == ComplexityType.EXPONENTIAL)

    def test_payload_generation(self):
        res = self.analyzer.analyze(r"(a+)+$", dynamic_verify=False)
        self.assertTrue(len(res.sample_payloads) >= 1)
        self.assertTrue(any("!" in p for p in res.sample_payloads))

    def test_syntax_error_handled(self):
        res = self.analyzer.analyze(r"(unclosed group[a-z", dynamic_verify=False)
        self.assertEqual(res.risk_level, ReDoSRiskLevel.SAFE)
        self.assertEqual(res.findings[0].vuln_type, "syntax_error")

    def test_to_dict_serialization(self):
        res = analyze_redos(r"^[0-9]+$", dynamic_verify=False)
        d = res.to_dict()
        self.assertIn("pattern", d)
        self.assertIn("risk_level", d)
        self.assertIn("findings", d)
        self.assertIn("sample_payloads", d)


if __name__ == "__main__":
    unittest.main()
