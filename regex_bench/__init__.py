"""regex-bench-cli: Terminal utility for testing regular expressions, evaluating catastrophic backtracking risks, and inspecting match captures."""

__version__ = "0.1.0"
__author__ = "slopggobblercobbler81"
__license__ = "MIT"

from regex_bench.analyzer import ReDoSAnalyzer, analyze_redos, ReDoSRiskLevel
from regex_bench.benchmark import RegexBenchmark, benchmark_regex
from regex_bench.inspector import RegexInspector, inspect_match
from regex_bench.tester import TestSuiteRunner, run_test_suite

__all__ = [
    "ReDoSAnalyzer",
    "analyze_redos",
    "ReDoSRiskLevel",
    "RegexBenchmark",
    "benchmark_regex",
    "RegexInspector",
    "inspect_match",
    "TestSuiteRunner",
    "run_test_suite",
    "__version__",
]
