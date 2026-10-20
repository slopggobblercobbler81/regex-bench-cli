"""Test suite execution engine for regular expression verification."""

import concurrent.futures
import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Union


@dataclass
class TestCaseResult:
    name: str
    input_text: str
    status: str  # "PASSED", "FAILED", "TIMEOUT", "ERROR"
    duration_ms: float
    matched: bool
    expected_match: bool
    failure_reasons: List[str] = field(default_factory=list)
    actual_groups: List[Optional[str]] = field(default_factory=list)
    actual_named_groups: Dict[str, Optional[str]] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "input_text": self.input_text,
            "status": self.status,
            "duration_ms": round(self.duration_ms, 3),
            "matched": self.matched,
            "expected_match": self.expected_match,
            "failure_reasons": self.failure_reasons,
            "actual_groups": self.actual_groups,
            "actual_named_groups": self.actual_named_groups,
        }


@dataclass
class TestSuiteReport:
    suite_name: str
    pattern: str
    flags: int
    total_tests: int
    passed_count: int
    failed_count: int
    timeout_count: int
    error_count: int
    total_duration_ms: float
    all_passed: bool
    results: List[TestCaseResult] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "suite_name": self.suite_name,
            "pattern": self.pattern,
            "flags": self.flags,
            "total_tests": self.total_tests,
            "passed_count": self.passed_count,
            "failed_count": self.failed_count,
            "timeout_count": self.timeout_count,
            "error_count": self.error_count,
            "total_duration_ms": round(self.total_duration_ms, 3),
            "all_passed": self.all_passed,
            "results": [r.to_dict() for r in self.results],
        }


class TestSuiteRunner:
    """Executes a test suite against a regular expression pattern."""

    def __init__(self, default_timeout_sec: float = 2.0):
        self.default_timeout_sec = default_timeout_sec

    def run_suite_data(self, data: Dict[str, Any]) -> TestSuiteReport:
        suite_name = data.get("name", "Unnamed Test Suite")
        pattern = data.get("pattern", "")
        if not pattern:
            raise ValueError("Test suite must specify a 'pattern'")

        # Parse flags
        flags_spec = data.get("flags", [])
        flag_val = 0
        if isinstance(flags_spec, list):
            for f in flags_spec:
                f_upper = str(f).upper()
                if hasattr(re, f_upper):
                    flag_val |= getattr(re, f_upper)
        elif isinstance(flags_spec, int):
            flag_val = flags_spec

        test_cases = data.get("tests", [])
        compiled = re.compile(pattern, flag_val)

        results: List[TestCaseResult] = []
        start_suite = time.perf_counter()

        passed_count = 0
        failed_count = 0
        timeout_count = 0
        error_count = 0

        def timed_call(fn, arg):
            t_start = time.perf_counter()
            res = fn(arg)
            t_end = time.perf_counter()
            return res, (t_end - t_start) * 1000.0

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            for idx, tc in enumerate(test_cases):
                tc_name = tc.get("name", f"Test #{idx + 1}")
                inp = tc.get("input", "")
                expected_match = tc.get("should_match", True)
                expected_groups = tc.get("groups", None)
                expected_named = tc.get("named_groups", None)
                max_ms = tc.get("max_ms", None)
                method_name = tc.get("method", "search").lower()
                timeout_sec = tc.get("timeout_sec", self.default_timeout_sec)

                func = getattr(compiled, method_name, compiled.search)

                status = "PASSED"
                failure_reasons: List[str] = []
                actual_groups: List[Optional[str]] = []
                actual_named: Dict[str, Optional[str]] = {}
                matched = False
                dur_ms = 0.0

                future = executor.submit(timed_call, func, inp)
                try:
                    match_obj, dur_ms = future.result(timeout=timeout_sec)

                    if match_obj is not None:
                        matched = True
                        actual_groups = list(match_obj.groups())
                        actual_named = match_obj.groupdict()

                    # Verification assertions
                    if matched != expected_match:
                        failure_reasons.append(
                            f"Match mismatch: expected should_match={expected_match}, got {matched}"
                        )
                        status = "FAILED"

                    # Group assertions if matched and specified
                    if matched and expected_groups is not None:
                        if isinstance(expected_groups, list):
                            for g_idx, exp_val in enumerate(expected_groups):
                                if g_idx >= len(actual_groups):
                                    failure_reasons.append(
                                        f"Group #{g_idx + 1} missing: expected {exp_val!r}, but only {len(actual_groups)} groups exist"
                                    )
                                    status = "FAILED"
                                elif actual_groups[g_idx] != exp_val:
                                    failure_reasons.append(
                                        f"Group #{g_idx + 1} mismatch: expected {exp_val!r}, got {actual_groups[g_idx]!r}"
                                    )
                                    status = "FAILED"

                    # Named groups assertion
                    if matched and expected_named is not None:
                        for name, exp_val in expected_named.items():
                            act_val = actual_named.get(name)
                            if act_val != exp_val:
                                failure_reasons.append(
                                    f"Named group {name!r} mismatch: expected {exp_val!r}, got {act_val!r}"
                                )
                                status = "FAILED"

                    # Max execution time assertion
                    if max_ms is not None and dur_ms > max_ms:
                        failure_reasons.append(
                            f"Performance threshold exceeded: took {dur_ms:.2f}ms, limit was {max_ms:.2f}ms"
                        )
                        status = "FAILED"

                except concurrent.futures.TimeoutError:
                    dur_ms = timeout_sec * 1000.0
                    failure_reasons.append(f"Timed out after {timeout_sec:.2f}s")
                    status = "TIMEOUT"
                except Exception as e:
                    dur_ms = 0.0
                    failure_reasons.append(f"Execution error: {e}")
                    status = "ERROR"

                if status == "PASSED":
                    passed_count += 1
                elif status == "FAILED":
                    failed_count += 1
                elif status == "TIMEOUT":
                    timeout_count += 1
                elif status == "ERROR":
                    error_count += 1

                results.append(
                    TestCaseResult(
                        name=tc_name,
                        input_text=inp,
                        status=status,
                        duration_ms=dur_ms,
                        matched=matched,
                        expected_match=expected_match,
                        failure_reasons=failure_reasons,
                        actual_groups=actual_groups,
                        actual_named_groups=actual_named,
                    )
                )

        total_suite_ms = (time.perf_counter() - start_suite) * 1000.0
        all_passed = failed_count == 0 and timeout_count == 0 and error_count == 0

        return TestSuiteReport(
            suite_name=suite_name,
            pattern=pattern,
            flags=flag_val,
            total_tests=len(test_cases),
            passed_count=passed_count,
            failed_count=failed_count,
            timeout_count=timeout_count,
            error_count=error_count,
            total_duration_ms=total_suite_ms,
            all_passed=all_passed,
            results=results,
        )

    def run_suite_file(self, file_path: Union[str, Path]) -> TestSuiteReport:
        p = Path(file_path)
        if not p.exists():
            raise FileNotFoundError(f"Suite file not found: {p}")

        content = p.read_text(encoding="utf-8")
        if p.suffix.lower() in (".yaml", ".yml"):
            try:
                import yaml
                data = yaml.safe_load(content)
            except ImportError:
                # Basic JSON fallback or notify
                raise ImportError("PyYAML is required to parse YAML suite files. Run `pip install pyyaml` or use JSON format.")
        else:
            data = json.loads(content)

        return self.run_suite_data(data)


def run_test_suite(suite_data_or_path: Union[Dict[str, Any], str, Path]) -> TestSuiteReport:
    """Helper function to run regex test suite."""
    runner = TestSuiteRunner()
    if isinstance(suite_data_or_path, (str, Path)):
        return runner.run_suite_file(suite_data_or_path)
    return runner.run_suite_data(suite_data_or_path)
