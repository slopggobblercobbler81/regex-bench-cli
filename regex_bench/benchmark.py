"""Microbenchmarking and performance profiling engine for regular expressions."""

import statistics
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional
import re


@dataclass
class BenchmarkStats:
    iterations: int
    total_time_ms: float
    min_us: float
    max_us: float
    mean_us: float
    median_us: float
    p90_us: float
    p95_us: float
    p99_us: float
    stdev_us: float
    ops_per_second: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "iterations": self.iterations,
            "total_time_ms": round(self.total_time_ms, 3),
            "min_us": round(self.min_us, 3),
            "max_us": round(self.max_us, 3),
            "mean_us": round(self.mean_us, 3),
            "median_us": round(self.median_us, 3),
            "p90_us": round(self.p90_us, 3),
            "p95_us": round(self.p95_us, 3),
            "p99_us": round(self.p99_us, 3),
            "stdev_us": round(self.stdev_us, 3),
            "ops_per_second": round(self.ops_per_second, 1),
        }


@dataclass
class BenchmarkItemResult:
    input_text: str
    matched: bool
    match_count: int
    stats: BenchmarkStats

    def to_dict(self) -> Dict[str, Any]:
        return {
            "input_text": self.input_text,
            "matched": self.matched,
            "match_count": self.match_count,
            "stats": self.stats.to_dict(),
        }


@dataclass
class ScalingStepResult:
    length: int
    mean_us: float
    ops_per_second: float


@dataclass
class BenchmarkResult:
    pattern: str
    flags: int
    method: str
    items: List[BenchmarkItemResult] = field(default_factory=list)
    scaling_curve: List[ScalingStepResult] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pattern": self.pattern,
            "flags": self.flags,
            "method": self.method,
            "items": [item.to_dict() for item in self.items],
            "scaling_curve": [
                {
                    "length": step.length,
                    "mean_us": round(step.mean_us, 3),
                    "ops_per_second": round(step.ops_per_second, 1),
                }
                for step in self.scaling_curve
            ],
        }


class RegexBenchmark:
    """Benchmark runner for measuring regex match speed and throughput."""

    def __init__(
        self,
        iterations: int = 1000,
        warmup: int = 50,
        method: str = "search",
    ):
        self.iterations = iterations
        self.warmup = warmup
        self.method = method.lower()

    def run(
        self,
        pattern: str,
        test_strings: List[str],
        flags: int = 0,
        run_scaling: bool = False,
    ) -> BenchmarkResult:
        compiled = re.compile(pattern, flags)
        func: Callable[[str], Any]

        if self.method == "match":
            func = compiled.match
        elif self.method == "fullmatch":
            func = compiled.fullmatch
        elif self.method == "findall":
            func = compiled.findall
        elif self.method == "finditer":
            func = lambda s: list(compiled.finditer(s))
        else:
            func = compiled.search

        item_results: List[BenchmarkItemResult] = []

        for text in test_strings:
            # Check match status and count
            res = func(text)
            matched = False
            match_count = 0
            if res is not None:
                if isinstance(res, list):
                    match_count = len(res)
                    matched = match_count > 0
                else:
                    matched = True
                    match_count = 1

            # Warmup runs
            for _ in range(self.warmup):
                func(text)

            # Measurement runs
            durations_us: List[float] = []
            start_total = time.perf_counter()

            for _ in range(self.iterations):
                t0 = time.perf_counter()
                func(text)
                t1 = time.perf_counter()
                durations_us.append((t1 - t0) * 1_000_000.0)

            total_ms = (time.perf_counter() - start_total) * 1000.0
            durations_us.sort()

            mean_val = statistics.mean(durations_us)
            median_val = statistics.median(durations_us)
            min_val = durations_us[0]
            max_val = durations_us[-1]
            stdev_val = statistics.stdev(durations_us) if len(durations_us) > 1 else 0.0

            def percentile(sorted_list: List[float], p: float) -> float:
                idx = int(len(sorted_list) * p)
                idx = min(idx, len(sorted_list) - 1)
                return sorted_list[idx]

            p90_val = percentile(durations_us, 0.90)
            p95_val = percentile(durations_us, 0.95)
            p99_val = percentile(durations_us, 0.99)

            total_seconds = total_ms / 1000.0
            ops_sec = self.iterations / total_seconds if total_seconds > 0 else 0.0

            stats = BenchmarkStats(
                iterations=self.iterations,
                total_time_ms=total_ms,
                min_us=min_val,
                max_us=max_val,
                mean_us=mean_val,
                median_us=median_val,
                p90_us=p90_val,
                p95_us=p95_val,
                p99_us=p99_val,
                stdev_us=stdev_val,
                ops_per_second=ops_sec,
            )

            item_results.append(
                BenchmarkItemResult(
                    input_text=text,
                    matched=matched,
                    match_count=match_count,
                    stats=stats,
                )
            )

        # Optional length scaling benchmark
        scaling_curve: List[ScalingStepResult] = []
        if run_scaling and test_strings:
            base_template = test_strings[0] if test_strings else "abc123XYZ "
            multipliers = [1, 5, 20, 100, 500]
            for mult in multipliers:
                scaled_text = base_template * mult
                length = len(scaled_text)

                # Calibrate iterations for long strings
                iters = max(50, min(self.iterations // 2, 500))
                for _ in range(10):
                    func(scaled_text)

                t0 = time.perf_counter()
                for _ in range(iters):
                    func(scaled_text)
                duration_total = time.perf_counter() - t0

                mean_us = (duration_total / iters) * 1_000_000.0
                ops_sec = iters / duration_total if duration_total > 0 else 0.0

                scaling_curve.append(
                    ScalingStepResult(
                        length=length,
                        mean_us=mean_us,
                        ops_per_second=ops_sec,
                    )
                )

        return BenchmarkResult(
            pattern=pattern,
            flags=flags,
            method=self.method,
            items=item_results,
            scaling_curve=scaling_curve,
        )


def benchmark_regex(
    pattern: str,
    test_strings: List[str],
    iterations: int = 1000,
    warmup: int = 50,
    method: str = "search",
    flags: int = 0,
    run_scaling: bool = False,
) -> BenchmarkResult:
    """Helper function to run microbenchmarking on a regular expression."""
    bench = RegexBenchmark(iterations=iterations, warmup=warmup, method=method)
    return bench.run(pattern, test_strings, flags=flags, run_scaling=run_scaling)
