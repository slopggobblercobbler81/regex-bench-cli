"""Unit tests for regex benchmark runner and statistics."""

import unittest
from regex_bench.benchmark import RegexBenchmark, benchmark_regex


class TestRegexBenchmark(unittest.TestCase):
    def test_benchmark_simple_search(self):
        bench = RegexBenchmark(iterations=50, warmup=5, method="search")
        res = bench.run(r"\d+", ["123", "abc", "foo 999 bar"])
        self.assertEqual(res.pattern, r"\d+")
        self.assertEqual(len(res.items), 3)

        self.assertTrue(res.items[0].matched)
        self.assertFalse(res.items[1].matched)
        self.assertTrue(res.items[2].matched)

        s = res.items[0].stats
        self.assertEqual(s.iterations, 50)
        self.assertGreater(s.ops_per_second, 0)
        self.assertGreaterEqual(s.max_us, s.min_us)
        self.assertGreaterEqual(s.p95_us, s.p90_us)

    def test_benchmark_findall_method(self):
        bench = RegexBenchmark(iterations=20, warmup=2, method="findall")
        res = bench.run(r"\w+", ["apple banana orange"])
        self.assertEqual(len(res.items), 1)
        self.assertTrue(res.items[0].matched)
        self.assertEqual(res.items[0].match_count, 3)

    def test_benchmark_scaling_curve(self):
        bench = RegexBenchmark(iterations=30, warmup=2, method="search")
        res = bench.run(r"[a-z]+", ["abc"], run_scaling=True)
        self.assertTrue(len(res.scaling_curve) >= 3)
        self.assertLess(res.scaling_curve[0].length, res.scaling_curve[-1].length)

    def test_to_dict_serialization(self):
        res = benchmark_regex(r"abc", ["abc", "xyz"], iterations=10, warmup=1)
        d = res.to_dict()
        self.assertIn("pattern", d)
        self.assertIn("method", d)
        self.assertEqual(len(d["items"]), 2)
        self.assertIn("ops_per_second", d["items"][0]["stats"])


if __name__ == "__main__":
    unittest.main()
