# regex-bench-cli ⚡

[![CI](https://github.com/slopggobblercobbler81/regex-bench-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/slopggobblercobbler81/regex-bench-cli/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-brightgreen.svg)](https://www.python.org/downloads/)

> A modern terminal utility to test regular expressions against test cases, evaluate catastrophic backtracking (ReDoS) risks, benchmark match throughput, and inspect group captures.

---

## ✨ Features

- 🛡️ **Catastrophic Backtracking (ReDoS) Analyzer**:
  - Static AST inspection of nested quantifiers (e.g. `(a+)+`), overlapping alternations (e.g. `(a|ab)+`), and adjacent unbounded repetitions.
  - Dynamic stress-testing with safe timeout bounds to empirically verify exponential ($O(2^N)$) or polynomial ($O(N^k)$) execution stall.
  - Automatic synthesis of worst-case attack payloads.
- ⚡ **High-Precision Microbenchmarking**:
  - Detailed timing metrics: Min, Mean, Median, Max, P90, P95, P99, Standard Deviation, and Throughput (ops/sec).
  - Length-scaling curve profiler (`--scale`) to measure execution performance as input size grows.
- 🔬 **Visual Match & Capture Inspector**:
  - Text span visualization with index ruler and colored group boundaries.
  - Formatted breakdown of numbered and named (`(?P<name>...)`) groups.
- 📋 **Automated Test Suite Runner**:
  - Run regression test suites from structured JSON/YAML files.
  - Assert match status, group captures, and execution time limits (`max_ms`).
- 🤖 **Developer & CI Friendly**:
  - Export machine-readable outputs with `--json` or GitHub-ready summaries with `--markdown`.
  - Zero required external dependencies — runs directly on Python 3.8+.

---

## 🚀 Installation

```bash
git clone https://github.com/slopggobblercobbler81/regex-bench-cli.git
cd regex-bench-cli
pip install .
```

Or run directly without installation:

```bash
python -m regex_bench --help
```

---

## 📖 CLI Usage

### 1. Analyze Catastrophic Backtracking (ReDoS)

Evaluate if a regular expression is susceptible to exponential or polynomial catastrophic backtracking:

```bash
regex-bench analyze "(a+)+$"
```

**Output Example:**
```text
🔍 ReDoS & Backtracking Analysis: (a+)+$
   Risk:        CATASTROPHIC  (Score: 100/100)
   Complexity: O(2^N)
   Summary:    CATASTROPHIC: Vulnerable to exponential backtracking O(2^N). Dynamic stress test confirmed severe execution stall/timeout!

  Vulnerability Findings:
┌────────────────────┬────────────────┬────────────┬───────────────────────────────────────────────┐
│ Type               │ Risk           │ Subpattern │ Recommendation                                │
├────────────────────┼────────────────┼────────────┼───────────────────────────────────────────────┤
│ nested_quantifiers │  CATASTROPHIC  │ (...a+)+   │ Eliminate nested quantifiers. Flatten the ... │
└────────────────────┴────────────────┴────────────┴───────────────────────────────────────────────┘

  Dynamic Stress Test Timings:
┌────────────┬────────────┬─────────────────┬─────────┐
│ Length (N) │ Duration   │ Timed Out       │ Matched │
├────────────┼────────────┼─────────────────┼─────────┤
│         10 │   0.718 ms │       No        │   No    │
│         15 │   2.885 ms │       No        │   No    │
│         20 │  75.459 ms │       No        │   No    │
│         24 │ 500.000 ms │ YES (> timeout) │   No    │
└────────────┴────────────┴─────────────────┴─────────┘

  Sample ReDoS Attack Payloads:
    1. aaaaaaaaaaaaaaa! (len=16)
    2. aaaaaaaaaaaaaaaaaaaaaaaaa! (len=26)
    3. aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa! (len=36)
```

Use `--fail-on-risk` in CI pipelines to return a non-zero exit code if high or catastrophic risks are discovered.

---

### 2. Inspect Match Spans and Groups

Visualize match positions, character spans, and group captures:

```bash
regex-bench inspect "^(?P<user>[a-zA-Z0-9_.+-]+)@(?P<domain>[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+)$" "alice.dev@company-corp.org"
```

**Output Example:**
```text
🔬 Match Inspector: ^(?P<user>[a-zA-Z0-9_.+-]+)@(?P<domain>[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+)$
   Result: MATCH (1 match)

  Input:  alice.dev@company-corp.org
  Ruler:  01234567890123456789012345
  Match:  [========================] (0..26)
    user:  [-------]                  (0..9) 'alice.dev'
  domain:            [--------------] (10..26) 'company-corp.org'

┌───────┬────────┬────────┬────────┬────────────────────┐
│ Group │ Name   │ Span   │ Length │ Value              │
├───────┼────────┼────────┼────────┼────────────────────┤
│  #1   │ user   │  0..9  │      9 │ 'alice.dev'        │
│  #2   │ domain │ 10..26 │     16 │ 'company-corp.org' │
└───────┴────────┴────────┴────────┴────────────────────┘
```

---

### 3. Benchmark Match Speed & Throughput

Profile execution speed across sample inputs:

```bash
regex-bench bench "[a-z0-9]+" "test12345sample" "short" --scale
```

**Output Example:**
```text
⚡ Benchmark: [a-z0-9]+
   Method: search | Iterations: 1,000 | Warmup: 50

┌─────────────────┬───────┬─────────┬─────────┬─────────┬──────────┬─────────┬─────────────────┐
│ Input           │ Match │ Mean    │ Median  │ Min     │ Max      │ P95     │ Throughput      │
├─────────────────┼───────┼─────────┼─────────┼─────────┼──────────┼─────────┼─────────────────┤
│ test12345sample │  YES  │ 0.48 μs │ 0.50 μs │ 0.30 μs │  0.90 μs │ 0.60 μs │ 1,472,537 ops/s │
│ short           │  YES  │ 0.43 μs │ 0.40 μs │ 0.20 μs │ 11.60 μs │ 0.50 μs │ 1,660,854 ops/s │
└─────────────────┴───────┴─────────┴─────────┴─────────┴──────────┴─────────┴─────────────────┘

  Length Scaling Throughput:
┌────────────────┬───────────┬─────────────────┐
│ Length (chars) │ Mean (μs) │ Throughput      │
├────────────────┼───────────┼─────────────────┤
│             15 │   0.13 μs │ 7,598,784 ops/s │
│             75 │   0.26 μs │ 3,881,988 ops/s │
│            300 │   0.72 μs │ 1,393,922 ops/s │
│          1,500 │   3.61 μs │   277,146 ops/s │
│          7,500 │  16.93 μs │    59,070 ops/s │
└────────────────┴───────────┴─────────────────┘
```

---

### 4. Run Test Suites

Run structured regression suites from JSON files:

```bash
regex-bench run examples/email_suite.json
```

**Test Suite File Format (`suite.json`):**
```json
{
  "name": "Email Validation Test Suite",
  "pattern": "^(?P<user>[a-zA-Z0-9_.+-]+)@(?P<domain>[a-zA-Z0-9-]+(?:\\.[a-zA-Z0-9-]+)+)$",
  "flags": ["IGNORECASE"],
  "tests": [
    {
      "name": "standard email",
      "input": "developer@example.com",
      "should_match": true,
      "groups": ["developer", "example.com"],
      "max_ms": 5.0
    },
    {
      "name": "missing at sign",
      "input": "invalidemail.org",
      "should_match": false
    }
  ]
}
```

---

### 5. Quick One-Off Assertion Testing

```bash
# Assert match with expected group captures
regex-bench test "^(\d{3})-(\d{4})$" "123-4567" -g 123 4567

# Assert negative match
regex-bench test "^(\d{3})-(\d{4})$" "123-abc" --should-not-match
```

---

## 🐍 Python API

You can also import and use `regex_bench` in Python code:

```python
from regex_bench import analyze_redos, inspect_match, benchmark_regex

# ReDoS analysis
analysis = analyze_redos(r"(a+)+$")
print(f"Risk: {analysis.risk_level.value}, Complexity: {analysis.estimated_complexity.value}")

# Inspect match
inspection = inspect_match(r"(?P<user>\w+)@(?P<domain>\w+\.\w+)", "alice@example.com")
for group in inspection.matches[0].groups:
    print(f"Group #{group.index} ({group.name}): {group.value}")

# Benchmark
bench = benchmark_regex(r"\d+", ["123", "456", "789"], iterations=1000)
print(f"Average time: {bench.items[0].stats.mean_us:.2f} μs")
```

---

## 🧪 Testing

Run automated tests with Python's standard `unittest`:

```bash
python -m unittest discover -s tests -v
```

---

## 📄 License

MIT License. See [LICENSE](LICENSE) for details.
