# Changelog

All notable changes to `regex-bench-cli` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-20

### Added
- Static catastrophic backtracking (ReDoS) analyzer detecting nested quantifiers, overlapping alternations, and adjacent repetitions.
- Dynamic stress-testing engine with safe timeout protections to empirically prove exponential ($O(2^N)$) or polynomial ($O(N^k)$) slowdowns.
- Tailored attack payload generator synthesizing prefix, pump, and poison suffix combinations.
- High-precision microbenchmarking command (`bench`) with statistical percentiles (min, mean, median, p90, p95, p99, stddev) and throughput (ops/sec).
- Length scaling throughput profiler (`--scale`) to measure execution time against growing input sizes.
- Visual match inspector (`inspect`) displaying index rulers, bracket spans, numbered groups, and named group captures.
- Automated test suite executor (`test` and `run`) supporting JSON test definitions with group matching and execution time thresholds.
- Cross-platform terminal formatter supporting ANSI colors, Unicode/ASCII tables, JSON output (`--json`), and GitHub Markdown (`--markdown`).
