# Contributing to regex-bench-cli

Thank you for your interest in contributing to `regex-bench-cli`!

## Development Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/slopggobblercobbler81/regex-bench-cli.git
   cd regex-bench-cli
   ```

2. Install in editable mode:
   ```bash
   pip install -e .
   ```

3. Run the test suite:
   ```bash
   python -m unittest discover -s tests -v
   ```

## Adding Features

- New ReDoS detection heuristics should be added to `regex_bench/analyzer.py` with accompanying unit tests in `tests/test_analyzer.py`.
- Benchmark enhancements belong in `regex_bench/benchmark.py`.
- Formatter updates should ensure cross-platform compatibility across Windows, Linux, and macOS terminals.

## Pull Requests

1. Fork the repo and create your feature branch: `git checkout -b feature/my-enhancement`.
2. Commit your changes: `git commit -am 'Add new heuristic'`.
3. Push to the branch: `git push origin feature/my-enhancement`.
4. Submit a pull request.
