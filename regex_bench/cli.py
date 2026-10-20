"""Command-line interface for regex-bench-cli."""

import argparse
import json
import re
import sys
from typing import List, Optional

# Attempt UTF-8 reconfiguration for Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from regex_bench import __version__
from regex_bench.analyzer import ReDoSAnalyzer, ReDoSRiskLevel
from regex_bench.benchmark import RegexBenchmark
from regex_bench.formatter import Formatter, default_formatter
from regex_bench.inspector import RegexInspector
from regex_bench.tester import TestSuiteRunner


def parse_flags(args: argparse.Namespace) -> int:
    flags = 0
    if getattr(args, "ignore_case", False):
        flags |= re.IGNORECASE
    if getattr(args, "multiline", False):
        flags |= re.MULTILINE
    if getattr(args, "dotall", False):
        flags |= re.DOTALL
    return flags


def cmd_analyze(args: argparse.Namespace, fmt: Formatter) -> int:
    analyzer = ReDoSAnalyzer(timeout_per_trial=args.timeout)
    flags = parse_flags(args)
    res = analyzer.analyze(args.pattern, flags=flags, dynamic_verify=not args.no_dynamic)

    if args.json:
        print(json.dumps(res.to_dict(), indent=2))
        return 1 if res.risk_level in (ReDoSRiskLevel.HIGH, ReDoSRiskLevel.CATASTROPHIC) and args.fail_on_risk else 0

    if args.markdown:
        lines = [
            f"# ReDoS Analysis: `{res.pattern}`",
            "",
            f"- **Risk Level:** `{res.risk_level.value}` (Score: {res.risk_score}/100)",
            f"- **Estimated Complexity:** `{res.estimated_complexity.value}`",
            f"- **Summary:** {res.summary}",
            "",
        ]
        if res.findings:
            lines.append("## Vulnerability Findings")
            lines.append("| Type | Risk | Subpattern | Recommendation |")
            lines.append("| --- | --- | --- | --- |")
            for f in res.findings:
                lines.append(f"| {f.vuln_type} | {f.risk_level.value} | `{f.subpattern}` | {f.recommendation} |")
            lines.append("")
        if res.timing_points:
            lines.append("## Dynamic Scaling Timings")
            lines.append("| Input Length | Duration (ms) | Timed Out |")
            lines.append("| --- | --- | --- |")
            for tp in res.timing_points:
                lines.append(f"| {tp.length} | {tp.duration_ms:.3f} | {tp.timed_out} |")
            lines.append("")
        if res.sample_payloads:
            lines.append("## Attack Payloads")
            for p in res.sample_payloads:
                lines.append(f"- `{p}`")
        print("\n".join(lines))
        return 1 if res.risk_level in (ReDoSRiskLevel.HIGH, ReDoSRiskLevel.CATASTROPHIC) and args.fail_on_risk else 0

    # Terminal output
    print(fmt.bold(f"\n🔍 ReDoS & Backtracking Analysis: ") + fmt.cyan(args.pattern))
    print(f"   Risk:       {fmt.badge(res.risk_level.value, res.risk_level.value)} (Score: {res.risk_score}/100)")
    print(f"   Complexity: {fmt.bold(res.estimated_complexity.value)}")
    print(f"   Summary:    {res.summary}\n")

    if res.findings:
        print(fmt.bold("  Vulnerability Findings:"))
        headers = ["Type", "Risk", "Subpattern", "Recommendation"]
        rows = [
            [f.vuln_type, fmt.badge(f.risk_level.value, f.risk_level.value), f.subpattern, f.recommendation]
            for f in res.findings
        ]
        print(fmt.table(headers, rows, max_col_width=45))
        print()

    if res.timing_points:
        print(fmt.bold("  Dynamic Stress Test Timings:"))
        headers = ["Length (N)", "Duration", "Timed Out", "Matched"]
        rows = []
        for tp in res.timing_points:
            dur_str = f"{tp.duration_ms:.3f} ms"
            to_str = fmt.red("YES (> timeout)") if tp.timed_out else fmt.green("No")
            match_str = "Yes" if tp.matched else "No"
            rows.append([str(tp.length), dur_str, to_str, match_str])
        print(fmt.table(headers, rows, alignments=["right", "right", "center", "center"]))
        print()

    if res.sample_payloads:
        print(fmt.bold("  Sample ReDoS Attack Payloads:"))
        for idx, payload in enumerate(res.sample_payloads, 1):
            disp = payload if len(payload) <= 60 else payload[:55] + "..."
            print(f"    {fmt.dim(str(idx) + '.')} {fmt.yellow(disp)} {fmt.dim(f'(len={len(payload)})')}")
        print()

    if res.risk_level in (ReDoSRiskLevel.HIGH, ReDoSRiskLevel.CATASTROPHIC) and args.fail_on_risk:
        return 1
    return 0


def cmd_bench(args: argparse.Namespace, fmt: Formatter) -> int:
    flags = parse_flags(args)
    bench = RegexBenchmark(iterations=args.iterations, warmup=args.warmup, method=args.method)
    test_strings = args.strings if args.strings else ["test", "sample string 12345", "unmatched_sample!"]

    res = bench.run(args.pattern, test_strings, flags=flags, run_scaling=args.scale)

    if args.json:
        print(json.dumps(res.to_dict(), indent=2))
        return 0

    if args.markdown:
        lines = [
            f"# Regex Benchmark: `{res.pattern}`",
            "",
            f"- **Method:** `{res.method}` | **Iterations:** {args.iterations}",
            "",
            "| Input | Matched | Mean (μs) | Median (μs) | Min (μs) | Max (μs) | P95 (μs) | Ops/sec |",
            "| --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
        for it in res.items:
            s = it.stats
            lines.append(
                f"| `{it.input_text}` | {it.matched} | {s.mean_us:.2f} | {s.median_us:.2f} | {s.min_us:.2f} | {s.max_us:.2f} | {s.p95_us:.2f} | {s.ops_per_second:,.0f} |"
            )
        print("\n".join(lines))
        return 0

    print(fmt.bold(f"\n⚡ Benchmark: ") + fmt.cyan(args.pattern))
    print(f"   Method: {args.method} | Iterations: {args.iterations:,} | Warmup: {args.warmup}\n")

    headers = ["Input", "Match", "Mean", "Median", "Min", "Max", "P95", "Throughput"]
    rows = []
    for it in res.items:
        s = it.stats
        match_str = fmt.green("YES") if it.matched else fmt.dim("no")
        rows.append([
            it.input_text,
            match_str,
            f"{s.mean_us:.2f} μs",
            f"{s.median_us:.2f} μs",
            f"{s.min_us:.2f} μs",
            f"{s.max_us:.2f} μs",
            f"{s.p95_us:.2f} μs",
            f"{s.ops_per_second:,.0f} ops/s",
        ])
    print(fmt.table(headers, rows, alignments=["left", "center", "right", "right", "right", "right", "right", "right"]))
    print()

    if res.scaling_curve:
        print(fmt.bold("  Length Scaling Throughput:"))
        sc_headers = ["Length (chars)", "Mean (μs)", "Throughput"]
        sc_rows = []
        for step in res.scaling_curve:
            sc_rows.append([
                f"{step.length:,}",
                f"{step.mean_us:.2f} μs",
                f"{step.ops_per_second:,.0f} ops/s",
            ])
        print(fmt.table(sc_headers, sc_rows, alignments=["right", "right", "right"]))
        print()

    return 0


def cmd_inspect(args: argparse.Namespace, fmt: Formatter) -> int:
    flags = parse_flags(args)
    inspector = RegexInspector(find_all=args.all)
    res = inspector.inspect(args.pattern, args.string, flags=flags)

    if args.json:
        print(json.dumps(res.to_dict(), indent=2))
        return 0

    if args.markdown:
        lines = [
            f"# Regex Match Inspection: `{res.pattern}`",
            "",
            f"- **Input:** `{res.input_text}`",
            f"- **Matched:** `{res.matched}` (Total Matches: {res.total_matches})",
            "",
        ]
        for m in res.matches:
            lines.append(f"### Match #{m.match_index + 1}: `{m.matched_text}` (span {m.span})")
            if m.groups:
                lines.append("| Group # | Name | Span | Value |")
                lines.append("| --- | --- | --- | --- |")
                for g in m.groups:
                    span_str = str(g.span) if g.span else "None"
                    lines.append(f"| {g.index} | {g.name or '-'} | {span_str} | `{g.value}` |")
            lines.append("")
        print("\n".join(lines))
        return 0

    print(fmt.bold(f"\n🔬 Match Inspector: ") + fmt.cyan(args.pattern))
    if not res.matched:
        print(f"   Result: {fmt.red('NO MATCH')} for input {res.input_text!r}\n")
        return 1

    print(f"   Result: {fmt.green('MATCH')} ({res.total_matches} match{'es' if res.total_matches > 1 else ''})\n")

    for m in res.matches:
        if res.total_matches > 1:
            print(fmt.bold(f"  --- Match #{m.match_index + 1} ---"))

        # Render visual diagram
        group_spans = [(g.name or f"Group {g.index}", g.span, g.value) for g in m.groups]
        print(fmt.render_spans(res.input_text, m.span, group_spans))
        print()

        # Group table
        if m.groups:
            headers = ["Group", "Name", "Span", "Length", "Value"]
            rows = []
            for g in m.groups:
                name_str = g.name or fmt.dim("-")
                span_str = f"{g.span[0]}..{g.span[1]}" if g.span else fmt.dim("None")
                len_str = str(g.span[1] - g.span[0]) if g.span else fmt.dim("0")
                val_str = repr(g.value) if g.value is not None else fmt.dim("None")
                rows.append([f"#{g.index}", name_str, span_str, len_str, val_str])
            print(fmt.table(headers, rows, alignments=["center", "left", "center", "right", "left"]))
            print()

    return 0


def cmd_test(args: argparse.Namespace, fmt: Formatter) -> int:
    flags = parse_flags(args)
    runner = TestSuiteRunner(default_timeout_sec=args.timeout)

    test_case = {
        "name": "CLI Single Test",
        "input": args.string,
        "should_match": not args.should_not_match,
        "max_ms": args.max_ms,
    }
    if args.groups:
        test_case["groups"] = args.groups

    suite_data = {
        "name": "Single Test Run",
        "pattern": args.pattern,
        "flags": flags,
        "tests": [test_case],
    }

    report = runner.run_suite_data(suite_data)
    res = report.results[0]

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
        return 0 if report.all_passed else 1

    badge = fmt.badge("PASSED", "PASS") if res.status == "PASSED" else fmt.badge(res.status, "FAIL")
    print(f"\n{badge} {args.pattern} against {res.input_text!r} ({res.duration_ms:.2f} ms)")

    if res.failure_reasons:
        print(fmt.bold("\n  Failures:"))
        for r in res.failure_reasons:
            print(fmt.red(f"    - {r}"))
    print()

    return 0 if report.all_passed else 1


def cmd_run(args: argparse.Namespace, fmt: Formatter) -> int:
    runner = TestSuiteRunner(default_timeout_sec=args.timeout)
    report = runner.run_suite_file(args.suite_file)

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
        return 0 if report.all_passed else 1

    if args.markdown:
        lines = [
            f"# Test Suite: {report.suite_name}",
            "",
            f"- **Pattern:** `{report.pattern}`",
            f"- **Total Tests:** {report.total_tests} | **Passed:** {report.passed_count} | **Failed:** {report.failed_count}",
            f"- **Duration:** {report.total_duration_ms:.2f} ms",
            "",
            "| Status | Test Name | Input | Duration (ms) | Notes |",
            "| --- | --- | --- | --- | --- |",
        ]
        for r in report.results:
            notes = "; ".join(r.failure_reasons) if r.failure_reasons else "-"
            lines.append(f"| {r.status} | {r.name} | `{r.input_text}` | {r.duration_ms:.2f} | {notes} |")
        print("\n".join(lines))
        return 0 if report.all_passed else 1

    print(fmt.bold(f"\n📋 Test Suite: ") + fmt.cyan(report.suite_name))
    print(f"   Pattern: {report.pattern}\n")

    headers = ["Status", "Test Name", "Input", "Duration", "Details"]
    rows = []
    for r in report.results:
        status_disp = fmt.badge(r.status, "PASS" if r.status == "PASSED" else "FAIL")
        details = ", ".join(r.failure_reasons) if r.failure_reasons else fmt.dim("ok")
        rows.append([status_disp, r.name, r.input_text, f"{r.duration_ms:.2f} ms", details])

    print(fmt.table(headers, rows, alignments=["center", "left", "left", "right", "left"], max_col_width=40))
    print()

    summary_status = fmt.green("ALL TESTS PASSED") if report.all_passed else fmt.red("TESTS FAILED")
    print(fmt.bold(f"  Summary: {summary_status}"))
    print(
        f"  Total: {report.total_tests} | "
        f"Passed: {fmt.green(str(report.passed_count))} | "
        f"Failed: {fmt.red(str(report.failed_count))} | "
        f"Timeouts: {fmt.yellow(str(report.timeout_count))} | "
        f"Duration: {report.total_duration_ms:.2f} ms\n"
    )

    return 0 if report.all_passed else 1


def build_parser() -> argparse.ArgumentParser:
    common_parser = argparse.ArgumentParser(add_help=False)
    common_parser.add_argument("--no-color", action="store_true", help="Disable ANSI color output")
    common_parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    common_parser.add_argument("--markdown", action="store_true", help="Output results in GitHub Markdown format")

    parser = argparse.ArgumentParser(
        prog="regex-bench",
        description="regex-bench-cli: Terminal CLI utility to test regular expressions, evaluate catastrophic backtracking risks, and output formatted match captures.",
        parents=[common_parser],
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Command: analyze
    p_analyze = subparsers.add_parser(
        "analyze",
        parents=[common_parser],
        help="Detect catastrophic backtracking (ReDoS) vulnerabilities",
    )
    p_analyze.add_argument("pattern", help="Regular expression pattern to analyze")
    p_analyze.add_argument("--no-dynamic", action="store_true", help="Skip dynamic stress testing")
    p_analyze.add_argument("--timeout", type=float, default=0.5, help="Timeout in seconds for dynamic tests (default: 0.5)")
    p_analyze.add_argument("--fail-on-risk", action="store_true", help="Return exit code 1 if HIGH or CATASTROPHIC risk found")
    p_analyze.add_argument("-i", "--ignore-case", action="store_true", help="Enable re.IGNORECASE")
    p_analyze.add_argument("-m", "--multiline", action="store_true", help="Enable re.MULTILINE")
    p_analyze.add_argument("-s", "--dotall", action="store_true", help="Enable re.DOTALL")

    # Command: bench
    p_bench = subparsers.add_parser(
        "bench",
        parents=[common_parser],
        help="Benchmark regex matching performance and throughput",
    )
    p_bench.add_argument("pattern", help="Regular expression pattern")
    p_bench.add_argument("strings", nargs="*", help="Sample strings to benchmark against")
    p_bench.add_argument("-n", "--iterations", type=int, default=1000, help="Number of benchmark iterations (default: 1000)")
    p_bench.add_argument("-w", "--warmup", type=int, default=50, help="Number of warmup iterations (default: 50)")
    p_bench.add_argument(
        "--method",
        choices=["search", "match", "fullmatch", "findall", "finditer"],
        default="search",
        help="Matching method to invoke (default: search)",
    )
    p_bench.add_argument("--scale", action="store_true", help="Run length scaling throughput test")
    p_bench.add_argument("-i", "--ignore-case", action="store_true", help="Enable re.IGNORECASE")
    p_bench.add_argument("-m", "--multiline", action="store_true", help="Enable re.MULTILINE")
    p_bench.add_argument("-s", "--dotall", action="store_true", help="Enable re.DOTALL")

    # Command: inspect
    p_inspect = subparsers.add_parser(
        "inspect",
        parents=[common_parser],
        help="Inspect match spans, numbered groups, and named captures",
    )
    p_inspect.add_argument("pattern", help="Regular expression pattern")
    p_inspect.add_argument("string", help="String to match against")
    p_inspect.add_argument("-a", "--all", action="store_true", help="Find and inspect all matches in string")
    p_inspect.add_argument("-i", "--ignore-case", action="store_true", help="Enable re.IGNORECASE")
    p_inspect.add_argument("-m", "--multiline", action="store_true", help="Enable re.MULTILINE")
    p_inspect.add_argument("-s", "--dotall", action="store_true", help="Enable re.DOTALL")

    # Command: test
    p_test = subparsers.add_parser(
        "test",
        parents=[common_parser],
        help="Test a pattern against a string with assertions",
    )
    p_test.add_argument("pattern", help="Regular expression pattern")
    p_test.add_argument("string", help="Input string to test")
    p_test.add_argument("--should-not-match", action="store_true", help="Assert that the pattern should NOT match")
    p_test.add_argument("-g", "--groups", nargs="*", help="Expected captured group values")
    p_test.add_argument("--max-ms", type=float, help="Max execution time limit in milliseconds")
    p_test.add_argument("--timeout", type=float, default=2.0, help="Per-test timeout in seconds (default: 2.0)")
    p_test.add_argument("-i", "--ignore-case", action="store_true", help="Enable re.IGNORECASE")
    p_test.add_argument("-m", "--multiline", action="store_true", help="Enable re.MULTILINE")
    p_test.add_argument("-s", "--dotall", action="store_true", help="Enable re.DOTALL")

    # Command: run
    p_run = subparsers.add_parser(
        "run",
        parents=[common_parser],
        help="Run a test suite from a JSON or YAML file",
    )
    p_run.add_argument("suite_file", help="Path to test suite JSON or YAML file")
    p_run.add_argument("--timeout", type=float, default=2.0, help="Per-test timeout in seconds (default: 2.0)")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    fmt = Formatter(color_enabled=False if args.no_color else None)

    try:
        if args.command == "analyze":
            return cmd_analyze(args, fmt)
        elif args.command == "bench":
            return cmd_bench(args, fmt)
        elif args.command == "inspect":
            return cmd_inspect(args, fmt)
        elif args.command == "test":
            return cmd_test(args, fmt)
        elif args.command == "run":
            return cmd_run(args, fmt)
        else:
            parser.print_help()
            return 1
    except KeyboardInterrupt:
        print("\nAborted.", file=sys.stderr)
        return 130
    except Exception as e:
        print(fmt.red(f"\nError: {e}"), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
