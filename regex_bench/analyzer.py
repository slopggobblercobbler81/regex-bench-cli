"""Catastrophic backtracking (ReDoS) static analysis and dynamic verification engine."""

import concurrent.futures
import enum
import math
import re
import sre_constants
import sre_parse
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


class ReDoSRiskLevel(str, enum.Enum):
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CATASTROPHIC = "CATASTROPHIC"

    @property
    def score(self) -> int:
        mapping = {
            ReDoSRiskLevel.SAFE: 0,
            ReDoSRiskLevel.LOW: 25,
            ReDoSRiskLevel.MEDIUM: 50,
            ReDoSRiskLevel.HIGH: 75,
            ReDoSRiskLevel.CATASTROPHIC: 100,
        }
        return mapping[self]


class ComplexityType(str, enum.Enum):
    CONSTANT = "O(1)"
    LINEAR = "O(N)"
    POLYNOMIAL = "O(N^k)"
    EXPONENTIAL = "O(2^N)"
    UNKNOWN = "Unknown"


@dataclass
class VulnerabilityFinding:
    vuln_type: str
    risk_level: ReDoSRiskLevel
    description: str
    subpattern: str
    recommendation: str
    suggested_pump: str = "a"
    prefix: str = ""
    poison_suffix: str = "!"


@dataclass
class DynamicTimingPoint:
    length: int
    duration_ms: float
    timed_out: bool = False
    matched: bool = False


@dataclass
class ReDoSAnalysisResult:
    pattern: str
    flags: int
    risk_level: ReDoSRiskLevel
    risk_score: int
    estimated_complexity: ComplexityType
    findings: List[VulnerabilityFinding] = field(default_factory=list)
    dynamic_verified: bool = False
    dynamic_growth: ComplexityType = ComplexityType.UNKNOWN
    timing_points: List[DynamicTimingPoint] = field(default_factory=list)
    sample_payloads: List[str] = field(default_factory=list)
    ast_summary: Dict[str, Any] = field(default_factory=dict)
    summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pattern": self.pattern,
            "risk_level": self.risk_level.value,
            "risk_score": self.risk_score,
            "estimated_complexity": self.estimated_complexity.value,
            "dynamic_verified": self.dynamic_verified,
            "dynamic_growth": self.dynamic_growth.value,
            "findings": [
                {
                    "type": f.vuln_type,
                    "risk_level": f.risk_level.value,
                    "description": f.description,
                    "subpattern": f.subpattern,
                    "recommendation": f.recommendation,
                }
                for f in self.findings
            ],
            "sample_payloads": self.sample_payloads,
            "timing_points": [
                {
                    "length": p.length,
                    "duration_ms": round(p.duration_ms, 4),
                    "timed_out": p.timed_out,
                    "matched": p.matched,
                }
                for p in self.timing_points
            ],
            "summary": self.summary,
        }


def _is_unbounded_repeat(min_count: int, max_count: int) -> bool:
    """Check if repeat count allows high/unbounded iterations."""
    return max_count == sre_constants.MAXREPEAT or max_count >= 50


def _extract_sample_char_from_node(node: Tuple[Any, Any]) -> str:
    """Extract a representative character matching the node."""
    op, val = node
    if op == sre_constants.LITERAL:
        return chr(val)
    elif op == sre_constants.NOT_LITERAL:
        forbidden = chr(val)
        return "b" if forbidden == "a" else "a"
    elif op == sre_constants.IN:
        # val is list of (OP, item)
        for item in val:
            subop, subval = item
            if subop == sre_constants.LITERAL:
                return chr(subval)
            elif subop == sre_constants.RANGE:
                return chr(subval[0])
            elif subop == sre_constants.CATEGORY:
                if subval in (sre_constants.CATEGORY_DIGIT, sre_constants.CATEGORY_UNI_DIGIT):
                    return "1"
                elif subval in (sre_constants.CATEGORY_WORD, sre_constants.CATEGORY_UNI_WORD):
                    return "a"
                elif subval in (sre_constants.CATEGORY_SPACE, sre_constants.CATEGORY_UNI_SPACE):
                    return " "
        return "a"
    elif op == sre_constants.CATEGORY:
        if val in (sre_constants.CATEGORY_DIGIT, sre_constants.CATEGORY_UNI_DIGIT):
            return "1"
        elif val in (sre_constants.CATEGORY_SPACE, sre_constants.CATEGORY_UNI_SPACE):
            return " "
        return "a"
    elif op == sre_constants.ANY:
        return "a"
    elif op == sre_constants.SUBPATTERN:
        # (group_idx, add_flags, del_flags, subpattern)
        sub = val[3]
        for sub_node in sub:
            c = _extract_sample_char_from_node(sub_node)
            if c:
                return c
        return "a"
    elif op in (sre_constants.MAX_REPEAT, sre_constants.MIN_REPEAT):
        sub = val[2]
        for sub_node in sub:
            c = _extract_sample_char_from_node(sub_node)
            if c:
                return c
        return "a"
    elif op == sre_constants.BRANCH:
        branches = val[1]
        for b in branches:
            for sub_node in b:
                c = _extract_sample_char_from_node(sub_node)
                if c:
                    return c
        return "a"
    return "a"


def _get_chars_set_from_node(node: Tuple[Any, Any]) -> Set[int]:
    """Return a small set of representative ordinals matched by this node."""
    op, val = node
    chars: Set[int] = set()
    if op == sre_constants.LITERAL:
        chars.add(val)
    elif op == sre_constants.IN:
        for item in val:
            subop, subval = item
            if subop == sre_constants.LITERAL:
                chars.add(subval)
            elif subop == sre_constants.RANGE:
                # Add sample ordinals in range
                chars.add(subval[0])
                chars.add(subval[1])
                chars.add((subval[0] + subval[1]) // 2)
            elif subop == sre_constants.CATEGORY:
                if subval in (sre_constants.CATEGORY_DIGIT, sre_constants.CATEGORY_UNI_DIGIT):
                    chars.update(ord(c) for c in "012")
                elif subval in (sre_constants.CATEGORY_WORD, sre_constants.CATEGORY_UNI_WORD):
                    chars.update(ord(c) for c in "ab1_")
    elif op == sre_constants.CATEGORY:
        if val in (sre_constants.CATEGORY_DIGIT, sre_constants.CATEGORY_UNI_DIGIT):
            chars.update(ord(c) for c in "012")
        elif val in (sre_constants.CATEGORY_WORD, sre_constants.CATEGORY_UNI_WORD):
            chars.update(ord(c) for c in "ab1_")
    elif op == sre_constants.ANY:
        chars.update(ord(c) for c in "abc123")
    elif op == sre_constants.SUBPATTERN:
        sub = val[3]
        for sub_node in sub:
            chars.update(_get_chars_set_from_node(sub_node))
    elif op in (sre_constants.MAX_REPEAT, sre_constants.MIN_REPEAT):
        sub = val[2]
        for sub_node in sub:
            chars.update(_get_chars_set_from_node(sub_node))
    return chars


class ReDoSAnalyzer:
    """Static and dynamic ReDoS vulnerability detector for regular expressions."""

    def __init__(self, timeout_per_trial: float = 0.5):
        self.timeout_per_trial = timeout_per_trial

    def analyze(self, pattern: str, flags: int = 0, dynamic_verify: bool = True) -> ReDoSAnalysisResult:
        """Perform static ReDoS vulnerability checks and optional dynamic stress test."""
        findings: List[VulnerabilityFinding] = []
        ast_summary: Dict[str, Any] = {"parsed": False, "node_count": 0}

        try:
            parsed = sre_parse.parse(pattern, flags)
            ast_summary["parsed"] = True
            ast_summary["node_count"] = len(parsed)
        except Exception as e:
            return ReDoSAnalysisResult(
                pattern=pattern,
                flags=flags,
                risk_level=ReDoSRiskLevel.SAFE,
                risk_score=0,
                estimated_complexity=ComplexityType.UNKNOWN,
                findings=[
                    VulnerabilityFinding(
                        vuln_type="syntax_error",
                        risk_level=ReDoSRiskLevel.SAFE,
                        description=f"Invalid regex syntax: {e}",
                        subpattern=pattern,
                        recommendation="Fix regex syntax error.",
                    )
                ],
                summary=f"Syntax error: {e}",
            )

        # 1. Static heuristic analysis
        self._check_nested_quantifiers(parsed, findings)
        self._check_overlapping_alternation_in_repeat(parsed, findings)
        self._check_adjacent_overlapping_quantifiers(parsed, findings)

        # Determine overall risk level
        max_score = 0
        risk_level = ReDoSRiskLevel.SAFE
        complexity = ComplexityType.LINEAR

        for f in findings:
            if f.risk_level.score > max_score:
                max_score = f.risk_level.score
                risk_level = f.risk_level

        if risk_level == ReDoSRiskLevel.CATASTROPHIC:
            complexity = ComplexityType.EXPONENTIAL
        elif risk_level == ReDoSRiskLevel.HIGH:
            complexity = ComplexityType.EXPONENTIAL
        elif risk_level == ReDoSRiskLevel.MEDIUM:
            complexity = ComplexityType.POLYNOMIAL
        elif risk_level == ReDoSRiskLevel.LOW:
            complexity = ComplexityType.LINEAR
        else:
            complexity = ComplexityType.LINEAR

        # Build attack payloads
        sample_payloads = self._generate_payloads(pattern, findings)

        # Dynamic verification if requested and findings exist or pattern has quantifiers
        dynamic_verified = False
        dynamic_growth = ComplexityType.UNKNOWN
        timing_points: List[DynamicTimingPoint] = []

        if dynamic_verify and (findings or any(op in (sre_constants.MAX_REPEAT, sre_constants.MIN_REPEAT) for op, _ in parsed)):
            dynamic_verified, dynamic_growth, timing_points = self._dynamic_stress_test(
                pattern, flags, findings, sample_payloads
            )
            # Upgrade risk if dynamic test proved exponential or timed out
            if dynamic_growth == ComplexityType.EXPONENTIAL or any(tp.timed_out for tp in timing_points):
                risk_level = ReDoSRiskLevel.CATASTROPHIC
                max_score = 100
                complexity = ComplexityType.EXPONENTIAL
            elif dynamic_growth == ComplexityType.POLYNOMIAL and risk_level.score < ReDoSRiskLevel.HIGH.score:
                risk_level = ReDoSRiskLevel.HIGH
                max_score = 75
                complexity = ComplexityType.POLYNOMIAL

        summary = self._build_summary(risk_level, complexity, findings, dynamic_verified, dynamic_growth, timing_points)

        return ReDoSAnalysisResult(
            pattern=pattern,
            flags=flags,
            risk_level=risk_level,
            risk_score=max_score,
            estimated_complexity=complexity,
            findings=findings,
            dynamic_verified=dynamic_verified,
            dynamic_growth=dynamic_growth,
            timing_points=timing_points,
            sample_payloads=sample_payloads,
            ast_summary=ast_summary,
            summary=summary,
        )

    def _check_nested_quantifiers(
        self, subpattern: Any, findings: List[VulnerabilityFinding], depth: int = 0
    ) -> None:
        """Detect nested quantifiers e.g. (a+)+ or ([0-9]+)* or (.*)*."""
        for item in subpattern:
            op, val = item
            if op in (sre_constants.MAX_REPEAT, sre_constants.MIN_REPEAT):
                min_outer, max_outer, inner_nodes = val
                if _is_unbounded_repeat(min_outer, max_outer):
                    # Check for repeat inside inner_nodes
                    self._find_inner_repeats(inner_nodes, findings, outer_node=item)
            elif op == sre_constants.SUBPATTERN:
                # val: (group, add_flags, del_flags, sub)
                self._check_nested_quantifiers(val[3], findings, depth + 1)
            elif op == sre_constants.BRANCH:
                # val: (None, [branch1, branch2, ...])
                for b in val[1]:
                    self._check_nested_quantifiers(b, findings, depth + 1)

    def _find_inner_repeats(
        self, nodes: List[Tuple[Any, Any]], findings: List[VulnerabilityFinding], outer_node: Tuple[Any, Any]
    ) -> None:
        """Find repeat nodes inside a repetition subpattern."""
        for node in nodes:
            op, val = node
            if op in (sre_constants.MAX_REPEAT, sre_constants.MIN_REPEAT):
                min_inner, max_inner, sub = val
                if _is_unbounded_repeat(min_inner, max_inner):
                    pump = _extract_sample_char_from_node(node)
                    findings.append(
                        VulnerabilityFinding(
                            vuln_type="nested_quantifiers",
                            risk_level=ReDoSRiskLevel.CATASTROPHIC,
                            description=(
                                f"Nested unbounded repetition detected (inner repeat within outer repeat). "
                                f"Causes exponential O(2^N) backtracking when matching a non-matching suffix."
                            ),
                            subpattern=f"(...{pump}+)+",
                            recommendation=(
                                "Eliminate nested quantifiers. Flatten the repetition, use atomic grouping, "
                                "or ensure the inner and outer tokens are mutually exclusive."
                            ),
                            suggested_pump=pump,
                            poison_suffix="!",
                        )
                    )
            elif op == sre_constants.SUBPATTERN:
                self._find_inner_repeats(val[3], findings, outer_node)
            elif op == sre_constants.BRANCH:
                for b in val[1]:
                    self._find_inner_repeats(b, findings, outer_node)

    def _check_overlapping_alternation_in_repeat(
        self, subpattern: Any, findings: List[VulnerabilityFinding]
    ) -> None:
        """Detect overlapping alternation branches inside a repetition e.g. (a|ab)+ or (a|a)+."""
        for item in subpattern:
            op, val = item
            if op in (sre_constants.MAX_REPEAT, sre_constants.MIN_REPEAT):
                min_count, max_count, inner_nodes = val
                if _is_unbounded_repeat(min_count, max_count):
                    # Check if inner_nodes contains a BRANCH or SUBPATTERN containing a BRANCH
                    self._inspect_branches_in_repeat(inner_nodes, findings)
            elif op == sre_constants.SUBPATTERN:
                self._check_overlapping_alternation_in_repeat(val[3], findings)
            elif op == sre_constants.BRANCH:
                for b in val[1]:
                    self._check_overlapping_alternation_in_repeat(b, findings)

    def _inspect_branches_in_repeat(
        self, nodes: List[Tuple[Any, Any]], findings: List[VulnerabilityFinding]
    ) -> None:
        """Inspect nodes inside a repeat for ambiguous/overlapping branches."""
        has_prefix = False
        prefix_char = "a"

        for idx, node in enumerate(nodes):
            nop, nval = node
            if nop == sre_constants.LITERAL:
                has_prefix = True
                prefix_char = chr(nval)
            elif nop == sre_constants.BRANCH:
                branches = nval[1]
                if len(branches) >= 2:
                    has_empty_branch = any(len(b) == 0 for b in branches)
                    # If sre_parse factored out a common prefix and left empty branches
                    # or an empty branch allows ambiguous iteration inside the repeat
                    if has_empty_branch:
                        findings.append(
                            VulnerabilityFinding(
                                vuln_type="overlapping_alternation_in_repeat",
                                risk_level=ReDoSRiskLevel.CATASTROPHIC,
                                description=(
                                    "Overlapping alternation branches inside a repetition. Multiple "
                                    "branches can match identical character sequences, leading to exponential search paths."
                                ),
                                subpattern=f"({prefix_char}...)+",
                                recommendation="Make alternation branches mutually exclusive or eliminate redundant branches.",
                                suggested_pump=prefix_char,
                                poison_suffix="!",
                            )
                        )
                        return

                    # Compare non-empty branches for overlapping characters
                    branch_sets = [
                        _get_chars_set_from_node(b[0]) if b else set()
                        for b in branches
                    ]
                    for i in range(len(branch_sets)):
                        for j in range(i + 1, len(branch_sets)):
                            if branch_sets[i] and branch_sets[j] and (branch_sets[i] & branch_sets[j]):
                                sample_c = chr(next(iter(branch_sets[i] & branch_sets[j])))
                                findings.append(
                                    VulnerabilityFinding(
                                        vuln_type="overlapping_alternation_in_repeat",
                                        risk_level=ReDoSRiskLevel.CATASTROPHIC,
                                        description=(
                                            "Overlapping alternation branches inside a repetition. Multiple "
                                            "branches can match identical character sequences, leading to exponential search paths."
                                        ),
                                        subpattern="(branchA|branchB)+",
                                        recommendation="Make alternation branches mutually exclusive or extract common prefixes.",
                                        suggested_pump=sample_c,
                                        poison_suffix="!",
                                    )
                                )
                                return
            elif nop == sre_constants.SUBPATTERN:
                self._inspect_branches_in_repeat(nval[3], findings)

    def _check_adjacent_overlapping_quantifiers(
        self, subpattern: Any, findings: List[VulnerabilityFinding]
    ) -> None:
        """Detect adjacent unbounded quantifiers matching overlapping characters e.g. .*.* or \\w+\\d+."""
        nodes = list(subpattern)
        for i in range(len(nodes) - 1):
            n1 = nodes[i]
            n2 = nodes[i + 1]

            op1, val1 = n1
            op2, val2 = n2

            if op1 in (sre_constants.MAX_REPEAT, sre_constants.MIN_REPEAT) and op2 in (
                sre_constants.MAX_REPEAT,
                sre_constants.MIN_REPEAT,
            ):
                min1, max1, sub1 = val1
                min2, max2, sub2 = val2
                if _is_unbounded_repeat(min1, max1) and _is_unbounded_repeat(min2, max2):
                    chars1 = _get_chars_set_from_node(sub1[0]) if sub1 else set()
                    chars2 = _get_chars_set_from_node(sub2[0]) if sub2 else set()
                    # Check wildcard ANY
                    is_wild1 = sub1 and sub1[0][0] == sre_constants.ANY
                    is_wild2 = sub2 and sub2[0][0] == sre_constants.ANY

                    if is_wild1 or is_wild2 or (chars1 and chars2 and (chars1 & chars2)):
                        sample_c = chr(next(iter(chars1))) if chars1 else "a"
                        findings.append(
                            VulnerabilityFinding(
                                vuln_type="adjacent_overlapping_quantifiers",
                                risk_level=ReDoSRiskLevel.HIGH,
                                description=(
                                    "Adjacent unbounded quantifiers with overlapping character sets. "
                                    "Ambiguous division of matches between repetitions leads to polynomial O(N^2) or O(N^3) backtracking."
                                ),
                                subpattern="rep1.*rep2",
                                recommendation="Introduce a distinct delimiter between repetitions or anchor patterns specifically.",
                                suggested_pump=sample_c,
                                poison_suffix="!",
                            )
                        )

    def _generate_payloads(
        self, pattern: str, findings: List[VulnerabilityFinding]
    ) -> List[str]:
        """Generate test attack payloads tailored to the regex."""
        payloads = []
        pump = "a"
        suffix = "!"
        prefix = ""

        if findings:
            for f in findings:
                if f.suggested_pump:
                    pump = f.suggested_pump
                    suffix = f.poison_suffix
                    prefix = f.prefix
                    break
        else:
            # Fallback heuristic: search for any literal or digit
            if "\\d" in pattern or "[0-9]" in pattern:
                pump = "1"
            elif "\\w" in pattern:
                pump = "x"

        # If pattern starts with an anchor or prefix e.g. ^name=
        m = re.match(r"^\^?([a-zA-Z0-9_\-=:]+)", pattern)
        if m and len(m.group(1)) > 1:
            prefix = m.group(1)

        for n in [15, 25, 35]:
            payloads.append(f"{prefix}{pump * n}{suffix}")

        return payloads

    def _dynamic_stress_test(
        self,
        pattern: str,
        flags: int,
        findings: List[VulnerabilityFinding],
        payloads: List[str],
    ) -> Tuple[bool, ComplexityType, List[DynamicTimingPoint]]:
        """Stress-test the regex with safe timeout bounds to measure execution scaling."""
        pump = findings[0].suggested_pump if findings else "a"
        suffix = findings[0].poison_suffix if findings else "!"
        prefix = findings[0].prefix if findings else ""

        lengths = [10, 15, 20, 24, 28, 30]
        timing_points: List[DynamicTimingPoint] = []
        compiled = None
        try:
            compiled = re.compile(pattern, flags)
        except Exception:
            return False, ComplexityType.UNKNOWN, []

        def execute_match(text: str) -> bool:
            return bool(compiled.search(text))

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            timed_out_encountered = False
            for length in lengths:
                test_str = f"{prefix}{pump * length}{suffix}"
                t0 = time.perf_counter()
                future = executor.submit(execute_match, test_str)
                timed_out = False
                matched = False
                try:
                    matched = future.result(timeout=self.timeout_per_trial)
                    duration_ms = (time.perf_counter() - t0) * 1000.0
                except concurrent.futures.TimeoutError:
                    timed_out = True
                    timed_out_encountered = True
                    duration_ms = self.timeout_per_trial * 1000.0

                timing_points.append(
                    DynamicTimingPoint(
                        length=length,
                        duration_ms=duration_ms,
                        timed_out=timed_out,
                        matched=matched,
                    )
                )

                if timed_out_encountered:
                    break

        # Analyze timing growth curve
        dynamic_growth = ComplexityType.LINEAR
        if timed_out_encountered:
            dynamic_growth = ComplexityType.EXPONENTIAL
        elif len(timing_points) >= 4:
            valid_durations = [p.duration_ms for p in timing_points if not p.timed_out]
            if len(valid_durations) >= 4 and valid_durations[-1] > 2.0:
                # Check ratio of consecutive steps
                ratios = []
                for i in range(1, len(valid_durations)):
                    prev = max(valid_durations[i - 1], 0.001)
                    curr = valid_durations[i]
                    ratios.append(curr / prev)
                avg_ratio = sum(ratios) / len(ratios)
                if avg_ratio >= 3.0:
                    dynamic_growth = ComplexityType.EXPONENTIAL
                elif avg_ratio >= 1.8:
                    dynamic_growth = ComplexityType.POLYNOMIAL

        is_verified = timed_out_encountered or dynamic_growth in (
            ComplexityType.EXPONENTIAL,
            ComplexityType.POLYNOMIAL,
        )
        return is_verified, dynamic_growth, timing_points

    def _build_summary(
        self,
        risk_level: ReDoSRiskLevel,
        complexity: ComplexityType,
        findings: List[VulnerabilityFinding],
        dynamic_verified: bool,
        dynamic_growth: ComplexityType,
        timing_points: List[DynamicTimingPoint],
    ) -> str:
        if risk_level == ReDoSRiskLevel.CATASTROPHIC:
            msg = f"CATASTROPHIC: Vulnerable to exponential backtracking {complexity.value}."
            if dynamic_verified:
                msg += " Dynamic stress test confirmed severe execution stall/timeout!"
            return msg
        elif risk_level == ReDoSRiskLevel.HIGH:
            return f"HIGH RISK: High-order backtracking detected ({complexity.value}). Attack strings cause severe slowdown."
        elif risk_level == ReDoSRiskLevel.MEDIUM:
            return f"MEDIUM RISK: Potential polynomial backtracking ({complexity.value}) detected with adjacent or loose quantifiers."
        elif risk_level == ReDoSRiskLevel.LOW:
            return "LOW RISK: Minor ambiguity detected, but catastrophic backtracking is unlikely."
        return "SAFE: No catastrophic backtracking vulnerabilities detected."


def analyze_redos(pattern: str, flags: int = 0, dynamic_verify: bool = True) -> ReDoSAnalysisResult:
    """Helper function to run ReDoS analysis on a regex pattern."""
    analyzer = ReDoSAnalyzer()
    return analyzer.analyze(pattern, flags, dynamic_verify=dynamic_verify)
