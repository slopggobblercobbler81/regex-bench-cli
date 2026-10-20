"""Match inspection and capture group extraction engine."""

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class GroupCapture:
    index: int
    name: Optional[str]
    span: Optional[Tuple[int, int]]
    value: Optional[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "name": self.name,
            "span": list(self.span) if self.span else None,
            "value": self.value,
        }


@dataclass
class MatchInspection:
    match_index: int
    span: Tuple[int, int]
    matched_text: str
    groups: List[GroupCapture] = field(default_factory=list)
    named_groups: Dict[str, Optional[str]] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "match_index": self.match_index,
            "span": list(self.span),
            "matched_text": self.matched_text,
            "groups": [g.to_dict() for g in self.groups],
            "named_groups": self.named_groups,
        }


@dataclass
class InspectionResult:
    pattern: str
    flags: int
    input_text: str
    matched: bool
    total_matches: int
    matches: List[MatchInspection] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pattern": self.pattern,
            "flags": self.flags,
            "input_text": self.input_text,
            "matched": self.matched,
            "total_matches": self.total_matches,
            "matches": [m.to_dict() for m in self.matches],
        }


class RegexInspector:
    """Inspects matches, group captures, spans, and named subgroups."""

    def __init__(self, find_all: bool = False):
        self.find_all = find_all

    def inspect(self, pattern: str, input_text: str, flags: int = 0) -> InspectionResult:
        compiled = re.compile(pattern, flags)
        groupindex = compiled.groupindex  # name -> index

        # Invert groupindex to get index -> name
        index_to_name: Dict[int, str] = {idx: name for name, idx in groupindex.items()}

        raw_matches = list(compiled.finditer(input_text)) if self.find_all else []
        if not self.find_all:
            first_m = compiled.search(input_text)
            if first_m:
                raw_matches = [first_m]

        if not raw_matches:
            return InspectionResult(
                pattern=pattern,
                flags=flags,
                input_text=input_text,
                matched=False,
                total_matches=0,
                matches=[],
            )

        match_inspections: List[MatchInspection] = []

        for m_idx, m in enumerate(raw_matches):
            group_captures: List[GroupCapture] = []
            named_dict: Dict[str, Optional[str]] = {}

            # Total groups in pattern
            total_groups = compiled.groups
            for g_num in range(1, total_groups + 1):
                g_span = m.span(g_num)
                # If group didn't match, span is (-1, -1)
                valid_span = g_span if g_span != (-1, -1) else None
                g_val = m.group(g_num)
                g_name = index_to_name.get(g_num)

                group_captures.append(
                    GroupCapture(
                        index=g_num,
                        name=g_name,
                        span=valid_span,
                        value=g_val,
                    )
                )

            # Named groups
            for name, idx in groupindex.items():
                named_dict[name] = m.group(name)

            match_inspections.append(
                MatchInspection(
                    match_index=m_idx,
                    span=m.span(),
                    matched_text=m.group(0),
                    groups=group_captures,
                    named_groups=named_dict,
                )
            )

        return InspectionResult(
            pattern=pattern,
            flags=flags,
            input_text=input_text,
            matched=True,
            total_matches=len(match_inspections),
            matches=match_inspections,
        )


def inspect_match(
    pattern: str, input_text: str, flags: int = 0, find_all: bool = False
) -> InspectionResult:
    """Helper function to inspect regular expression match and capture groups."""
    inspector = RegexInspector(find_all=find_all)
    return inspector.inspect(pattern, input_text, flags=flags)
