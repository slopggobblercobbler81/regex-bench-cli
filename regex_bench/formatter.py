"""Terminal styling, table rendering, and output formatting for regex-bench-cli."""

import os
import sys
from typing import Any, Dict, List, Optional, Tuple, Union


class AnsiColor:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    ITALIC = "\033[3m"
    UNDERLINE = "\033[4m"

    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"

    BRIGHT_BLACK = "\033[90m"
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN = "\033[96m"
    BRIGHT_WHITE = "\033[97m"

    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"
    BG_MAGENTA = "\033[45m"
    BG_CYAN = "\033[46m"
    BG_DARK_GRAY = "\033[100m"


class Formatter:
    def __init__(self, color_enabled: Optional[bool] = None):
        if color_enabled is not None:
            self.color_enabled = color_enabled
        else:
            # Check NO_COLOR env var or non-tty stdout
            no_color_env = os.environ.get("NO_COLOR")
            term_dumb = os.environ.get("TERM") == "dumb"
            is_atty = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()
            self.color_enabled = not bool(no_color_env) and not term_dumb and is_atty

    def style(self, text: str, *styles: str) -> str:
        if not self.color_enabled or not styles:
            return str(text)
        prefix = "".join(styles)
        return f"{prefix}{text}{AnsiColor.RESET}"

    def bold(self, text: str) -> str:
        return self.style(text, AnsiColor.BOLD)

    def dim(self, text: str) -> str:
        return self.style(text, AnsiColor.DIM)

    def red(self, text: str) -> str:
        return self.style(text, AnsiColor.BRIGHT_RED)

    def green(self, text: str) -> str:
        return self.style(text, AnsiColor.BRIGHT_GREEN)

    def yellow(self, text: str) -> str:
        return self.style(text, AnsiColor.BRIGHT_YELLOW)

    def blue(self, text: str) -> str:
        return self.style(text, AnsiColor.BRIGHT_BLUE)

    def magenta(self, text: str) -> str:
        return self.style(text, AnsiColor.BRIGHT_MAGENTA)

    def cyan(self, text: str) -> str:
        return self.style(text, AnsiColor.BRIGHT_CYAN)

    def badge(self, label: str, level: str) -> str:
        lvl = level.upper()
        if lvl in ("SAFE", "PASS", "PASSED", "OK"):
            return self.style(f" {label} ", AnsiColor.BOLD, AnsiColor.GREEN)
        elif lvl in ("LOW", "INFO"):
            return self.style(f" {label} ", AnsiColor.BOLD, AnsiColor.CYAN)
        elif lvl in ("MEDIUM", "WARN", "WARNING"):
            return self.style(f" {label} ", AnsiColor.BOLD, AnsiColor.YELLOW)
        elif lvl in ("HIGH", "FAIL", "FAILED", "ERROR"):
            return self.style(f" {label} ", AnsiColor.BOLD, AnsiColor.RED)
        elif lvl in ("CATASTROPHIC", "CRITICAL"):
            return self.style(f" {label} ", AnsiColor.BOLD, AnsiColor.BRIGHT_WHITE, AnsiColor.BG_RED)
        return self.style(f" {label} ", AnsiColor.BOLD)

    def table(
        self,
        headers: List[str],
        rows: List[List[Any]],
        alignments: Optional[List[str]] = None,
        max_col_width: Optional[int] = 50,
    ) -> str:
        """Render a formatted ASCII/Unicode terminal table."""
        if not headers and not rows:
            return ""

        num_cols = len(headers) if headers else (len(rows[0]) if rows else 0)
        if not alignments:
            alignments = ["left"] * num_cols

        # Convert everything to string and calculate max widths
        str_headers = [str(h) for h in headers]
        str_rows: List[List[str]] = []
        for row in rows:
            formatted_row = []
            for cell in row:
                s = str(cell) if cell is not None else ""
                # Replace newlines for table cell display
                s = s.replace("\n", "\\n").replace("\r", "")
                if max_col_width and len(s) > max_col_width:
                    s = s[: max_col_width - 3] + "..."
                formatted_row.append(s)
            while len(formatted_row) < num_cols:
                formatted_row.append("")
            str_rows.append(formatted_row[:num_cols])

        # Width calculation (excluding ANSI codes)
        def visible_len(text: str) -> int:
            # Strip ANSI escape sequences for length calculation
            import re
            ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
            return len(ansi_escape.sub("", text))

        col_widths = [0] * num_cols
        for i, h in enumerate(str_headers):
            col_widths[i] = max(col_widths[i], visible_len(h))

        for row in str_rows:
            for i, cell in enumerate(row):
                col_widths[i] = max(col_widths[i], visible_len(cell))

        # Add padding
        col_widths = [max(w, 3) for w in col_widths]

        # Box drawing characters or ASCII fallback
        encoding = getattr(sys.stdout, "encoding", "utf-8") or "utf-8"
        try:
            "┌├└│─".encode(encoding)
            top_left, top_mid, top_right = "┌", "┬", "┐"
            mid_left, mid_mid, mid_right = "├", "┼", "┤"
            bot_left, bot_mid, bot_right = "└", "┴", "┘"
            horiz, vert = "─", "│"
        except UnicodeEncodeError:
            top_left, top_mid, top_right = "+", "+", "+"
            mid_left, mid_mid, mid_right = "+", "+", "+"
            bot_left, bot_mid, bot_right = "+", "+", "+"
            horiz, vert = "-", "|"

        lines = []

        # Top border
        top_border = top_left + top_mid.join(horiz * (w + 2) for w in col_widths) + top_right
        lines.append(top_border)

        # Header row
        if headers:
            header_cells = []
            for i, h in enumerate(str_headers):
                pad = col_widths[i] - visible_len(h)
                cell_str = self.bold(h) + " " * pad
                header_cells.append(f" {cell_str} ")
            lines.append(vert + vert.join(header_cells) + vert)

            # Header separator
            sep = mid_left + mid_mid.join(horiz * (w + 2) for w in col_widths) + mid_right
            lines.append(sep)

        # Data rows
        for row in str_rows:
            row_cells = []
            for i, cell in enumerate(row):
                align = alignments[i] if i < len(alignments) else "left"
                pad = col_widths[i] - visible_len(cell)
                if align == "right":
                    cell_str = " " * pad + cell
                elif align == "center":
                    left_pad = pad // 2
                    right_pad = pad - left_pad
                    cell_str = " " * left_pad + cell + " " * right_pad
                else:
                    cell_str = cell + " " * pad
                row_cells.append(f" {cell_str} ")
            lines.append(vert + vert.join(row_cells) + vert)

        # Bottom border
        bot_border = bot_left + bot_mid.join(horiz * (w + 2) for w in col_widths) + bot_right
        lines.append(bot_border)

        return "\n".join(lines)

    def render_spans(
        self,
        text: str,
        match_span: Optional[Tuple[int, int]],
        group_spans: List[Tuple[str, Optional[Tuple[int, int]], Optional[str]]],
    ) -> str:
        """Render an aligned visual diagram of matches and group spans."""
        lines = []
        # Header showing the text with index ruler
        lines.append(f"  {self.bold('Input:')}  {text}")

        # Index ruler (tens and ones)
        if len(text) > 0:
            tens = " " * 10
            ones = " " * 10
            for i in range(len(text)):
                tens += str(i // 10) if i % 10 == 0 and i >= 10 else " "
                ones += str(i % 10)
            lines.append(self.dim(f"  Ruler:  {ones[10:]}"))

        if match_span:
            start, end = match_span
            length = len(text)
            marker = [" "] * length
            if 0 <= start < length:
                marker[start] = "["
            for idx in range(start + 1, min(end - 1, length)):
                marker[idx] = "="
            if 0 <= end - 1 < length:
                marker[end - 1] = "]" if end - 1 > start else "|"
            marker_str = "".join(marker)
            lines.append(f"  {self.green('Match:')}  {self.green(marker_str)} {self.dim(f'({start}..{end})')}")

        for name, span, val in group_spans:
            if span is not None:
                start, end = span
                length = len(text)
                marker = [" "] * length
                if 0 <= start < length:
                    marker[start] = "["
                for idx in range(start + 1, min(end - 1, length)):
                    marker[idx] = "-"
                if 0 <= end - 1 < length:
                    marker[end - 1] = "]" if end - 1 > start else "|"
                marker_str = "".join(marker)
                val_disp = repr(val) if val is not None else "None"
                lines.append(
                    f"  {self.cyan(f'{name:>6}:')}  {self.cyan(marker_str)} {self.dim(f'({start}..{end})')} {val_disp}"
                )
            else:
                lines.append(f"  {self.dim(f'{name:>6}:')}  {self.dim('<did not participate>')}")

        return "\n".join(lines)


# Global default instance
default_formatter = Formatter()
