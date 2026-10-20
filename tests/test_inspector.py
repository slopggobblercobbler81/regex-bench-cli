"""Unit tests for regex inspector and capture group extraction."""

import unittest
from regex_bench.inspector import RegexInspector, inspect_match


class TestRegexInspector(unittest.TestCase):
    def test_single_match_with_groups(self):
        inspector = RegexInspector()
        res = inspector.inspect(r"(\w+)@(\w+\.\w+)", "user@example.com")
        self.assertTrue(res.matched)
        self.assertEqual(res.total_matches, 1)

        m = res.matches[0]
        self.assertEqual(m.matched_text, "user@example.com")
        self.assertEqual(m.span, (0, 16))
        self.assertEqual(len(m.groups), 2)
        self.assertEqual(m.groups[0].value, "user")
        self.assertEqual(m.groups[0].span, (0, 4))
        self.assertEqual(m.groups[1].value, "example.com")
        self.assertEqual(m.groups[1].span, (5, 16))

    def test_named_groups(self):
        res = inspect_match(r"(?P<first>[a-z]+)\s+(?P<last>[a-z]+)", "john doe")
        self.assertTrue(res.matched)
        m = res.matches[0]
        self.assertEqual(m.named_groups["first"], "john")
        self.assertEqual(m.named_groups["last"], "doe")

    def test_unmatched_pattern(self):
        res = inspect_match(r"^\d+$", "abc")
        self.assertFalse(res.matched)
        self.assertEqual(res.total_matches, 0)
        self.assertEqual(res.matches, [])

    def test_find_all_matches(self):
        inspector = RegexInspector(find_all=True)
        res = inspector.inspect(r"\d+", "item 10, item 20, item 30")
        self.assertTrue(res.matched)
        self.assertEqual(res.total_matches, 3)
        self.assertEqual([m.matched_text for m in res.matches], ["10", "20", "30"])

    def test_unmatched_optional_group(self):
        res = inspect_match(r"a(b)?c", "ac")
        self.assertTrue(res.matched)
        m = res.matches[0]
        self.assertIsNone(m.groups[0].value)
        self.assertIsNone(m.groups[0].span)

    def test_to_dict_serialization(self):
        res = inspect_match(r"(\d+)", "123")
        d = res.to_dict()
        self.assertIn("pattern", d)
        self.assertIn("input_text", d)
        self.assertIn("matches", d)
        self.assertEqual(d["matches"][0]["matched_text"], "123")


if __name__ == "__main__":
    unittest.main()
