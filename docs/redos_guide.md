# Guide to Catastrophic Backtracking and ReDoS

Regular Expression Denial of Service (ReDoS) occurs when an algorithmic regex engine (such as standard backtracking engines in Python, JavaScript, Java, and .NET) encounters a pathological input that forces it to explore an exponential number of search paths.

## Common ReDoS Patterns

### 1. Nested Quantifiers (Star Height > 1)
When an unbounded quantifier is nested inside another quantifier:
```text
(a+)+
([a-zA-Z0-9]+)*
((x*)*)*
```
- **Why it fails**: For a string of $N$ identical characters followed by an unmatched character (`aaaa...X`), the engine must test every possible partition of $N$ items across the inner and outer repetitions. The number of partitions is $2^{N-1}$. At $N=30$, this is over $500,000,000$ iterations!

### 2. Overlapping Alternation inside Repetitions
When alternation branches can match the same prefix or character class inside a repeat:
```text
(a|ab)+
(a|a)+
([a-z]|[0-9a-z])+
(\w|\d)+
```
- **Why it fails**: When matching fails, the engine tries all alternate branches for every repeat token, generating $2^N$ backtracking decisions.

### 3. Adjacent Overlapping Quantifiers
When two adjacent unbounded repetitions match identical or overlapping character sets:
```text
.*.*X
\w+\d+!
```
- **Why it fails**: On failure, the division of characters between the first and second repeat is ambiguous, resulting in polynomial $O(N^2)$ or $O(N^3)$ complexity.

---

## Remediation Strategies

1. **Eliminate Nested Quantifiers**:
   - Rewrite `(a+)+` to `a+`.
   - Rewrite `([a-z]+)*` to `[a-z]*`.

2. **Make Alternations Disjoint**:
   - Instead of `(a|ab)+`, use `ab|a` or extract common factors: `a(b?)+` or `a+`.

3. **Use Explicit Delimiters**:
   - Instead of `.*foo.*`, delimit searches with distinct tokens or character classes (e.g., `[^/]+/foo/[^/]+`).

4. **Add Input Length Limits**:
   - Validate input length before feeding it to regex engines.

---

## How `regex-bench` Detects ReDoS

`regex-bench` uses a two-stage analysis pipeline:
1. **Static AST Analysis**: Inspects Python's regex internal syntax tree (`sre_parse`) for nested repetitions, overlapping alternation sets, and ambiguous adjacent quantifiers.
2. **Dynamic Stress Testing**: Synthesizes custom attack strings based on the pattern's token types (prefixes, repeating pumps, and poison suffixes). It measures execution times across scaling lengths with safe timeout bounds to empirically verify exponential or polynomial degradation.
