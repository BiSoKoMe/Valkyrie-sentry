"""Standalone test for the site scanner.

Verifies ALLOW / BLOCK / FLAG decisions against the canonical test cases.
Default logic: ALLOW everything; only block/flag on positive tracker signals.

Usage:
    python test_scanner.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from valkyrie.site_scanner import SiteScanner

scanner = SiteScanner(store=None)   # no cache - every call runs full analysis


# ---------------------------------------------------------------------------
# Test cases  (domain, expected_decision, note)
# ---------------------------------------------------------------------------

MUST_ALLOW = [
    ("google.com",          "allow", "well-known search engine"),
    ("github.com",          "allow", "well-known code host"),
    ("reddit.com",          "allow", "well-known social site"),
    ("looktv.mn",           "allow", "unknown domain — default allow"),
    ("youtube.com",         "allow", "well-known video site"),
    ("news.bbc.com",        "allow", "subdomain of legitimate site"),
    ("cdn.jsdelivr.net",    "allow", "CDN"),
    ("stackoverflow.com",   "allow", "developer site"),
    ("amazon.com",          "allow", "e-commerce"),
    ("any-random-site.com", "allow", "completely unknown — must default allow"),
    ("my-blog.net",         "allow", "personal blog"),
    ("university.edu.mn",   "allow", "educational domain"),
]

MUST_BLOCK = [
    ("pagead2.googlesyndication.com", "block", "tracker SLD"),
    ("pixel.facebook.com",            "block", "tracker subdomain prefix"),
    ("tracker.example.com",           "block", "tracker subdomain prefix"),
    ("analytics.somesite.com",        "block", "tracker subdomain prefix"),
    ("a7f2k9.telemetry.io",           "block", "telemetry SLD"),
]

MUST_FLAG = [
    ("segment.io",   "flag", "analytics SLD — flag only"),
    ("newrelic.com", "flag", "monitoring SLD — flag only"),
]


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_cases(cases: list, label: str) -> tuple[int, int]:
    passed = failed = 0
    print(f"\n-- {label} {'-' * (52 - len(label))}")
    for domain, expected, note in cases:
        result = scanner.analyze(domain, process="chrome.exe")
        ok     = result.decision == expected
        status = "PASS" if ok else "FAIL"
        marker = "+" if ok else "X"
        print(
            f"  {marker} [{status}]  {domain:<42s}  "
            f"got={result.decision:<5s}  score={result.confidence:.2f}"
        )
        if result.reasons:
            print(f"           reasons: {'; '.join(result.reasons)}")
        if not ok:
            print(f"           expected: {expected}  ({note})")
            failed += 1
        else:
            passed += 1
    return passed, failed


def main() -> None:
    print("Valkyrie site scanner test")
    print("=" * 60)

    total_pass = total_fail = 0

    for cases, label in [
        (MUST_ALLOW, "MUST ALLOW"),
        (MUST_BLOCK, "MUST BLOCK"),
        (MUST_FLAG,  "MUST FLAG"),
    ]:
        p, f = run_cases(cases, label)
        total_pass += p
        total_fail += f

    print(f"\n{'=' * 60}")
    print(f"  {total_pass} passed  /  {total_fail} failed")
    if total_fail:
        print("  RESULT: SOME TESTS FAILED")
        sys.exit(1)
    else:
        print("  RESULT: ALL TESTS PASSED")
        sys.exit(0)


if __name__ == "__main__":
    main()
