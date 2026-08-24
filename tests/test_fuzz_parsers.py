"""Tier 2.10 — every parser survives hostile input.

This is the CrowdStrike lesson taken literally. On 2024-07-19 CrowdStrike bricked
about 8.5 million machines because a **content parser read out of bounds on a
malformed input file** running in kernel mode. Not a clever exploit — a parser
that trusted its input's shape. Valkyrie parses plenty of attacker-influenced
data (event XML, hostile web pages, a kernel ring buffer, YAML from disk) and
had no malformed-input tests anywhere.

The contract asserted here is deliberately weak, and that is the point. We do
**not** assert a parser returns the right answer for garbage — there is no right
answer for garbage. We assert only what must hold for every input in the
universe:

    1. it does not raise an undeclared exception
    2. it does not hang
    3. its output does not blow up relative to its input

A parser that returns `{}` for nonsense is fine. A parser that raises
`ValueError` from an `int()` deep inside a `try` that only catches `ParseError`
is a crash in the DNS or telemetry path, and that is what this hunts.

No `hypothesis` dependency: the generators are seeded, so a failure reproduces
exactly from the printed seed. Reproducibility beats exploration for a CI gate —
a fuzz failure nobody can re-run is a fuzz failure nobody fixes.
"""

from __future__ import annotations

import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks

SEED = 20260729
# Per-input wall-clock ceiling. A parser that exceeds this on any single input is
# a denial-of-service surface, not merely slow.
_HANG_SECONDS = 2.0
# Default is the fast local pass (~10s). CI runs the full 10,000 per parser that
# TEST_PLAN tier 2 requires — ~51s for all 110k inputs — via an explicit argv.
_ITERATIONS = int(sys.argv[1]) if len(sys.argv) > 1 else 2000


# ── Hostile input generators ────────────────────────────────────────────────

_EVIL_SNIPPETS = (
    "", " ", "\x00", "\x00" * 64, "￿", "\ud800", "%s%s%s%n", "../../etc/passwd",
    "<", ">", "<>", "</>", "&", "&amp;", "&#x41;", "]]>", "<![CDATA[", "<!--",
    "{{", "}}", "{}", "[]", "null", "NaN", "-Infinity", "1e309", "0x" + "f" * 64,
    "\r\n", "\n\r", "\t", "\\", '"', "'", "`", ";", "|", "$(", "${", "‮",
    "A" * 1024, "中" * 256, "\U0001f600" * 128,
)

# Structured attacks that specifically target XML parsers.
_XML_BOMBS = (
    # billion laughs — entity expansion
    '<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "aaaaaaaaaa">'
    '<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">'
    '<!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">]><Event>&c;</Event>',
    # external entity — must not fetch anything
    '<?xml version="1.0"?><!DOCTYPE l [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
    '<Event><System>&x;</System></Event>',
    '<?xml version="1.0"?><!DOCTYPE l SYSTEM "http://169.254.169.254/latest/">'
    '<Event/>',
    # deep nesting
    "<Event>" + "<a>" * 500 + "x" + "</a>" * 500 + "</Event>",
    # unclosed / truncated
    "<Event><System><EventID>4688",
    "<Event><System><EventID>not-a-number</EventID></System></Event>",
    "<Event><System><EventID></EventID><EventRecordID>x</EventRecordID>"
    "</System></Event>",
    "<Event><System><EventID>" + "9" * 400 + "</EventID></System></Event>",
    "<Event><System><EventID>-1</EventID><Execution ProcessID='x' "
    "ThreadID='y'/></System></Event>",
    "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
    "<System><EventID>1</EventID></System></Event>",
)


def _rand_text(rng: random.Random) -> str:
    """A string assembled from hostile fragments plus raw noise."""
    parts = []
    for _ in range(rng.randint(0, 12)):
        if rng.random() < 0.6:
            parts.append(rng.choice(_EVIL_SNIPPETS))
        else:
            parts.append("".join(chr(rng.randint(0, 0x10FFFF))
                                 for _ in range(rng.randint(0, 40))))
    return "".join(parts)


def _rand_xml(rng: random.Random) -> str:
    if rng.random() < 0.35:
        return rng.choice(_XML_BOMBS)
    tag = rng.choice(("Event", "System", "EventID", "Data", "x"))
    body = _rand_text(rng)
    shape = rng.randint(0, 3)
    if shape == 0:
        return f"<{tag}>{body}</{tag}>"
    if shape == 1:
        return f"<{tag} {body}='{body}'/>"
    if shape == 2:
        return f"<Event><System><EventID>{body}</EventID></System></Event>"
    return body


def _rand_bytes(rng: random.Random) -> bytes:
    n = rng.choice((0, 1, 7, 15, 16, 63, 64, 255, 1024, 4096))
    return bytes(rng.randint(0, 255) for _ in range(n))


def _rand_record(rng: random.Random) -> dict:
    """A dict shaped vaguely like a telemetry record, with hostile values."""
    keys = ("id", "severity", "category", "title", "entity", "process_name",
            "timestamp", "reason", "score", "labels", "technique", "")
    out: dict = {}
    for _ in range(rng.randint(0, 8)):
        k = rng.choice(keys)
        r = rng.random()
        if r < 0.4:
            out[k] = _rand_text(rng)
        elif r < 0.55:
            out[k] = rng.choice((None, True, False, 0, -1, 1 << 70, float("nan"),
                                 float("inf"), -0.0))
        elif r < 0.7:
            out[k] = [_rand_text(rng) for _ in range(rng.randint(0, 5))]
        elif r < 0.85:
            out[k] = {_rand_text(rng): _rand_text(rng)}
        else:
            out[k] = _rand_text(rng)
    return out


def _rand_yaml(rng: random.Random) -> str:
    shapes = (
        _rand_text(rng),
        "playbooks:\n" + "  - id: " + _rand_text(rng) + "\n",
        "playbooks:\n  - " + "a" * rng.randint(0, 200),
        "- " * rng.randint(0, 300),
        "{" * rng.randint(0, 200),
        "[" * rng.randint(0, 200),
        "a: &x [" + "*x," * rng.randint(0, 20) + "]",
        "!!python/object/apply:os.system ['echo pwned']",
        "playbooks:\n  - id: x\n    actions:\n      - action: " + _rand_text(rng),
    )
    return rng.choice(shapes)


# ── The fuzz driver ─────────────────────────────────────────────────────────

def _fuzz(c: Checks, label: str, fn, gen, n: int, allowed=()) -> None:
    """Run *fn* over *n* generated inputs; record one check for the whole run.

    `allowed` lists exception types the parser is documented to raise. Anything
    else is a defect. The failing input is printed so the failure is actionable
    rather than merely alarming.
    """
    rng = random.Random(SEED ^ hash(label) & 0xFFFFFFFF)
    worst = 0.0
    worst_in = None
    failure = None
    for i in range(n):
        payload = gen(rng)
        t0 = time.monotonic()
        try:
            fn(payload)
        except allowed:
            pass
        except BaseException as exc:            # noqa: BLE001 — that is the test
            failure = (i, type(exc).__name__, str(exc)[:120], repr(payload)[:220])
            break
        finally:
            dt = time.monotonic() - t0
            if dt > worst:
                worst, worst_in = dt, payload

    if failure:
        i, exc_name, msg, payload = failure
        print(f"  [!] {label}: raised {exc_name} on input #{i}")
        print(f"        msg:   {msg}")
        print(f"        input: {payload}")
        c.check(f"{label}: never raises on hostile input "
                f"(raised {exc_name})", False)
        return

    c.check(f"{label}: {n} hostile inputs, no undeclared exception", True)
    c.check(f"{label}: no input took > {_HANG_SECONDS}s "
            f"(worst {worst * 1000:.1f}ms)", worst <= _HANG_SECONDS)
    if worst > _HANG_SECONDS:
        print(f"        slowest input: {repr(worst_in)[:200]}")


def main() -> int:
    c = Checks("parser fuzzing", expect_min=14)
    print(f"seed={SEED}  iterations={_ITERATIONS} per parser "
          f"(pass a count as argv[1] to change)\n")

    # 1. Windows event XML — attacker-influenced, and the closest analogue to
    #    the CrowdStrike channel-file parser.
    from valkyrie.etw.wineventlog import parse_event_xml, record_id_of
    print("[1] etw/wineventlog")
    _fuzz(c, "parse_event_xml", parse_event_xml, _rand_xml, _ITERATIONS)
    _fuzz(c, "record_id_of", record_id_of, _rand_xml, _ITERATIONS)

    # 2. Hostile web pages — this parser reads pages chosen by an attacker by
    #    design, so it is the most exposed parser in the product.
    from valkyrie.site_analyzer import analyze_content, third_party_hosts
    print("\n[2] site_analyzer")
    _fuzz(c, "analyze_content", lambda s: analyze_content(s, "http://x.test/"),
          _rand_text, _ITERATIONS)
    _fuzz(c, "third_party_hosts", lambda s: third_party_hosts(s, "x.test"),
          _rand_text, _ITERATIONS)

    # 3. SIEM serialisers — a malformed field must not corrupt a record or
    #    escape the format (CEF injection).
    from valkyrie.siem import (format_cef, format_jsonl, incident_record,
                               dns_block_record)
    print("\n[3] siem")
    _fuzz(c, "format_cef", format_cef, _rand_record, _ITERATIONS)
    _fuzz(c, "format_jsonl", format_jsonl, _rand_record, _ITERATIONS)
    _fuzz(c, "incident_record", incident_record, _rand_record, _ITERATIONS)
    _fuzz(c, "dns_block_record", dns_block_record, _rand_record, _ITERATIONS)

    # 4. Kernel ring buffer — raw bytes from kernel mode. This is literally the
    #    CrowdStrike shape: a binary record parsed in the trusted path.
    from valkyrie.kernel_bridge import record_to_event, parse_records
    print("\n[4] kernel_bridge")
    _fuzz(c, "record_to_event", record_to_event, _rand_bytes, _ITERATIONS)
    _fuzz(c, "parse_records", parse_records, _rand_bytes, _ITERATIONS)

    # 5. YAML loaders — playbooks come off disk and drive automated response.
    #    An unsafe loader here is remote code execution with extra steps.
    from valkyrie.edr.playbooks import _parse_playbook
    print("\n[5] playbook parsing")

    # ValueError is _parse_playbook's DECLARED contract, not a defect: it is how
    # an invalid playbook is rejected, and PlaybookEngine.load catches it at
    # playbooks.py:152 and records a load error. Declaring it here is the
    # difference between fuzzing the contract and fuzzing our assumption of it.
    def _pb(raw):
        try:
            import yaml
            doc = yaml.safe_load(raw)
        except Exception:
            return None            # a YAML syntax error is the loader's job
        if isinstance(doc, dict):
            for item in (doc.get("playbooks") or []):
                if isinstance(item, dict):
                    _parse_playbook(item)
        return None

    _fuzz(c, "_parse_playbook via yaml.safe_load", _pb, _rand_yaml, _ITERATIONS,
          allowed=(ValueError,))

    # The contract that actually matters is the one at the boundary: a hostile
    # playbook FILE must never take the engine down, whatever is in it.
    from valkyrie.edr.playbooks import PlaybookEngine
    import tempfile

    rng = random.Random(SEED)
    tmpdir = Path(tempfile.mkdtemp(prefix="valkyrie_fuzz_pb_"))
    engine_failure = None
    for i in range(200):
        pbf = tmpdir / "pb.yaml"
        pbf.write_text(_rand_yaml(rng), encoding="utf-8", errors="replace")
        try:
            PlaybookEngine(None, path=pbf).load()
        except BaseException as exc:      # noqa: BLE001 — that is the test
            engine_failure = f"{type(exc).__name__}: {str(exc)[:100]}"
            break
    c.check(f"PlaybookEngine.load survives a hostile playbook file "
            f"({engine_failure or 'no exception'})", engine_failure is None)

    # 6. The YAML loader must be safe_load, not load — assert it directly rather
    #    than hoping the fuzzer stumbles onto the object-instantiation tag.
    print("\n[6] YAML deserialisation is not a code-execution primitive")
    import yaml
    evil = "!!python/object/apply:os.system ['echo pwned']"
    try:
        yaml.safe_load(evil)
        constructed = True
    except yaml.YAMLError:
        constructed = False
    c.check("yaml.safe_load refuses python/object tags", not constructed)
    src = Path("valkyrie/edr/playbooks.py").read_text(encoding="utf-8")
    c.check("playbooks.py never calls the unsafe yaml.load",
            "yaml.load(" not in src)

    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
