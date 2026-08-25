# Known-flaky tests

## test_capability_delivery.py

Failed once inside a full `run_safe.py` sweep (131 files back-to-back), passed
3/3 when run alone immediately after. Root cause not yet isolated - suspected
resource contention (port allocation, disk, or CPU scheduling) from running
many real-engine-boot tests in sequence, not a logic bug in the test or in
`__main__.py`.

Recorded here rather than silently ignored or "fixed" by guessing. If it
recurs, capture the actual failing output from inside `run_safe.py` (the
per-file capture already keeps stdout) before changing anything - a fix without
a reproduced failure is a guess wearing a commit message.
