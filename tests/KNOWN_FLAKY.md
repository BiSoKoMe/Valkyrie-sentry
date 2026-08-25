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

## test_self_test.py

Same shape, second occurrence: failed once inside a full sweep on the single
check named "health probe answered under GIL contention", passed 41/41 clean
3/3 times run alone immediately after. The check's own name states the
mechanism - the health probe races real GIL contention, and running ~130
processes that each boot a real engine back-to-back is exactly the load that
would occasionally lose that race. Same suspected cause as
`test_capability_delivery.py` above, not a new independent issue.
