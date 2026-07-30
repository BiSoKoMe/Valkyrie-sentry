# Evaluation history

One row per run. `Tier A` = classifier replay (safe, runs anywhere). `Tier B` = live VM execution (real ground truth). Percentages are the STRICT headline score (CONDITIONAL and known-mismatch outcomes count as misses).

| Timestamp (UTC) | Tier | Commit | Overall | Exec | Pers | Defe | Cred | Disc | Late | Comm | Impa |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 20260730T034140Z | A_replay | 3c9c8bd | 9/40 (22%) | 0/7 | 4/6 | 0/6 | 0/4 | 0/6 | 0/3 | 4/5 | 1/3 |
| 20260730T203810Z | A_replay | bce9f93 | 25/40 (62%) | 5/7 | 6/6 | 4/6 | 1/4 | 1/6 | 1/3 | 5/5 | 2/3 |
