# Causal Authority Experiment Report

**Result:** PASS

**Independent run:** [GitHub Actions 33287499023](https://github.com/BiSoKoMe/Valkyrie-sentry/actions/runs/33287499023)

**Source revision:** `61135020c4d194196a28e75fea38e3104e90c1b7`

**Runner:** Windows 10 build 26100, Python 3.11.9

## Question

A fresh one-shot grant scoped to origin, destination, tab, frame, action, and data labels can distinguish the fixed authorized and unauthorized corpus locally without retaining raw values.

## Fixed corpus and thresholds

- Authorized consequences: 500
- Unauthorized consequences: 100
- Required decision accuracy: 100%
- Allowed false allows and false refusals: 0
- Allowed raw sentinel leaks: 0
- In-process p99 budget: 10.000 ms

## Results

- Correct decisions: 600/600
- False allows: 0
- False refusals: 0
- Raw sentinel leaks: 0
- In-process latency p50/p95/p99: 0.0531 / 0.0864 / 0.1206 ms
- Maximum observed in-process latency: 1.2960 ms

## What this refuses to claim

- No real browser or native-messaging latency was measured.
- No network request was blocked or rewritten.
- No Windows PID was attributed from browser context.
- No malware efficacy or production false-positive rate was measured.
- No kernel driver was loaded or validated.

The committed [JSON evidence](evidence/authority-windows-6113502.json) contains
every trial, its expected and actual verdict, the refusal reason, the measured
in-process decision latency, the environment, and the exact source revision.
Its SHA-256 is
`80292A5B9488CC1FD498AB6BF4CB68F8E9C89BDAC2603AAA182A873B8723E949`.
