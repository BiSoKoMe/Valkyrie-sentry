# Causal Authority Experiment Report

**Result:** PASS

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
- In-process latency p50/p95/p99: 0.0404 / 0.0708 / 0.1139 ms

## What this refuses to claim

- No real browser or native-messaging latency was measured.
- No network request was blocked or rewritten.
- No Windows PID was attributed from browser context.
- No malware efficacy or production false-positive rate was measured.
- No kernel driver was loaded or validated.

The JSON evidence artifact contains every trial, its expected and actual
verdict, the refusal reason, the measured in-process decision latency,
and the source revision used for the run.
