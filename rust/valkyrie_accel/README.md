# valkyrie_accel — optional native accelerators

A small Rust/[PyO3](https://pyo3.rs) extension that speeds up hot paths in
Valkyrie. **It is entirely optional.** If it is not built/installed, Valkyrie
falls back to a pure-Python implementation with identical behavior — so a source
checkout or a Raspberry-Pi install with only Python still runs everything.

## What it accelerates today

- **`IpSet`** — the CIDR/host membership set the DNS answer-screening path checks
  on every allowed reply. Drop-in for `valkyrie.firewall._PyIPSet`; the two are
  proven equivalent by a randomized differential test
  (`tests/test_rust_accel.py`). Measured ~20× faster per lookup than the
  (already-bucketed) Python version, and ~16,000× faster than the original
  linear scan.

## Build & install

Requires a Rust toolchain (`rustc`/`cargo`) and [maturin](https://www.maturin.rs):

```bash
pip install maturin
cd rust/valkyrie_accel
maturin build --release
pip install target/wheels/*.whl
```

Verify it is active:

```bash
python -c "from valkyrie import firewall; print(firewall._IPSET_BACKEND)"  # -> rust
```

To go back to pure Python, just `pip uninstall valkyrie_accel`.

## Design contract

- **Never a hard dependency.** `firewall.py` imports it inside a `try/except` and
  selects the Python fallback on any failure.
- **Behavior-identical.** Any accelerator must match its Python reference exactly,
  pinned by a differential test that runs in CI (the `accel` job builds this and
  runs the whole suite with the Rust backend active; the `unit` job runs the same
  suite on the pure-Python fallback).
- **Small, safe surface.** Memory-safe Rust, no `unsafe`, no network, no I/O
  beyond what the Python API already did.
