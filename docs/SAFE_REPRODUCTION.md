# Safe Reproduction Guide

This guide reproduces the causal-authority mechanism evidence without reading
real browser data, changing DNS, modifying firewall state, loading a driver, or
executing offensive techniques.

## Requirements

- Python 3.10 or newer
- Git
- Windows, Linux, or macOS for the synthetic run
- No administrator privileges

## Reproduce from a clean checkout

```powershell
git clone https://github.com/BiSoKoMe/Valkyrie-sentry.git
cd Valkyrie-sentry
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements_modular.txt
python -m pip install pytest httpx
```

Run the focused regression tests:

```powershell
python -m pytest -q tests/test_causal_authority.py tests/test_browser_context.py tests/test_authority_experiment.py
```

Run the fixed evidence corpus:

```powershell
python tools/authority_experiment.py --authorized 500 --unauthorized 100 --max-p99-ms 10 --output artifacts/authority-evidence.json --report artifacts/AUTHORITY_EXPERIMENT_REPORT.md
```

The command exits nonzero if any fixed criterion fails. Inspect the JSON rather
than relying only on the summary. It contains the source revision, environment,
thresholds, aggregate metrics, and every expected and actual trial verdict.
The repository also preserves the clean Windows result used in the paper at
`docs/evidence/authority-windows-6113502.json`.

## Independent Windows run

Open the repository's GitHub Actions page and run **Causal authority evidence**.
The workflow checks out one exact commit on a clean `windows-latest` runner,
runs the focused tests, executes the same 500 plus 100 corpus, and uploads the
JSON evidence and Markdown report for 90 days.

## Safety boundary

This reproduction is synthetic. It does not start Valkyrie's DNS interceptor,
install the browser extension, inspect TLS, alter the host firewall, load the
unsigned driver, or run Atomic Red Team. Those activities require a disposable,
snapshot-capable, isolated Windows VM and a separate protocol.

## Interpreting a pass

A pass means the deterministic collector and verifier classified this fixed
corpus correctly, retained no raw sentinel, and met the in-process p99 budget on
that runner. It does not mean that a browser request was blocked, that all
browser actions are visible, that Windows process attribution is correct, or
that production efficacy has been established.
