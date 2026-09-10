# Walkthrough

1. Run `./scripts/run-preflight.sh`.
2. Open the generated Markdown report.
3. Point out the unsafe command, broad scope, fake secret, and tainted input findings.
4. Run `PYTHONPATH=. python3 tests/run_stdlib.py` to show tenant isolation, approval, quota, redaction, and invalid target checks.
5. Explain that all data is synthetic and the tool is a bounded preflight, not a full assessment.
