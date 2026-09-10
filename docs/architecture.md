# Architecture

Fixture tools are loaded from JSON. `rules.py` performs static checks. `Fixture` handles synthetic behavioral calls. `ApprovalStore` provides short-lived request-bound approvals. `Audit` records sanitized decisions and input hashes. `reports.py` writes Markdown and JSON artifacts.

The security boundary is local demo token, synthetic data, no network, no shell execution, no real secrets, tenant-bound reads, and no automatic write retry.
