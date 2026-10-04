# Contributing to TokenVault

Thank you for your interest in contributing. This document covers the essentials for getting started.

## Setting up

```bash
git clone https://github.com/keyurkhant/tokenvault.git
cd tokenvault
pip install -e ".[dev]"
```

## Running tests

```bash
pytest --tb=short -q
```

All 116 tests must pass before opening a pull request.

## Code style

```bash
ruff check tokenvault tests   # lint
ruff format tokenvault tests  # format
mypy tokenvault               # type check
```

CI runs all three automatically on every pull request.

## Guidelines

**No real PII in the repository.** Tests must use programmatically generated synthetic data only.

**Test-driven.** Write a failing test before implementing the fix or feature. Each commit should leave the suite green.

**No cross-domain imports.** `tokenizers/`, `matchers/`, `keys/`, `policy/`, `audit/` must not import from each other. Cross-domain wiring belongs in `vault.py` or `config.py`.

**Security-sensitive changes** (tokenizers, key stores, policy engine, audit sinks) need a reviewer comment explaining the threat model impact. See [SECURITY.md](SECURITY.md) for the disclosure policy.

## Pull request checklist

- [ ] Tests added or updated for the change
- [ ] `ruff check` and `mypy` pass with zero new warnings
- [ ] No raw PII or real credentials in any file
- [ ] `CHANGELOG.md` entry added under `[Unreleased]`

## Reporting bugs

Use the [bug report template](https://github.com/keyurkhant/tokenvault/issues/new?template=bug_report.md).
