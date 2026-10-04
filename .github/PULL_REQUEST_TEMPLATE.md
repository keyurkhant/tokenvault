## What does this PR do?

<!-- One paragraph summary of the change and why it's needed. -->

## Type of change

- [ ] Bug fix
- [ ] New feature (tokenizer / matcher / normalizer / key store)
- [ ] Refactor
- [ ] Documentation
- [ ] CI / tooling

## Checklist

- [ ] Tests added or updated; full suite passes (`pytest -q`)
- [ ] `ruff check` and `mypy tokenvault` pass with zero new warnings
- [ ] No raw PII or real credentials in any committed file
- [ ] `CHANGELOG.md` updated under `[Unreleased]`
- [ ] Cross-domain import invariant preserved (no imports across `tokenizers/`, `matchers/`, `keys/`, `policy/`, `audit/`)

## Security impact

<!-- Does this change touch token comparison, key handling, policy evaluation, or audit emission? If yes, describe the threat model impact. -->
