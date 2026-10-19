# Contributing

Thanks for helping improve this project! Please follow the steps below.

## Reporting Issues

- Search existing issues before opening a new one.
- For bugs, include the command you ran, the expected and actual output, and
  your Python version.
- When an issue is about specific code, link to the exact lines
  (click the line number in GitHub → "Reference in new issue").
- Security vulnerabilities must **not** be reported as public issues; see
  [SECURITY.md](SECURITY.md).

## Submitting Pull Requests

1. Create a branch from the latest `main`:
   ```bash
   git checkout main && git pull
   git checkout -b fix-issue-<number>
   ```
2. Make focused changes. One issue per pull request.
3. Make sure every check below passes.
4. Open a pull request against `main`, describe what changed and why, and
   include `Fixes #<issue-number>` so the issue closes automatically.
5. Request a review from a code owner (see `.github/CODEOWNERS`). `main` is
   protected: direct pushes are blocked and history must stay linear.

## Coding Style

- Code is formatted and linted with [ruff](https://docs.astral.sh/ruff/)
  (PEP 8, line length 88). Run `poetry run ruff format .` before committing.
- `poetry run ruff check .` must report no errors.
- `poetry run mypy main.py merkle_proof.py util.py` must pass.
- `poetry run bandit -r . -c pyproject.toml` must report no issues.
- Never commit secrets. The pre-commit hook runs TruffleHog on every commit;
  install it with `poetry run pre-commit install`.

## Testing Requirements

- Add or update tests in `tests/` for every bug fix or new feature.
- Tests must not depend on the live Rekor service; mock network calls.
- `poetry run pytest` must pass, and total coverage must stay at or above
  **75%**.
